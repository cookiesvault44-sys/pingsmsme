// worker.js — Cloudflare Workers port of the SMS portal OTP backend
// (originally Flask appy.py). Serves the Chrome extension's floating panels.
//
// Routes:
//   GET /ping        -> {status:"alive"}              (health check)
//   GET /stats       -> per-number OTP view + CLI    (?number=&cli=&date=&month=&start=&end=&alnum=)
//   GET /messages    -> flat message list + CLI      (same filters)
//   GET /get-otp     -> newest OTP for ?phone=
//   GET /mark-seen   -> mark rows seen for ?phone=
//   GET /restart     -> clear session + seen rows, re-login, return stats
//   GET /debug-rows  -> first raw portal rows (format check)
//
// Env vars (set in the Worker dashboard): PORTAL_USER, PORTAL_PASS
// Optional: PORTAL_TZ_OFFSET_HOURS (default "0")

const PORTAL_BASE_URL = "http://135.125.222.224/ints";
const LOGIN_URL = `${PORTAL_BASE_URL}/login`;
const INBOX_URL = `${PORTAL_BASE_URL}/client/SMSCDRStats`;
const DATA_URL = `${PORTAL_BASE_URL}/client/res/data_smscdr.php`;

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const TIMESTAMP_RE = /\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?/;
const TIMESTAMP_FULL = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?$/;

// ---------------------------------------------------------------- cookie jar
// Module-level state persists across requests served by the same isolate.
// If the isolate is evicted the jar is lost and the code simply re-logs in.
const jar = new Map();

function saveCookies(res) {
  let raws = [];
  if (typeof res.headers.getSetCookie === "function") {
    raws = res.headers.getSetCookie();
  } else {
    const sc = res.headers.get("set-cookie");
    if (sc) raws = [sc];
  }
  for (const h of raws) {
    const semi = h.indexOf(";");
    const pair = semi >= 0 ? h.slice(0, semi) : h;
    const eq = pair.indexOf("=");
    if (eq > 0) jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
}

function cookieHeader() {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

// fetch with manual redirect handling so cookies are saved at every hop
// (the portal sets session cookies on redirects; plain redirect:"follow"
// would swallow them).
async function pfetch(url, opts = {}, maxRedirects = 5) {
  let current = url;
  let method = (opts.method || "GET").toUpperCase();
  let body = opts.body;
  const extraHeaders = opts.headers || {};
  for (let i = 0; i <= maxRedirects; i++) {
    const headers = new Headers(extraHeaders);
    headers.set("User-Agent", UA);
    const ch = cookieHeader();
    if (ch) headers.set("Cookie", ch);
    const res = await fetch(current, { method, headers, body, redirect: "manual" });
    saveCookies(res);
    if ([301, 302, 303, 307, 308].includes(res.status) && i < maxRedirects) {
      const loc = res.headers.get("location");
      if (!loc) return res;
      current = new URL(loc, current).toString();
      if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === "POST")) {
        method = "GET";
        body = undefined;
      }
      continue;
    }
    return res;
  }
}

// ---------------------------------------------------------------- html helpers
function stripTags(html) {
  return String(html).replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}

function solveMathCaptcha(text) {
  const m = String(text).match(/(\d{1,2})\s*\+\s*(\d{1,2})/);
  return m ? parseInt(m[1], 10) + parseInt(m[2], 10) : null;
}

function buildLoginRequest(html, username, password) {
  const formMatch = String(html).match(/<form[\s\S]*?<\/form>/i);
  if (!formMatch) return null;
  const formHtml = formMatch[0];
  const captcha =
    solveMathCaptcha(stripTags(formHtml)) ?? solveMathCaptcha(stripTags(html));
  if (captcha === null || captcha === undefined) return null;
  const payload = {};
  let usernameSet = false;
  const inputRe = /<input\b[^>]*>/gi;
  let im;
  while ((im = inputRe.exec(formHtml)) !== null) {
    const tag = im[0];
    const attr = (n) => {
      const mm = tag.match(new RegExp(`\\b${n}\\s*=\\s*"([^"]*)"|\\b${n}\\s*=\\s*'([^']*)'|\\b${n}\\s*=\\s*([^\\s>]+)`, "i"));
      return mm ? (mm[1] ?? mm[2] ?? mm[3] ?? "") : null;
    };
    const name = attr("name");
    const itype = (attr("type") || "text").toLowerCase();
    const value = attr("value") || "";
    if (!name || ["submit", "button", "image", "checkbox", "radio"].includes(itype)) continue;
    const lname = name.toLowerCase();
    if (itype === "password") payload[name] = password;
    else if (itype === "hidden") payload[name] = value;
    else if (lname.includes("capt") || lname.includes("answer") || lname.includes("math"))
      payload[name] = String(captcha);
    else if (!usernameSet) {
      payload[name] = username;
      usernameSet = true;
    } else payload[name] = String(captcha);
  }
  const actionM = formHtml.match(/<form\b[^>]*\baction\s*=\s*"([^"]*)"|<form\b[^>]*\baction\s*=\s*'([^']*)'/i);
  let action = LOGIN_URL;
  if (actionM) {
    const a = actionM[1] ?? actionM[2];
    if (a) action = new URL(a, LOGIN_URL).toString();
  }
  return { action, payload };
}

// ---------------------------------------------------------------- portal login
async function isLoggedIn() {
  try {
    const res = await pfetch(INBOX_URL);
    if ([401, 403].includes(res.status) || res.url.toLowerCase().includes("login")) return false;
    const text = await res.text();
    if (/<input\b[^>]*type\s*=\s*["']?password/i.test(text)) return false;
    return true;
  } catch {
    return false;
  }
}

async function loginToPortal(env) {
  const username = env.PORTAL_USER;
  const password = env.PORTAL_PASS;
  if (!username || !password) {
    console.log("Portal credentials not configured (set PORTAL_USER/PORTAL_PASS).");
    return false;
  }
  try {
    const res = await pfetch(LOGIN_URL);
    if (res.status !== 200) {
      console.log("Failed to load login page");
      return false;
    }
    const html = await res.text();
    const req = buildLoginRequest(html, username, password);
    if (!req) {
      console.log("Could not read login form or solve the math CAPTCHA");
      return false;
    }
    console.log(`Posting login to ${req.action} with fields ${Object.keys(req.payload).join(",")}`);
    const body = new URLSearchParams(req.payload).toString();
    await pfetch(req.action, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    const ok = await isLoggedIn();
    console.log(ok ? "Login successful!" : "Login failed (wrong credentials or CAPTCHA)");
    return ok;
  } catch (e) {
    console.log("Login Exception: " + (e && e.message ? e.message : e));
    return false;
  }
}

// ---------------------------------------------------------------- data fetch
function pad2(n) {
  return String(n).padStart(2, "0");
}
function ymd(d) {
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`;
}

function buildParams(portalFilters) {
  const now = new Date();
  const pf = portalFilters || {};
  let d1, d2;
  if (pf.date) {
    d1 = pf.date + " 00:00:00";
    d2 = pf.date + " 23:59:59";
  } else if (pf.month) {
    const parts = pf.month.split("-");
    const last = new Date(Date.UTC(+parts[0], +parts[1], 0)).getUTCDate();
    d1 = `${pf.month}-01 00:00:00`;
    d2 = `${pf.month}-${pad2(last)} 23:59:59`;
  } else if (pf.start || pf.end) {
    d1 = (pf.start || "2000-01-01") + " 00:00:00";
    d2 = (pf.end || ymd(now)) + " 23:59:59";
  } else {
    d1 = ymd(new Date(now.getTime() - 86400000)) + " 00:00:00";
    d2 = ymd(new Date(now.getTime() + 86400000)) + " 23:59:59";
  }
  // NOTE: number/cli/month are filtered LOCALLY (see rowPassesFilters) — the
  // portal's own fnum/fcli fields use different value formats.
  const params = {
    fdate1: d1, fdate2: d2,
    frange: "", fnum: "", fcli: "",
    fgdate: "", fgmonth: "", fgrange: "",
    fgnumber: "", fgcli: "", fg: "0",
    sEcho: "1", iColumns: "7", sColumns: ",,,,,,",
    iDisplayStart: "0", iDisplayLength: "500",
    sSearch: "", bRegex: "false",
    iSortCol_0: "0", sSortDir_0: "desc", iSortingCols: "1",
    _: String(Date.now()),
  };
  for (let i = 0; i < 7; i++) {
    params[`mDataProp_${i}`] = String(i);
    params[`sSearch_${i}`] = "";
    params[`bRegex_${i}`] = "false";
    params[`bSearchable_${i}`] = "true";
    params[`bSortable_${i}`] = "true";
  }
  return params;
}

const portalInfo = { total: null };

async function fetchRows(env, portalFilters) {
  const headers = {
    "X-Requested-With": "XMLHttpRequest",
    Referer: INBOX_URL,
    Accept: "application/json, text/javascript, */*; q=0.01",
  };
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await pfetch(INBOX_URL); // warm up the session
      const qs = new URLSearchParams(buildParams(portalFilters)).toString();
      const r = await pfetch(`${DATA_URL}?${qs}`, { headers });
      const text = await r.text();
      const t = text.trim();
      if (r.url.toLowerCase().includes("login") || t.startsWith("<!DOCTYPE") || t.startsWith("<html")) {
        throw new Error("Session expired, got HTML");
      }
      const data = JSON.parse(t);
      const rows = data.aaData || [];
      portalInfo.total = data.iTotalRecords;
      return rows;
    } catch (e) {
      if (attempt < 2) {
        if (!(await loginToPortal(env))) return null;
      } else {
        return null;
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------- OTP parsing
const ALNUM_TOKEN = /(?<![\w/@.])([A-Za-z0-9]{4,8})(?![\w@/]|\.\w)/g;
const OTP_KEYWORD = /otp|code|pin|verification|password|passcode/i;

function extractAlnumOtp(message) {
  const cands = [];
  for (const m of String(message).matchAll(ALNUM_TOKEN)) cands.push([m.index, m[1]]);
  const mixed = cands.filter(([, t]) => /\d/.test(t) && /[A-Za-z]/.test(t));
  if (!mixed.length) return null;
  const kw = String(message).match(OTP_KEYWORD);
  if (kw) {
    for (const [p, t] of cands) {
      if (p >= kw.index + kw[0].length && /\d/.test(t)) return t;
    }
  }
  return mixed[0][1];
}

function extractOtp(message, alnum = false) {
  const msg = String(message);
  if (alnum) {
    const f = extractAlnumOtp(msg);
    if (f) return f;
  }
  let m = msg.match(/(?:otp|code|pin|verification)\D{0,25}(\d{4,8})/i);
  if (m) return m[1];
  m = msg.match(/(\d{4,8})\D{0,25}(?:is your|otp|code)/i);
  if (m) return m[1];
  m = msg.match(/\b(\d{3})-(\d{3})\b/); // WhatsApp/Telegram style 123-456
  if (m) return m[1] + m[2];
  m = msg.match(/\b\d{4,6}\b/);
  return m ? m[0] : null;
}

function phNational(number) {
  let d = String(number).replace(/\D/g, "");
  if (d.startsWith("63") && d.length >= 12) d = d.slice(2);
  else if (d.startsWith("0") && d.length >= 11) d = d.slice(1);
  return d.length > 10 ? d.slice(-10) : d;
}

function rowMatchesPhone(cells, target) {
  if (!target) return false;
  for (const cell of cells) {
    const token0 = String(cell).replace(/[\s+\-().]/g, "");
    if (/^[\d*xX#]{9,15}$/.test(token0)) {
      let token = token0;
      if (token.startsWith("63") && token.length >= 12) token = token.slice(2);
      else if (token.startsWith("0") && token.length >= 11) token = token.slice(1);
      token = token.slice(-10);
      if (token.length === target.length) {
        const real = [...token]
          .map((a, i) => [a, target[i]])
          .filter(([a]) => !"*xX#".includes(a));
        if (real.length >= 6 && real.every(([a, b]) => a === b)) return true;
      }
    }
  }
  return cells.join(" ").replace(/\D/g, "").includes(target);
}

// OTP rows already returned, so an old code is never sent twice.
// (In-memory; lost if the isolate is evicted — same caveat as a server restart.)
const servedRows = new Map();

function findNewOtp(rows, targetDigits, markOnly = false) {
  let seen = servedRows.get(targetDigits);
  if (!seen) {
    seen = new Set();
    servedRows.set(targetDigits, seen);
  }
  const candidates = [];
  rows.forEach((row, idx) => {
    if (!Array.isArray(row)) return;
    const cells = row.map((c) => stripTags(String(c)));
    const rowText = cells.join(" ");
    if (!rowMatchesPhone(cells, targetDigits)) return;
    const rowKey = rowText;
    if (markOnly) {
      seen.add(rowKey);
      return;
    }
    if (seen.has(rowKey)) return;
    const stampM = rowText.match(TIMESTAMP_RE);
    const message = cells.reduce((a, b) => (a.length >= b.length ? a : b), "");
    const otp = extractOtp(message);
    if (otp) candidates.push([stampM ? stampM[0] : "", otp, rowKey, idx]);
  });
  if (!candidates.length) return null;
  // newest timestamp wins; without timestamps the first row (newest on top) wins
  let best = null;
  for (const c of candidates) {
    if (!best || c[0] > best[0] || (c[0] === best[0] && c[3] < best[3])) best = c;
  }
  seen.add(best[2]);
  return best[1];
}

function normalizePhone(phoneParam) {
  return phNational(phoneParam);
}

// ---------------------------------------------------------------- CLI detection
const CLI_PATTERNS = {
  Microsoft: [/microsoft/i, /msft/i, /azure/i, /outlook/i],
  "Royal Canin": [/royal\s*canin/i, /canin/i],
  Ticketmaster: [/ticketmaster/i, /tkmst/i],
  Google: [/google/i, /g-/i, /gmail/i],
  WhatsApp: [/whatsapp/i, /wa-/i],
  Telegram: [/telegram/i, /t\.me/i],
  Facebook: [/facebook/i, /fb-/i],
  Amazon: [/amazon/i, /amzn/i],
  Uber: [/uber/i],
  Apple: [/apple/i],
};

function detectCli(text, sender = "") {
  const combined = `${sender} ${text}`;
  for (const [cli, patterns] of Object.entries(CLI_PATTERNS)) {
    for (const pat of patterns) {
      if (pat.test(combined)) return cli;
    }
  }
  return sender && sender.trim() ? sender.trim().replace(/\b\w/g, (c) => c.toUpperCase()) : "Other";
}

// ---------------------------------------------------------------- rows -> objects
function extractNumber(cells) {
  for (const cell of cells) {
    const token0 = String(cell).replace(/[\s+\-().]/g, "");
    if (/^[\d*xX#]{9,15}$/.test(token0)) {
      let token = token0;
      if (token.startsWith("63") && token.length >= 12) token = token.slice(2);
      else if (token.startsWith("0") && token.length >= 11) token = token.slice(1);
      return "+63" + token.slice(-10);
    }
  }
  return null;
}

function getRequestFilters(searchParams) {
  const g = (k) => (searchParams.get(k) || "").trim();
  return { number: g("number"), cli: g("cli"), date: g("date"), month: g("month"), start: g("start"), end: g("end") };
}

function parseRow(row, alnum = false) {
  if (!Array.isArray(row)) return null;
  const cells = row.map((c) => stripTags(String(c)));
  const stampM = cells.join(" ").match(TIMESTAMP_RE);
  const stamp = stampM ? stampM[0] : "";
  const number = extractNumber(cells);
  const texts = cells.filter((c) => !TIMESTAMP_FULL.test(c));
  const pool = texts.length ? texts : cells;
  const message = pool.reduce((a, b) => (a.length >= b.length ? a : b), "");
  return {
    number,
    cli: detectCli(message),
    code: extractOtp(message, alnum),
    text: message,
    timestamp: stamp,
  };
}

function rowPassesFilters(p, f) {
  if (!p) return false;
  if (f.number) {
    const want = f.number.replace(/\D/g, "");
    const have = (p.number || "").replace(/\D/g, "");
    if (want && !have.includes(want)) return false;
  }
  if (f.cli && f.cli.toLowerCase() !== "all") {
    if ((p.cli || "").toLowerCase() !== f.cli.toLowerCase()) return false;
  }
  const ts = (p.timestamp || "").slice(0, 10);
  if (f.date && ts !== f.date) return false;
  if (f.month && ts.slice(0, 7) !== f.month) return false;
  if (f.start && ts && ts < f.start) return false;
  if (f.end && ts && ts > f.end) return false;
  return true;
}

function todayStr(env) {
  const off = parseFloat(env.PORTAL_TZ_OFFSET_HOURS || "0") || 0;
  const d = new Date(Date.now() + off * 3600000);
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`;
}

function computeStats(rows, alnum, filters, env) {
  const f = filters || {};
  const hasDateFilter = !!(f.date || f.month || f.start || f.end);
  const today = todayStr(env);
  const data = {};
  let total = 0;
  for (const row of rows) {
    const p = parseRow(row, alnum);
    if (!p || !p.number) continue;
    if (!rowPassesFilters(p, f)) continue;
    const stamp = p.timestamp;
    if (!hasDateFilter && stamp && stamp.slice(0, 10) !== today) continue; // not today's SMS
    total += 1;
    if (!data[p.number]) data[p.number] = [];
    if (p.code) {
      data[p.number].push({ otp: p.code, time: stamp.slice(11, 19), cli: p.cli });
    }
  }
  const numbers = Object.entries(data)
    .sort((a, b) => b[1].length - a[1].length)
    .map(([n, otps]) => {
      otps.sort((a, b) => (a.time < b.time ? 1 : -1));
      const cliCounts = {};
      for (const o of otps) cliCounts[o.cli] = (cliCounts[o.cli] || 0) + 1;
      const topCli = Object.entries(cliCounts).sort((a, b) => b[1] - a[1])[0];
      return {
        number: n,
        country_code: n.slice(0, 3),
        local: n.slice(3),
        otp_count: otps.length,
        last_otp: otps.length ? otps[0].otp : null,
        last_otp_time: otps.length ? otps[0].time : "",
        cli: topCli ? topCli[0] : null,
        otps,
      };
    });
  return { total_sms: total, date: f.date || today, alnum: !!alnum, filters: f, numbers };
}

// ---------------------------------------------------------------- http layer
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "*",
      "Cache-Control": "no-store",
    },
  });
}

async function handleStats(url, env) {
  const f = getRequestFilters(url.searchParams);
  const rows = await fetchRows(env, f);
  if (!rows) return json({ error: "Failed to log into SMS portal" }, 500);
  return json(computeStats(rows, url.searchParams.get("alnum") === "1", f, env));
}

async function handleMessages(url, env) {
  const f = getRequestFilters(url.searchParams);
  const alnum = url.searchParams.get("alnum") === "1";
  const rows = await fetchRows(env, f);
  if (!rows) return json({ error: "Failed to log into SMS portal" }, 500);
  const out = [];
  for (const row of rows) {
    const p = parseRow(row, alnum);
    if (!p || !p.number) continue;
    if (!rowPassesFilters(p, f)) continue;
    out.push({ number: p.number, cli: p.cli, code: p.code, text: p.text, timestamp: p.timestamp });
  }
  out.sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
  return json({ total: out.length, filters: f, messages: out.slice(0, 500) });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        },
      });
    }
    const path = url.pathname;
    try {
      if (path === "/ping") {
        return json({ status: "alive", time: new Date().toISOString() });
      }
      if (path === "/get-otp") {
        const phoneParam = (url.searchParams.get("phone") || "").trim();
        const target = normalizePhone(phoneParam);
        if (!target) return json({ error: "Phone parameter required" }, 400);
        const rows = await fetchRows(env, null);
        if (!rows) return json({ error: "Failed to log into SMS portal" }, 500);
        const otp = findNewOtp(rows, target);
        return json({ phone: phoneParam, otp, rows_seen: rows.length });
      }
      if (path === "/mark-seen") {
        const phoneParam = (url.searchParams.get("phone") || "").trim();
        const target = normalizePhone(phoneParam);
        if (!target) return json({ error: "Phone parameter required" }, 400);
        const rows = await fetchRows(env, null);
        if (!rows) return json({ error: "Failed to log into SMS portal" }, 500);
        findNewOtp(rows, target, true);
        return json({ phone: phoneParam, marked: true });
      }
      if (path === "/stats") return handleStats(url, env);
      if (path === "/messages") return handleMessages(url, env);
      if (path === "/restart") {
        servedRows.clear();
        jar.clear();
        const ok = await loginToPortal(env);
        if (!ok) return json({ error: "Re-login to portal failed" }, 500);
        return handleStats(url, env);
      }
      if (path === "/debug-rows") {
        const rows = await fetchRows(env, null);
        if (!rows) return json({ error: "Failed to log into SMS portal" }, 500);
        return json({ rows_seen: rows.length, sample: rows.slice(0, 5) });
      }
      return json({ error: "Not found" }, 404);
    } catch (e) {
      return json({ error: String((e && e.message) || e) }, 500);
    }
  },
};

// Named exports for local unit testing (node --test style harness below).
export {
  stripTags,
  solveMathCaptcha,
  buildLoginRequest,
  extractOtp,
  extractAlnumOtp,
  phNational,
  rowMatchesPhone,
  detectCli,
  parseRow,
  rowPassesFilters,
  getRequestFilters,
  buildParams,
  computeStats,
  findNewOtp,
  normalizePhone,
  extractNumber,
};
