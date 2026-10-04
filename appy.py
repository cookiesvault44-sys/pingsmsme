import os
import re
import sys
import json
import getpass
import threading
import webbrowser
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------- CONFIG
PORTAL_BASE_URL = "http://135.125.222.224/ints"
LOGIN_URL = f"{PORTAL_BASE_URL}/login"
INBOX_URL = f"{PORTAL_BASE_URL}/client/SMSCDRStats"
DATA_URL = f"{PORTAL_BASE_URL}/client/res/data_smscdr.php"

# ---------------------------------------------------------------- SAVED LOGIN
# First run: asks for the portal username/password in the console window and
# saves them next to the exe/script in login.json, so you don't retype them
# every time you open the program. Run with --reset-login to change them.
CONFIG_PATH = (
    Path(sys.executable).parent / "login.json"
    if getattr(sys, "frozen", False)  # True when running as a PyInstaller .exe
    else Path(__file__).resolve().parent / "login.json"
)

def load_saved_login():
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if data.get("username") and data.get("password"):
                return data["username"], data["password"]
        except (OSError, json.JSONDecodeError):
            pass
    return None

def save_login(username, password):
    CONFIG_PATH.write_text(
        json.dumps({"username": username, "password": password}, indent=2),
        encoding="utf-8",
    )

def ask_login():
    print("=" * 50)
    print(" SMS Portal login (saved for next time)")
    print("=" * 50)
    username = input("Portal username: ").strip()
    password = getpass.getpass("Portal password: ").strip()
    save_login(username, password)
    print(f"Saved to {CONFIG_PATH}\n")
    return username, password

def get_login():
    # Env vars always win, so Render/production can override without files.
    env_user, env_pass = os.environ.get("PORTAL_USER"), os.environ.get("PORTAL_PASS")
    if env_user and env_pass:
        return env_user, env_pass
    if "--reset-login" in sys.argv:
        return ask_login()
    saved = load_saved_login()
    if saved:
        return saved
    if not sys.stdin.isatty():
        # e.g. running under gunicorn on Render without env vars: never prompt,
        # portal calls will just fail until PORTAL_USER/PORTAL_PASS are set.
        print("WARNING: PORTAL_USER/PORTAL_PASS not set and no console available.")
        return "", ""
    return ask_login()

USERNAME, PASSWORD = get_login()

# Philippines numbers: national format is 10 digits starting with 9
# (e.g. 9171234567). The portal shows them as 63 9171234567, the extension
# may send 09171234567, +639171234567 or 9171234567. All are normalized.
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

portal_lock = threading.RLock()

# One portal session per portal username, so the extension can serve several
# portal accounts (e.g. yours and a friend's) without touching Render:
# the extension sends X-Portal-User / X-Portal-Pass headers with each request.
portal_sessions = {}  # portal username -> requests.Session

def get_session(username):
    """Return (creating if needed) the portal session for this username."""
    with portal_lock:
        sess = portal_sessions.get(username)
        if sess is None:
            sess = requests.Session()
            sess.headers.update({"User-Agent": UA})
            portal_sessions[username] = sess
        return sess

LOGIN_REQUIRED = ("Portal login required — extension popup me apna portal "
                    "login save karo.")

def get_request_creds():
    """Portal login for this request, from X-Portal-User / X-Portal-Pass
    headers (sent by the extension when the user logged in there).
    No headers -> (None, None): every route must reject the request.
    There is deliberately NO silent fallback to the server env credentials,
    so one install can never see another user's portal account."""
    user = (request.headers.get("X-Portal-User") or "").strip()
    pw = request.headers.get("X-Portal-Pass") or ""
    if user and pw:
        return user, pw
    return None, None

def require_login():
    """Returns ((username, password), None) or (None, 401-response)."""
    username, password = get_request_creds()
    if not username:
        return None, (jsonify({"error": LOGIN_REQUIRED}), 401)
    return (username, password), None

# OTP rows already returned, so an old code is never sent twice
served_rows = {}  # (username, target_digits) -> set of row keys
portal_info = {"total": None}  # total SMS count reported by the portal

TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?")

# ---------------------------------------------------------------- LOGIN
def solve_math_captcha(text):
    """Find 'a + b' in the text and return the sum."""
    match = re.search(r"(\d{1,2})\s*\+\s*(\d{1,2})", text)
    if match:
        return int(match.group(1)) + int(match.group(2))
    return None

def build_login_request(html, username, password):
    """Read the real login form so field names/action come from the site.

    Uses the per-request portal credentials (NOT the server globals), so each
    extension user really logs into the portal as themselves."""
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    if not form:
        return None, None
    captcha = solve_math_captcha(form.get_text(" ")) or solve_math_captcha(soup.get_text(" "))
    if captcha is None:
        return None, None
    payload = {}
    username_set = False
    for inp in form.find_all("input"):
        name = inp.get("name")
        itype = (inp.get("type") or "text").lower()
        if not name or itype in ("submit", "button", "image", "checkbox", "radio"):
            continue
        lname = name.lower()
        if itype == "password":
            payload[name] = password
        elif itype == "hidden":
            payload[name] = inp.get("value", "")
        elif any(k in lname for k in ("capt", "answer", "math")):
            payload[name] = str(captcha)
        elif not username_set:
            payload[name] = username
            username_set = True
        else:
            payload[name] = str(captcha)
    action = urljoin(LOGIN_URL, form.get("action") or LOGIN_URL)
    return action, payload

def is_logged_in(session):
    """Open the inbox page; True only if we really got it (not the login page)."""
    try:
        res = session.get(INBOX_URL, timeout=10)
    except requests.RequestException:
        return False
    if res.status_code in (401, 403) or "login" in res.url.lower():
        return False
    page = BeautifulSoup(res.text, "html.parser")
    if page.find("input", {"type": "password"}):
        return False
    return True

def login_to_portal(session, username, password):
    if not username or not password:
        print("Portal credentials not configured (set PORTAL_USER/PORTAL_PASS).")
        return False
    try:
        response = session.get(LOGIN_URL, timeout=10)
        if response.status_code != 200:
            print("Failed to load login page")
            return False
        action, payload = build_login_request(response.text, username, password)
        if not payload:
            print("Could not read login form or solve the math CAPTCHA")
            return False
        print(f"Posting login to {action} with fields {list(payload.keys())}")
        session.post(action, data=payload, timeout=10)
        ok = is_logged_in(session)
        print("Login successful!" if ok else "Login failed (wrong credentials or CAPTCHA)")
        return ok
    except Exception as e:
        print(f"Login Exception: {e}")
        return False

# ---------------------------------------------------------------- DATA FETCH
def build_params(portal_filters=None, display_start=0, display_length=500):
    now = datetime.now()
    pf = portal_filters or {}

    # Date window for the portal fetch. Widened when the user filters by an
    # explicit date/month/range so older rows are included; otherwise a wide
    # +-1 day window (the portal clock may differ from ours).
    # NOTE: number/cli/month filters are applied LOCALLY in row_passes_filters()
    # only -- the portal's own fnum/fcli fields use different value formats
    # (e.g. they don't know "Royal Canin"), so passing ours would wrongly
    # return zero rows.
    if pf.get("date"):
        d1 = pf["date"] + " 00:00:00"
        d2 = pf["date"] + " 23:59:59"
    elif pf.get("month"):
        import calendar
        y, m = pf["month"].split("-")[:2]
        last = calendar.monthrange(int(y), int(m))[1]
        d1 = f"{pf['month']}-01 00:00:00"
        d2 = f"{pf['month']}-{last:02d} 23:59:59"
    elif pf.get("start") or pf.get("end"):
        d1 = (pf.get("start") or "2000-01-01") + " 00:00:00"
        d2 = (pf.get("end") or now.strftime("%Y-%m-%d")) + " 23:59:59"
    else:
        d1 = (now - timedelta(days=1)).strftime("%Y-%m-%d 00:00:00")
        d2 = (now + timedelta(days=1)).strftime("%Y-%m-%d 23:59:59")

    # FIX: Removed ALL trailing spaces from dictionary keys and values
    params = {
        "fdate1": d1, "fdate2": d2,
        "frange": "", "fnum": "", "fcli": "",
        "fgdate": "", "fgmonth": "", "fgrange": "",
        "fgnumber": "", "fgcli": "", "fg": 0,
        "sEcho": 1, "iColumns": 7, "sColumns": ",,,,,,",
        "iDisplayStart": display_start, "iDisplayLength": display_length,
        "sSearch": "", "bRegex": "false",
        "iSortCol_0": 0, "sSortDir_0": "desc", "iSortingCols": 1,
        "_": int(now.timestamp() * 1000),
    }
    for i in range(7):
        params.update({
            f"mDataProp_{i}": i, f"sSearch_{i}": "",
            f"bRegex_{i}": "false", f"bSearchable_{i}": "true",
            f"bSortable_{i}": "true",
        })
    return params

def fetch_rows(username, password, portal_filters=None, display_start=0,
               display_length=500):
    """
    Return one page of SMS rows (list of lists) from the AJAX endpoint, using
    the portal session that belongs to `username`. Logs in again if the
    session expired. Returns None if login fails.
    Use fetch_all_rows() to collect every page.
    """
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Referer": INBOX_URL,
        "Accept": "application/json, text/javascript, */*; q=0.01"
    }
    session = get_session(username)
    with portal_lock:
        for attempt in range(3):
            try:
                # FIX 1: "Refresh the page" first to warm up the session and set required cookies/tokens.
                print(f"[DEBUG] Visiting inbox page to warm up session...")
                session.get(INBOX_URL, timeout=10)
                
                print(f"[DEBUG] Fetching data from AJAX endpoint...")
                r = session.get(DATA_URL, params=build_params(portal_filters, display_start, display_length), headers=headers, timeout=15)
                
                print(f"[DEBUG] Response Status: {r.status_code}")
                
                # FIX 2: Check if the server gave us a login page instead of JSON
                if "login" in r.url.lower() or r.text.strip().startswith("<!DOCTYPE") or r.text.strip().startswith("<html"):
                    print("[DEBUG] ERROR: Portal returned HTML/Login page. Session expired.")
                    raise ValueError("Session expired, got HTML")

                # Print a snippet of the response so you can see what the server actually said
                print(f"[DEBUG] Response snippet: {r.text[:200]}")
                
                data = r.json()
                rows = data.get("aaData", [])
                portal_info["total"] = data.get("iTotalRecords")
                print(f"[DEBUG] Successfully fetched {len(rows)} rows.")
                return rows
                
            except Exception as e:
                print(f"[ERROR] Fetch failed (attempt {attempt + 1}): {e}")
                if attempt < 2:
                    print("[DEBUG] Attempting to re-login...")
                    if not login_to_portal(session, username, password):
                        print("[ERROR] Re-login failed completely.")
                        return None
                else:
                    print("[ERROR] Max retries reached. Giving up.")
                    return None


def fetch_all_rows(username, password, portal_filters=None, page_size=500,
                   max_pages=20):
    """Collect EVERY portal row by paging (iDisplayStart offsets).

    The portal caps a single response at page_size rows, so reading only the
    first page silently undercounts (e.g. 500 shown instead of 842).
    Returns None if login fails.
    """
    all_rows = []
    start = 0
    for _ in range(max_pages):
        rows = fetch_rows(username, password, portal_filters,
                           display_start=start, display_length=page_size)
        if rows is None:
            return None
        if not rows:
            break
        all_rows.extend(rows)
        if len(rows) < page_size:
            break
        start += page_size
    return all_rows

# ---------------------------------------------------------------- OTP PARSING
ALNUM_TOKEN = re.compile(r"(?<![\w/@.])([A-Za-z0-9]{4,8})(?![\w@/]|\.\w)")
OTP_KEYWORD = re.compile(r"otp|code|pin|verification|password|passcode", re.I)

# ---------------------------------------------------------------- CLI (from the portal itself)
# The portal reports the sending service directly in column 3 of every row
# (e.g. "TKTMASTER"). No guessing, no hardcoded list — the extension shows
# exactly the CLIs that exist in the portal data.
def detect_cli(cells):
    """Sending service = portal column 3, verbatim."""
    if len(cells) > 3:
        sender = str(cells[3]).strip()
        if sender:
            return sender
    return "Other"

# ---------------------------------------------------------------- COUNTRY + PAYOUT
# Weekly payout scheme (Monday -> Sunday): SMS count per country x rate.
PAYOUT_RATES = {
    "Palestine": 3.0,
    "Philippines": 1.7,
    "Algeria": 1.7,
}

# Route codes the portal uses, mapped to countries (labels vary wildly, e.g.
# 'Palestine-M4-06' vs 'M406'). The user confirmed M406/M606 are Palestine routes.
ROUTE_CODE_COUNTRY = {
    "m406": "Palestine",
    "m606": "Palestine",
}

def country_of(cells, number):
    """Country from the portal's route label (col 1). The label format varies
    ('Palestine-M4-06', 'M406-Palestine', ...), so the WHOLE label is searched
    for a known country name or route code — every route of a country uses
    that country's rate. Falls back to the number's country prefix."""
    route = str(cells[1]).strip().lower() if len(cells) > 1 else ""
    if route:
        for c in PAYOUT_RATES:
            if c.lower() in route:
                return c
        for code, c in ROUTE_CODE_COUNTRY.items():
            if code in route:
                return c
    if number:
        if number.startswith("+972") or number.startswith("+970"):
            return "Palestine"
        if number.startswith("+63"):
            return "Philippines"
        if number.startswith("+213"):
            return "Algeria"
    return "Other"

def split_number(n):
    """'+972569290973' -> ('+972', '569290973'). Variable-length country codes."""
    for cc in ("+972", "+970", "+63", "+213"):
        if n.startswith(cc):
            return cc, n[len(cc):]
    m = re.match(r"(\+\d{1,4})", n or "")
    if m:
        return m.group(1), n[len(m.group(1)):]
    return "", n or ""

def extract_alnum_otp(message):
    """OTPs that mix English letters and digits (e.g. A7K9Q2). Needs >=1 digit and >=1 letter."""
    cands = [(m.start(), m.group(1)) for m in ALNUM_TOKEN.finditer(message)]
    mixed = [(p, t) for p, t in cands if re.search(r"\d", t) and re.search(r"[A-Za-z]", t)]
    if not mixed:
        return None
    kw = OTP_KEYWORD.search(message)
    if kw:
        for p, t in cands:  # first code-like token after the keyword
            if p >= kw.end() and re.search(r"\d", t):
                return t
    return mixed[0][1]

def extract_otp(message, alnum=False):
    """Pull the OTP out of an SMS text. alnum=True also allows letters + digits."""
    if alnum:
        found = extract_alnum_otp(message)
        if found:
            return found
    keyword = re.search(r"(?:otp|code|pin|verification)\D{0,25}(\d{4,8})", message, re.I)
    if keyword:
        return keyword.group(1)
    reverse = re.search(r"(\d{4,8})\D{0,25}(?:is your|otp|code)", message, re.I)
    if reverse:
        return reverse.group(1)
    # WhatsApp/Telegram style codes like 123-456
    dashed = re.search(r"\b(\d{3})-(\d{3})\b", message)
    if dashed:
        return dashed.group(1) + dashed.group(2)
    plain = re.search(r"\b\d{4,6}\b", message)
    return plain.group(0) if plain else None

def ph_national(number):
    """Any PH format -> 10-digit national number (9XXXXXXXXX)."""
    d = re.sub(r"\D", "", str(number))
    if d.startswith("63") and len(d) >= 12:
        d = d[2:]
    elif d.startswith("0") and len(d) >= 11:
        d = d[1:]
    return d[-10:] if len(d) > 10 else d

def row_matches_phone(cells, target):
    """
    True if any cell holds this phone number. Handles 63917..., +63 917...,
    09171234567 and masked numbers like 63917****567 (masked chars match anything).
    """
    for cell in cells:
        token = re.sub(r"[\s+\-().]", "", cell)
        if re.fullmatch(r"[\d*xX#]{9,15}", token):
            # strip country / trunk prefix on the raw token (keeps mask chars)
            if token.startswith("63") and len(token) >= 12:
                token = token[2:]
            elif token.startswith("0") and len(token) >= 11:
                token = token[1:]
            token = token[-10:]
            if len(token) == len(target):
                real = [(a, b) for a, b in zip(token, target) if a not in "*xX#"]
                if len(real) >= 6 and all(a == b for a, b in real):
                    return True
    # fallback: digits-only substring over the whole row
    return target in re.sub(r"\D", "", " ".join(cells))

def find_new_otp(rows, target_digits, username="", mark_only=False):
    """
    Keep rows for this phone, skip rows already served, return the newest OTP.
    With mark_only=True, just remember all matching rows as already seen.
    """
    seen = served_rows.setdefault((username, target_digits), set())
    candidates = []
    for row in rows:
        if not isinstance(row, (list, tuple)):
            continue
        cells = [
            BeautifulSoup(str(c), "html.parser").get_text(" ", strip=True)
            for c in row
        ]
        row_text = " ".join(cells)
        if not row_matches_phone(cells, target_digits):
            continue
        row_key = row_text
        if mark_only:
            seen.add(row_key)
            continue
        if row_key in seen:
            continue
        stamp = TIMESTAMP_RE.search(row_text)
        # the SMS text is usually the longest cell
        message = max(cells, key=len)
        otp = extract_otp(message)
        if otp:
            candidates.append((stamp.group(0) if stamp else "", otp, row_key))
    if not candidates:
        return None
    # newest timestamp wins; without timestamps the first row (newest on top) wins
    best = max(enumerate(candidates), key=lambda x: (x[1][0], -x[0]))[1]
    seen.add(best[2])
    return best[1]

def normalize_phone(phone_param):
    return ph_national(phone_param)

# ---------------------------------------------------------------- FILTERS + CLI
def get_request_filters(args):
    """Filters the extension can send: number, cli, date, month, start, end (range)."""
    return {
        "number": (args.get("number") or "").strip(),
        "cli": (args.get("cli") or "").strip(),
        "date": (args.get("date") or "").strip(),
        "month": (args.get("month") or "").strip(),
        "start": (args.get("start") or "").strip(),
        "end": (args.get("end") or "").strip(),
    }

def parse_row(row, alnum=False):
    """One portal row -> {number, cli, code, text, timestamp} (or None)."""
    if not isinstance(row, (list, tuple)):
        return None
    cells = [BeautifulSoup(str(c), "html.parser").get_text(" ", strip=True) for c in row]
    stamp_m = TIMESTAMP_RE.search(" ".join(cells))
    stamp = stamp_m.group(0) if stamp_m else ""
    number = extract_number(cells)
    texts = [c for c in cells if not TIMESTAMP_RE.fullmatch(c)] or cells
    message = max(texts, key=len) if texts else ""
    return {
        "number": number,
        "country": country_of(cells, number),
        "route": str(cells[1]).strip() if len(cells) > 1 else "",
        "cli": detect_cli(cells),
        "code": extract_otp(message, alnum),
        "text": message,
        "timestamp": stamp,
    }

def row_passes_filters(p, f):
    """Local filter pass (backup for portal-side filtering)."""
    if not p:
        return False
    if f.get("number"):
        want = re.sub(r"\D", "", f["number"])
        have = re.sub(r"\D", "", p["number"] or "")
        if want and want not in have:
            return False
    if f.get("cli") and f["cli"].lower() != "all":
        if (p["cli"] or "").lower() != f["cli"].lower():
            return False
    ts = (p["timestamp"] or "")[:10]
    if f.get("date") and ts != f["date"]:
        return False
    if f.get("month") and ts[:7] != f["month"]:
        return False
    if f.get("start") and ts and ts < f["start"]:
        return False
    if f.get("end") and ts and ts > f["end"]:
        return False
    return True

# ---------------------------------------------------------------- CORS
@app.after_request
def add_cors(resp):
    """Lets the Chrome extension side panel call this server."""
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    resp.headers["Cache-Control"] = "no-store"
    return resp

# ---------------------------------------------------------------- ROUTES

@app.route("/ping", methods=["GET"])
def ping():
    """Render health check endpoint."""
    return jsonify({"status": "alive", "time": datetime.now().isoformat()}), 200

@app.route("/get-otp", methods=["GET"])
def get_otp():
    creds, err = require_login()
    if err:
        return err
    username, password = creds
    phone_param = request.args.get("phone", "").strip()
    target_digits = normalize_phone(phone_param)
    if not target_digits:
        return jsonify({"error": "Phone parameter required"}), 400
    rows = fetch_rows(username, password)
    if rows is None:
        return jsonify({"error": "Failed to log into SMS portal"}), 500
    try:
        otp = find_new_otp(rows, target_digits, username)
    except Exception as e:
        return jsonify({"error": f"Error parsing rows: {e}"}), 500
    return jsonify({"phone": phone_param, "otp": otp, "rows_seen": len(rows)})

@app.route("/mark-seen", methods=["GET"])
def mark_seen():
    """Call this BEFORE the SMS is requested, so old SMS for this number are ignored."""
    creds, err = require_login()
    if err:
        return err
    username, password = creds
    phone_param = request.args.get("phone", "").strip()
    target_digits = normalize_phone(phone_param)
    if not target_digits:
        return jsonify({"error": "Phone parameter required"}), 400
    rows = fetch_rows(username, password)
    if rows is None:
        return jsonify({"error": "Failed to log into SMS portal"}), 500
    find_new_otp(rows, target_digits, username, mark_only=True)
    return jsonify({"phone": phone_param, "marked": True})

# ---------------------------------------------------------------- STATS (floating panel)
def extract_number(cells):
    """Find the phone number cell -> '+<country><national>' (972/970, 63, 213 ...)."""
    for cell in cells:
        token = re.sub(r"[\s+\-().]", "", cell)
        if not re.fullmatch(r"[\d*xX#]{9,15}", token):
            continue
        if token.startswith("972"):
            return "+972" + token[3:]
        if token.startswith("970"):
            return "+970" + token[3:]
        if token.startswith("63") and len(token) >= 11:
            return "+63" + token[2:]
        if token.startswith("213"):
            return "+213" + token[3:]
        if token.startswith("0") and len(token) >= 10:
            return "+63" + token[1:]   # local format -> Philippines (portal default)
        return "+" + token
    return None

# If the portal clock differs from your PC clock, set e.g. PORTAL_TZ_OFFSET_HOURS=-5
TZ_OFFSET_HOURS = float(os.environ.get("PORTAL_TZ_OFFSET_HOURS", "0"))

def today_str():
    return (datetime.now() + timedelta(hours=TZ_OFFSET_HOURS)).strftime("%Y-%m-%d")

def compute_stats(rows, alnum=False, filters=None):
    """Per-number OTP view. TODAY only, unless a date/month/start/end filter is given.
    Every OTP and every number now also carries its CLI (sending service)."""
    f = filters or {}
    has_date_filter = any(f.get(k) for k in ("date", "month", "start", "end"))
    today = today_str()
    data = {}
    total = 0
    for row in rows:
        p = parse_row(row, alnum)
        if not p or not p["number"]:
            continue
        if not row_passes_filters(p, f):
            continue
        stamp = p["timestamp"]
        if not has_date_filter and stamp and stamp[:10] != today:
            continue  # not today's SMS (unless filtering by date)
        total += 1
        entry = data.setdefault(p["number"], {"otps": [], "countries": {}})
        if p["code"]:
            entry["otps"].append({"otp": p["code"], "time": stamp[11:19] if stamp else "",
                                  "cli": p["cli"]})
        ctry = p.get("country") or "Other"
        entry["countries"][ctry] = entry["countries"].get(ctry, 0) + 1

    numbers = []
    for n, entry in sorted(data.items(), key=lambda kv: -len(kv[1]["otps"])):
        otps = sorted(entry["otps"], key=lambda o: o["time"], reverse=True)  # newest first
        cli_counts = {}
        for o in otps:
            cli_counts[o["cli"]] = cli_counts.get(o["cli"], 0) + 1
        top_cli = max(cli_counts, key=cli_counts.get) if cli_counts else None
        cc, local = split_number(n)
        top_country = max(entry["countries"], key=entry["countries"].get)
        numbers.append({
            "number": n,
            "country_code": cc,          # +972 / +63 / +213 ...
            "local": local,              # number without country code
            "country": top_country,      # Palestine / Philippines / Algeria ...
            "otp_count": len(otps),
            "last_otp": otps[0]["otp"] if otps else None,
            "last_otp_time": otps[0]["time"] if otps else "",
            "cli": top_cli,              # sending service for this number (portal-direct)
            "otps": otps,                # full list, newest first (each has "cli")
        })
    return {"total_sms": total, "date": f.get("date") or today, "alnum": alnum,
            "filters": f, "numbers": numbers}

@app.route("/stats", methods=["GET"])
def stats():
    """Total SMS + OTP count per number, for the extension's floating panel.
    Filters: ?number=&cli=&date=&month=&start=&end=  (+ alnum=1)"""
    creds, err = require_login()
    if err:
        return err
    username, password = creds
    f = get_request_filters(request.args)
    rows = fetch_all_rows(username, password, portal_filters=f)
    if rows is None:
        return jsonify({"error": "Failed to log into SMS portal"}), 500
    result = compute_stats(rows, request.args.get("alnum") == "1", f)
    result["portal_user"] = username
    return jsonify(result)


@app.route("/messages", methods=["GET"])
def messages():
    """Flat message list with CLI + filters (portal-style view).
    Filters: ?number=&cli=&date=&month=&start=&end=  (+ alnum=1)"""
    creds, err = require_login()
    if err:
        return err
    username, password = creds
    f = get_request_filters(request.args)
    alnum = request.args.get("alnum") == "1"
    rows = fetch_rows(username, password, portal_filters=f)
    if rows is None:
        return jsonify({"error": "Failed to log into SMS portal"}), 500
    out = []
    for row in rows:
        p = parse_row(row, alnum)
        if not p or not p["number"]:
            continue
        if not row_passes_filters(p, f):
            continue
        out.append({k: p[k] for k in ("number", "cli", "code", "text", "timestamp")})
    out.sort(key=lambda m: m["timestamp"], reverse=True)
    return jsonify({"total": len(out), "filters": f, "messages": out[:500]})

@app.route("/restart", methods=["GET"])
def restart():
    """Soft restart: forget this user's seen rows, drop their session,
    log in again, return fresh stats."""
    creds, err = require_login()
    if err:
        return err
    username, password = creds
    with portal_lock:
        for key in [k for k in served_rows if k[0] == username]:
            del served_rows[key]
        sess = get_session(username)
        sess.cookies.clear()
        ok = login_to_portal(sess, username, password)
    if not ok:
        return jsonify({"error": "Re-login to portal failed"}), 500
    return stats()

@app.route("/debug-rows", methods=["GET"])
def debug_rows():
    """Shows the first raw rows from the portal, to check the format."""
    creds, err = require_login()
    if err:
        return err
    username, password = creds
    rows = fetch_rows(username, password)
    if rows is None:
        return jsonify({"error": "Failed to log into SMS portal"}), 500
    return jsonify({"rows_seen": len(rows), "sample": rows[:5]})

@app.route("/payout", methods=["GET"])
def payout():
    """Weekly payout (Monday -> Sunday): SMS count per country x rate + grand total.

    Counts every portal row in the current week (each row = 1 SMS), grouped by
    country (from the portal's route label, e.g. 'Palestine-M4-06'). When the
    week ends the window rolls to the new Monday and the counter restarts.
    """
    today = (datetime.now() + timedelta(hours=TZ_OFFSET_HOURS)).date()
    monday = today - timedelta(days=today.weekday())
    sunday = monday + timedelta(days=6)
    creds, err = require_login()
    if err:
        return err
    username, password = creds
    rows = fetch_all_rows(username, password, {"start": monday.isoformat(), "end": sunday.isoformat()})
    if rows is None:
        return jsonify({"error": "Failed to log into SMS portal"}), 500
    per_country = {}
    total_sms = 0
    unknown_sms = 0
    unknown_routes = {}
    for row in rows:
        p = parse_row(row)
        if not p or not p["number"]:
            continue
        c = p.get("country") or "Other"
        if c not in PAYOUT_RATES:
            unknown_sms += 1
            rl = p.get("route") or "?"
            unknown_routes[rl] = unknown_routes.get(rl, 0) + 1
            continue
        per_country[c] = per_country.get(c, 0) + 1
        total_sms += 1
    breakdown = {}
    grand = 0.0
    for c, count in per_country.items():
        amount = round(count * PAYOUT_RATES[c], 2)
        breakdown[c] = {"sms": count, "rate": PAYOUT_RATES[c], "amount": amount}
        grand += amount
    return jsonify({
        "week_start": monday.isoformat(),
        "week_end": sunday.isoformat(),
        "per_country": breakdown,
        "total_sms": total_sms,
        "grand_total": round(grand, 2),
        "portal_user": username,
        "unknown_sms": unknown_sms,
        "unknown_routes": dict(sorted(unknown_routes.items(),
                                      key=lambda kv: -kv[1])[:10]),
    }), 200

if __name__ == "__main__":
    # If the saved username/password turn out to be wrong, delete the bad
    # login.json and ask again (3 tries), instead of starting with dead creds.
    for attempt in range(3):
        if login_to_portal(get_session(USERNAME), USERNAME, PASSWORD):
            break
        print("That username/password didn't work on the portal.")
        if CONFIG_PATH.exists():
            CONFIG_PATH.unlink()
        USERNAME, PASSWORD = ask_login()
    else:
        print("Still couldn't log in after 3 tries. Starting server anyway;")
        print("it will keep retrying in the background.")

    print(f"\nServer running at http://127.0.0.1:5000  (keep this window open)")
    print("Load/reload the Floating Tools extension in Chrome to use it.\n")
    # 127.0.0.1 so only your own PC can reach it; debug off for safety
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)