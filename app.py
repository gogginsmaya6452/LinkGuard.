import os
import re
import math
import socket
import datetime
import sqlite3
import requests
import whois
import difflib


from datetime import timedelta
from urllib.parse import urlparse
from flask import Flask, render_template, request, session, redirect, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests as grequests

app = Flask(__name__)
app.secret_key = "veriscope_super_secret_key_2026"
app.permanent_session_lifetime = timedelta(days=7)

DB_NAME = 'veriscope.db'


# ---------------- KEEP SESSION PERMANENT ----------------
@app.before_request
def make_session_permanent():
    session.permanent = True


# ---------------- DATABASE ----------------
def get_db():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY,
        user_id TEXT,
        url TEXT,
        status TEXT,
        details TEXT,
        domain_age TEXT,
        ip_address TEXT,
        website_status TEXT,
        threat_score REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')

    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                  ("admin", generate_password_hash("admin")))
    except Exception:
        pass

    conn.commit()
    conn.close()


init_db()


# ---------------- TRUSTED TLD GROUPS ----------------
TRUSTED_TLDS = [
    ".com", ".org", ".net", ".edu", ".gov", ".mil",
    ".in", ".co.in", ".ac.in", ".gov.in",
    ".uk", ".co.uk", ".au", ".ca"
]

# ---------------- SUSPICIOUS INDICATORS ----------------
SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click",
    ".link", ".club", ".online", ".site", ".info", ".biz", ".pw",
    ".work", ".party", ".loan", ".win", ".review", ".download"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "confirm", "account",
    
    "signin", "password", "credential", "wallet", "support", "alert"
]

# Map brand name → canonical domain for "Did you mean?" suggestion
KNOWN_BRANDS = {
    "paypal":    "www.paypal.com",
    "amazon":    "www.amazon.com",
    "google":    "www.google.com",
    "microsoft": "www.microsoft.com",
    "apple":     "www.apple.com",
    "facebook":  "www.facebook.com",
    "instagram": "www.instagram.com",
    "netflix":   "www.netflix.com",
    "bank":      None,
    "ebay":      "www.ebay.com",
}

# ---------------- FALLBACK DOMAIN REGISTRATION YEARS ----------------
# Used when WHOIS is blocked or rate-limited for well-known domains
KNOWN_DOMAIN_YEARS = {
    "google.com":        1997,
    "youtube.com":       2005,
    "facebook.com":      2004,
    "instagram.com":     2010,
    "twitter.com":       2006,
    "x.com":             1996,
    "microsoft.com":     1991,
    "apple.com":         1987,
    "amazon.com":        1994,
    "netflix.com":       1997,
    "paypal.com":        1999,
    "ebay.com":          1995,
    "wikipedia.org":     2001,
    "linkedin.com":      2002,
    "reddit.com":        2005,
    "github.com":        2007,
    "stackoverflow.com": 2008,
    "whatsapp.com":      2009,
    "zoom.us":           2011,
    "dropbox.com":       2007,
    "yahoo.com":         1995,
    "bing.com":          2009,
    "adobe.com":         1986,
    "wordpress.com":     2005,
    "shopify.com":       2006,
    "flipkart.com":      2007,
    "flipkart.in":       2007,
    "paytm.com":         2010,
    "zomato.com":        2008,
    "swiggy.com":        2014,
    "naukri.com":        1997,
    "indiamart.com":     1999,
    "openai.com":        2015,
    "anthropic.com":     2021,
    "chatgpt.com":       2023,
    "canva.com":         2012,
    "figma.com":         2012,
    "notion.so":         2016,
    "slack.com":         2009,
    "discord.com":       2015,
    "telegram.org":      2013,
    "spotify.com":       2006,
    "twitch.tv":         2011,
    "tiktok.com":        2017,
    "snapchat.com":      2011,
    "pinterest.com":     2009,
    # FIX 1: Added Indian educational/institutional domains
    "nbkrist.org":       2004,
    "jntuk.edu.in":      2008,
    "jntua.edu.in":      2008,
    "jntuh.edu.in":      2008,
    "iitm.ac.in":        1999,
    "iitb.ac.in":        1998,
    "iitd.ac.in":        1999,
    "iitk.ac.in":        1999,
    "iisc.ac.in":        1999,
    "nitw.ac.in":        2002,
    "nitk.ac.in":        2002,
    "nitt.edu":          2002,
    "vit.ac.in":         2001,
    "manipal.edu":       2000,
    "bits-pilani.ac.in": 2000,
    "amrita.edu":        2003,
    "srm.edu.in":        2002,
    "kluniversity.in":   2010,
    "vignan.ac.in":      2005,
}

# ---------------- WHITELISTED DOMAINS ----------------
# FIX 5: Domains that are always returned as SAFE regardless of other checks
WHITELISTED_DOMAINS = [
    "nbkrist.org",
    "jntuk.edu.in",
    "jntua.edu.in",
    "jntuh.edu.in",
    "iitm.ac.in",
    "iitb.ac.in",
    "iitd.ac.in",
    "iitk.ac.in",
    "iisc.ac.in",
    "nitw.ac.in",
    "nitk.ac.in",
    "nitt.edu",
    "vit.ac.in",
    "manipal.edu",
    "bits-pilani.ac.in",
    "amrita.edu",
    "srm.edu.in",
    "kluniversity.in",
    "vignan.ac.in",
    "wikipedia.org",
    "github.com",
    "stackoverflow.com","google.com", "youtube.com", "amazon.com",
    "facebook.com", "microsoft.com", "apple.com", "netflix.com", "paypal.com", "ebay.com",
]


def is_whitelisted(domain):
    """Check if domain or any parent domain is whitelisted."""
    if domain in WHITELISTED_DOMAINS:
        return True
    for w in WHITELISTED_DOMAINS:
        if domain.endswith("." + w):
            return True
    return False


def is_similar_to_brand(domain):
    base = domain.split('.')[0].lower()
    for brand, canonical in KNOWN_BRANDS.items():
        similarity = difflib.SequenceMatcher(None, base, brand).ratio()
        if similarity > 0.8 and base != brand:
            return brand, canonical
    return None, None


# ---------------- UTILITIES ----------------
def calculate_entropy(string):
    if not string:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(string.count(chr(x))) / len(string)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)
    return entropy


def get_page_details(url):
    try:
        r = requests.get(url, timeout=5)
        return r.headers, r.text, r.status_code, r.url
    except Exception:
        return {}, "", 0, url


def get_domain_age_raw(domain):
    """
    Returns a datetime.datetime for the registration date, or None.
    Checks hardcoded fallback list first, then tries live WHOIS.
    """
    # Strip subdomains to get root domain
    parts = domain.split(".")
    if len(parts) > 2:
        root = ".".join(parts[-2:])
    else:
        root = domain

    # ── Step 1: Hardcoded fallback for well-known domains ────────────────────
    if root in KNOWN_DOMAIN_YEARS:
        year = KNOWN_DOMAIN_YEARS[root]
        return datetime.datetime(year, 1, 1)

    # ── Step 2: Live WHOIS lookup ────────────────────────────────────────────
    try:
        w = whois.whois(root)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(creation_date, datetime.datetime):
            return creation_date

        if isinstance(creation_date, datetime.date):
            return datetime.datetime(creation_date.year, creation_date.month, creation_date.day)

        if isinstance(creation_date, str):
            for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%SZ",
                        "%d/%m/%Y", "%Y-%m-%dT%H:%M:%S"):
                try:
                    return datetime.datetime.strptime(creation_date.strip(), fmt)
                except ValueError:
                    pass
            match = re.search(r'\d{4}', creation_date)
            if match:
                return datetime.datetime(int(match.group()), 1, 1)

    except Exception as e:
        print("WHOIS Error:", e)

    return None


def format_domain_age(creation_dt):
    if not creation_dt:
        return None

    now = datetime.datetime.utcnow()
    delta = now - creation_dt

    if delta.days < 0:
        return None

    if delta.days < 180:
        return f"New (since {creation_dt.year})"

    return f"Since {creation_dt.year}"


def get_ip_address(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "Hidden"


def check_website_availability(domain):
    try:
        requests.get(f"https://{domain}", timeout=3)
        return "Online (HTTPS)"
    except Exception:
        try:
            requests.get(f"http://{domain}", timeout=3)
            return "Online (HTTP)"
        except Exception:
            return "Offline"


def count_subdomains(domain):
    parts = domain.split(".")
    return max(0, len(parts) - 2)


def has_brand_in_subdomain(domain):
    parts = domain.split(".")
    subdomain_part = ".".join(parts[:-2]).lower()
    return any(brand in subdomain_part for brand in KNOWN_BRANDS)


# ---------------- CORE ANALYSIS ----------------
def run_analysis(raw_url):
    if not raw_url.startswith(('http://', 'https://')):
        url = 'https://' + raw_url
    else:
        url = raw_url

    try:
        headers, content, status_code, final_url = get_page_details(url)
        parsed = urlparse(final_url)
        domain = parsed.netloc.replace("www.", "").lower()

        creation_dt = get_domain_age_raw(domain)
        ip = get_ip_address(domain)
        entropy = calculate_entropy(domain)

    except Exception as e:
        print("Analysis Error:", e)
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "").lower()
        final_url = url
        headers, content = {}, ""
        creation_dt = None
        ip = get_ip_address(domain)
        entropy = calculate_entropy(domain)

    # FIX 5: Whitelist check — short-circuit immediately for known safe domains
    if is_whitelisted(domain):
        creation_dt = get_domain_age_raw(domain)
        age_display = format_domain_age(creation_dt) or "Unknown"
        return {
            'status': 'SAFE',
            'message': 'Verified educational or institutional domain',
            'domain': domain,
            'age': age_display,
            'ip': get_ip_address(domain),
            'website_status': check_website_availability(domain),
            'threat_score': 0.0,
            'suggestion': None,
        }

    threat_score = 0
    flags = []
    suggestion = None

    # FIX 2: Increased trusted TLD offset from -10 to -20 to better absorb
    # cosmetic false-positive flags on legitimate educational/gov/org sites
    TRUSTED_DOMAINS = [".edu", ".ac.in", ".gov", ".gov.in", ".org"]
    if any(domain.endswith(tld) for tld in TRUSTED_DOMAINS):
        threat_score -= 20

    # ── Check 1: High entropy ────────────────────────────────────────────────
    if entropy > 4.2:
        threat_score += 30
        flags.append("Random-looking domain name (possible DGA)")

    # ── Check 2: Very long URL ───────────────────────────────────────────────
    if len(raw_url) > 75:
        threat_score += 20
        flags.append("Unusually long URL")

    # ── Check 3: @ symbol ───────────────────────────────────────────────────
    if "@" in raw_url:
        threat_score += 35
        flags.append("@ redirect detected in URL")

    # ── Check 4: Suspicious TLD ─────────────────────────────────────────────
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        threat_score += 25
        flags.append(f"Suspicious top-level domain ({domain.rsplit('.', 1)[-1]})")

    # ── Check 5: No HTTPS ───────────────────────────────────────────────────
    if final_url.startswith("http://"):
        threat_score += 15
        flags.append("No HTTPS encryption (plain HTTP)")

    # ── Check 6: Excessive subdomains ───────────────────────────────────────
    sub_count = count_subdomains(domain)
    if sub_count >= 3:
        threat_score += 30
        flags.append(f"Excessive subdomains ({sub_count} levels deep)")
    elif sub_count == 2:
        threat_score += 10
        flags.append("Multiple subdomains detected")

    # ── Check 7: Brand in subdomain (spoofing) ───────────────────────────────
    if has_brand_in_subdomain(domain):
        threat_score += 40
        flags.append("Known brand used in subdomain (possible spoofing)")

    # ── Check 7.5: Typosquatting detection ──────────────────────────────────
    similar_brand, canonical_url = is_similar_to_brand(domain)
    if similar_brand:
        threat_score += 45
        flags.append(f"Domain mimics popular brand '{similar_brand}' (typosquatting)")
        if canonical_url:
            suggestion = canonical_url

    # ── Check 8: Phishing keywords ──────────────────────────────────────────
    url_lower = raw_url.lower()
    matched = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if len(matched) >= 2:
        threat_score += 20
        flags.append(f"Multiple phishing keywords: {', '.join(matched[:3])}")
    elif len(matched) == 1:
        threat_score += 8
        flags.append(f"Suspicious keyword in URL: {matched[0]}")

    # ── Check 9: IP address as domain ───────────────────────────────────────
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        threat_score += 35
        flags.append("IP address used as domain name")

    # ── Check 10: Hyphens ───────────────────────────────────────────────────
    first_label = domain.split(".")[0]
    hyphen_count = first_label.count("-")
    if hyphen_count >= 2:
        threat_score += 20
        flags.append(f"Multiple hyphens in domain ({hyphen_count})")
    elif hyphen_count == 1:
        threat_score += 8
        flags.append("Hyphen found in domain name")

    # ── Check 11: Very new domain ────────────────────────────────────────────
    if creation_dt:
        age_days = (datetime.datetime.utcnow() - creation_dt).days
        if age_days < 365:
            threat_score += 30
            flags.append("Domain registered less than 1 year ago")
        elif age_days < 730:
            threat_score += 15
            flags.append("Newly registered domain (less than 2 years old)")
    else:
        flags.append("Domain age unavailable")

    # ── Check 12: Double slash redirect ───────────────────────────────────────
    if raw_url.count("//") > 2:
        threat_score += 15
        flags.append("Multiple '//' detected (possible redirect obfuscation)")

    # ── Check 13: URL shortener ───────────────────────────────────────────────
    SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"]
    if any(short in domain for short in SHORTENERS):
        threat_score += 25
        flags.append("URL shortener used (hides real destination)")

    # ── Check 14: Suspicious file extensions ──────────────────────────────────
    if any(ext in raw_url.lower() for ext in [".exe", ".zip", ".rar", ".scr"]):
        threat_score += 30
        flags.append("Suspicious downloadable file in URL")

    # ── Check 15: Excessive digits ────────────────────────────────────────────
    digit_ratio = sum(c.isdigit() for c in domain) / len(domain) if domain else 0
    if digit_ratio > 0.3:
        threat_score += 20
        flags.append("Too many numbers in domain (random pattern)")

    # ── Check 16: Redirect mismatch ───────────────────────────────────────────
    if raw_url != final_url:
        http_to_https = raw_url.replace("http://", "https://") == final_url
        if not http_to_https:
            original_domain = urlparse(raw_url).netloc.replace("www.", "")
            final_domain = urlparse(final_url).netloc.replace("www.", "")
            if original_domain != final_domain and not final_domain.endswith(original_domain):
                threat_score += 35
                flags.append("Redirects to different domain")

    # ── Check 17: Missing favicon ─────────────────────────────────────────────
    # FIX 4: Reduced weight from 5 → 3 (cosmetic signal, many legit sites omit it)
    if content and not any(icon in content.lower() for icon in ["rel=\"icon\"", "rel=\"shortcut icon\""]):
        threat_score += 3
        flags.append("No favicon detected (low-quality site)")

    # ── Check 24: Page title phishing keywords ────────────────────────────────
    title_match = re.search(r"<title>(.*?)</title>", content, re.IGNORECASE)
    if title_match:
        title = title_match.group(1).lower()
        if any(word in title for word in ["login", "verify", "secure", "update"]):
            threat_score += 10
            flags.append("Suspicious page title")

    # ── Check 23: Missing trust pages ─────────────────────────────────────────
    # FIX 4: Reduced weight from 10 → 5 (many legit sites organise pages differently)
    if content and not any(word in content.lower() for word in ["about", "contact", "privacy", "terms"]):
        threat_score += 5
        flags.append("No legal/contact information found")

    # ── Check 22: External links ratio ────────────────────────────────────────
    links = re.findall(r'href=["\'](.*?)["\']', content)
    external_links = [l for l in links if l.startswith("http") and domain not in l]
    if len(links) > 0 and len(external_links) / len(links) > 0.6:
        threat_score += 15
        flags.append("Too many external links")

    # ── Cap & determine status ────────────────────────────────────────────────
    threat_score = min(int(threat_score), 100)

    # FIX 3: Raised SUSPICIOUS threshold from 25 → 30 to reduce false positives
    if threat_score >= 50:
        status = "PHISHING"
        summary = "; ".join(flags) if flags else "Multiple high-risk phishing indicators found"
    elif threat_score >= 30:
        status = "SUSPICIOUS"
        summary = "; ".join(flags) if flags else "Some suspicious indicators detected"
    else:
        status = "SAFE"
        summary = "No major threats detected"

    age_display = format_domain_age(creation_dt)
    if not age_display:
        age_display = "Unknown"

    return {
        'status': status,
        'message': summary,
        'domain': domain,
        'age': age_display,
        'ip': ip,
        'website_status': check_website_availability(domain),
        'threat_score': round(threat_score, 1),
        'suggestion': suggestion,
    }


# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username")
        p = request.form.get("password")

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, username, password FROM users WHERE username=?", (u,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], p):
            session.clear()
            session['username'] = user[1]
            session['email'] = user[1]
            session['user_id'] = str(user[0])
            return redirect("/dashboard")

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username")
        p = generate_password_hash(request.form.get("password"))

        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?,?)", (u, p))
            conn.commit()
            conn.close()
            return redirect("/")
        except Exception:
            return render_template("register.html", error="Username already exists")

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/scan", methods=["GET", "POST"])
def scan():
    guest_scans = int(request.cookies.get('guest_scans', 0))

    if request.method == "POST":
        if 'user_id' not in session and guest_scans >= 2:
            return render_template("scan.html", limit_reached=True, guest_scans=guest_scans)

        url = request.form.get("url", "").strip()
        if not url:
            return render_template("scan.html", error="Please enter a URL", limit_reached=False, guest_scans=guest_scans)

        result = run_analysis(url)

        if 'user_id' in session:
            try:
                conn = get_db()
                c = conn.cursor()
                c.execute('''INSERT INTO scan_history
                             (user_id, url, status, details, domain_age, ip_address, website_status, threat_score)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                          (session['user_id'],
                           result.get('domain', url),
                           result.get('status'),
                           result.get('message'),
                           result.get('age'),
                           result.get('ip'),
                           result.get('website_status'),
                           result.get('threat_score')))
                conn.commit()
                conn.close()
            except Exception as e:
                print("DB Save Error:", e)

            return render_template("result.html", result=result)
        else:
            response = make_response(render_template("result.html", result=result))
            response.set_cookie('guest_scans', str(guest_scans + 1), max_age=60 * 60 * 24)
            return response

    if 'user_id' not in session and guest_scans >= 2:
        return render_template("scan.html", limit_reached=True, guest_scans=guest_scans)

    return render_template("scan.html", limit_reached=False, guest_scans=guest_scans)


@app.route("/dashboard")
def dashboard():
    if 'user_id' in session:
        conn = get_db()
        c = conn.cursor()
        uid = session.get('user_id', '0')

        c.execute("SELECT COUNT(*) FROM scan_history WHERE user_id=?", (uid,))
        total = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM scan_history WHERE status='PHISHING' AND user_id=?", (uid,))
        threats = c.fetchone()[0]

        c.execute("SELECT AVG(threat_score) FROM scan_history WHERE user_id=?", (uid,))
        avg = c.fetchone()[0] or 0

        c.execute("SELECT id, url, status, threat_score FROM scan_history WHERE user_id=? ORDER BY timestamp DESC LIMIT 5", (uid,))
        recent_scans = c.fetchall()

        c.execute("SELECT COUNT(*) FROM scan_history WHERE status='SAFE' AND user_id=?", (uid,))
        safe = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM scan_history WHERE status='SUSPICIOUS' AND user_id=?", (uid,))
        suspicious = c.fetchone()[0]

        conn.close()

        threat_dist = [{'1': safe}, {'1': suspicious}, {'1': threats}]
        stats = [total, threats, round(avg, 1)]

        return render_template("dashboard.html",
                               stats=stats,
                               recent_scans=recent_scans,
                               threat_dist=threat_dist)
    else:
        threat_dist = [{'1': 0}, {'1': 0}, {'1': 0}]
        stats = [0, 0, 0.0]
        return render_template("dashboard.html",
                               stats=stats,
                               recent_scans=[],
                               threat_dist=threat_dist)


@app.route("/history")
def history():
    if 'user_id' in session:
        conn = get_db()
        c = conn.cursor()
        c.execute("""SELECT id, url, status, threat_score, timestamp
                     FROM scan_history
                     WHERE user_id=?
                     ORDER BY timestamp DESC""", (session['user_id'],))
        scans = c.fetchall()
        conn.close()
    else:
        scans = []

    return render_template("history.html", scans=scans)


@app.route("/settings")
def settings():
    if 'user_id' not in session:
        return redirect("/login")
    return render_template("settings.html")


@app.route("/download_enhanced_report/<int:scan_id>")
def download_enhanced_report(scan_id):
    if 'user_id' not in session:
        return redirect("/login")

    conn = get_db()
    c = conn.cursor()
    c.execute("""SELECT id, url, status, details, domain_age, ip_address,
                        website_status, threat_score, timestamp
                 FROM scan_history
                 WHERE id=? AND user_id=?""", (scan_id, session['user_id']))
    scan = c.fetchone()
    conn.close()

    if not scan:
        return "Report not found", 404

    report = f"""========================================
   VERISCOPE AI - FORENSIC REPORT
========================================

Scan ID      : #{scan[0]}
Target URL   : {scan[1]}
Status       : {scan[2]}
Threat Score : {scan[7]}/100
Details      : {scan[3]}
Domain Age   : {scan[4]}
IP Address   : {scan[5]}
Website      : {scan[6]}
Scanned At   : {scan[8]}

----------------------------------------
Generated by VeriScope AI
========================================
"""
    response = make_response(report)
    response.headers['Content-Type'] = 'text/plain'
    response.headers['Content-Disposition'] = f'attachment; filename=veriscope_report_{scan_id}.txt'
    return response


@app.route("/google-login", methods=["POST"])
def google_login():
    data = request.get_json()
    token = data.get("token")

    try:
        idinfo = id_token.verify_oauth2_token(
            token,
            grequests.Request(),
            "93245967028-gvs3jtmhmep0mlc72n3t18mifp2d52pr.apps.googleusercontent.com"
        )

        email = idinfo.get("email")

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=?", (email,))
        user = c.fetchone()

        if not user:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                      (email, "google_user"))
            conn.commit()
            user_id = c.lastrowid
        else:
            user_id = user[0]

        conn.close()

        session['username'] = email
        session['email'] = email
        session['user_id'] = str(user_id)

        return {"success": True, "redirect": "/dashboard"}

    except Exception as e:
        print("Google Auth Error:", e)
        return {"success": False}


@app.route("/technology")
def technology():
    return render_template("learn_more.html")


# ---------------- DEBUG (remove before production) ----------------
@app.route("/debug")
def debug():
    return str(dict(session))


# ---------------- RUN ----------------
if __name__ == '__main__':
    app.run(debug=True, port=3000)