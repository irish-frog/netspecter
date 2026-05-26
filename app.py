
#!/usr/bin/env python3
import json
import os
import sqlite3
import time
import socket
import subprocess
import ipaddress
import html
import csv
import io
import secrets
import re
from functools import wraps
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, unquote

import requests
from flask import Flask, request, redirect, Response, session
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None
    InvalidToken = Exception

try:
    import psutil
except Exception:
    psutil = None


BASE_DIR = Path(__file__).resolve().parent


def configured_path(env_name, default_path, local_path):
    override = os.environ.get(env_name)
    if override:
        return Path(override)

    default = Path(default_path)
    if default.exists() or default.parent.exists():
        return default

    return Path(local_path)


INSTALL_ROOT = configured_path("NETSPECTER_INSTALL_ROOT", "/opt/netspecter", BASE_DIR)
CONFIG_ROOT = configured_path("NETSPECTER_CONFIG_ROOT", "/etc/netspecter", BASE_DIR)
DATA_ROOT = configured_path("NETSPECTER_DATA_ROOT", "/var/lib/netspecter", BASE_DIR)
ROOT = Path(os.environ.get("NETSPECTER_APP_ROOT", str(INSTALL_ROOT)))
CONFIG_PATH = CONFIG_ROOT / "config.json"
DB_PATH = DATA_ROOT / "netspecter.db"
CACHE_PATH = DATA_ROOT / "cache.json"
SECRET_KEY_PATH = CONFIG_ROOT / "secret.key"
SESSION_KEY_PATH = CONFIG_ROOT / "session.key"

app = Flask(__name__, static_folder=str(ROOT / "static"), static_url_path="/static")

DEFAULT_CONFIG = {
    "app_name": "NetSpecter",
    "tagline": "Monitor | Filter | Protect",
    "adguard_url": "http://127.0.0.1",
    "adguard_user": "admin",
    "adguard_pass": "",
    "packet_iface": "br0",
    "gateway_ip": "",
    "ignore_ips": [],
    "adguard_querylog_interval_seconds": 15,
    "web_host": "0.0.0.0",
    "web_port": 5050,
    "auth_enabled": True,
    "admin_user": "admin",
    "admin_password_hash": "",
    "lan_prefix": "192.168.1.",
    "collect_interval_seconds": 2,
    "traffic_retention_days": 30,
    "dns_retention_days": 14,
    "public_ip_cache_seconds": 1800,
    "unifi_enabled": False,
    "unifi_connector_url": "",
    "unifi_site_id": "",
    "unifi_api_key": "",
    "scheduled_speedtests_per_day": 0,
}

SENSITIVE_CONFIG_KEYS = {"adguard_pass", "unifi_api_key"}
INTEGRATION_SETTINGS_KEYS = {
    "unifi_enabled", "unifi_connector_url", "unifi_site_id",
    "unifi_api_key", "scheduled_speedtests_per_day",
}
ENCRYPTED_PREFIX = "enc:"

NOISE_DOMAINS = [
    "msftconnecttest.com",
    "connectivitycheck.gstatic.com",
    "ping.ui.com",
    "cloudflare-dns.com",
    "dns.msftncsi.com",
    "detectportal.firefox.com",
]

APP_ICONS = {
    "YouTube": '<i class="fa-brands fa-youtube app-yt"></i>',
    "Netflix": '<i class="fa-solid fa-film app-netflix"></i>',
    "Microsoft": '<i class="fa-brands fa-microsoft app-ms"></i>',
    "Google": '<i class="fa-brands fa-google app-google"></i>',
    "WhatsApp": '<i class="fa-brands fa-whatsapp app-wa"></i>',
    "Facebook": '<i class="fa-brands fa-facebook app-fb"></i>',
    "Instagram": '<i class="fa-brands fa-instagram app-ig"></i>',
    "TikTok": '<i class="fa-brands fa-tiktok app-tiktok"></i>',
    "Twitter / X": '<i class="fa-brands fa-x-twitter app-other"></i>',
    "Snapchat": '<i class="fa-brands fa-snapchat app-other"></i>',
    "Discord": '<i class="fa-brands fa-discord app-other"></i>',
    "Twitch": '<i class="fa-brands fa-twitch app-other"></i>',
    "Disney+": '<i class="fa-solid fa-film app-other"></i>',
    "Prime Video": '<i class="fa-solid fa-circle-play app-other"></i>',
    "Gaming": '<i class="fa-solid fa-gamepad app-game"></i>',
    "Apple": '<i class="fa-brands fa-apple app-apple"></i>',
    "Cloud": '<i class="fa-solid fa-cloud app-cloud"></i>',
    "Security": '<i class="fa-solid fa-shield-halved app-sec"></i>',
    "Other": '<i class="fa-solid fa-globe app-other"></i>',
}
MONITORED_APP_CATEGORIES = {
    "YouTube",
    "Netflix",
    "TikTok",
    "Facebook",
    "Instagram",
    "WhatsApp",
    "Microsoft",
    "Spotify",
    "Steam",
    "Twitter / X",
    "Snapchat",
    "Discord",
    "Twitch",
    "Disney+",
    "Prime Video",
}

DEVICE_ICONS = {
    "PC": '<i class="fa-solid fa-desktop"></i>',
    "Phone": '<i class="fa-solid fa-mobile-screen"></i>',
    "TV": '<i class="fa-solid fa-tv"></i>',
    "Camera": '<i class="fa-solid fa-video"></i>',
    "Server": '<i class="fa-solid fa-server"></i>',
    "IoT": '<i class="fa-solid fa-microchip"></i>',
    "Gateway": '<i class="fa-solid fa-network-wired"></i>',
    "Printer": '<i class="fa-solid fa-print"></i>',
    "Unknown": '<i class="fa-solid fa-circle-question"></i>',
}


def secure_file_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    try:
        path.chmod(0o600)
    except Exception:
        pass


def get_or_create_session_secret():
    if SESSION_KEY_PATH.exists():
        return SESSION_KEY_PATH.read_text().strip()
    key = secrets.token_urlsafe(48)
    secure_file_write(SESSION_KEY_PATH, key)
    return key


def get_or_create_encryption_key():
    if SECRET_KEY_PATH.exists():
        return SECRET_KEY_PATH.read_text().strip().encode()
    if not Fernet:
        return b""
    key = Fernet.generate_key()
    secure_file_write(SECRET_KEY_PATH, key.decode())
    return key


def fernet():
    if not Fernet:
        return None
    try:
        return Fernet(get_or_create_encryption_key())
    except Exception as e:
        print(f"Encryption setup failed: {e}")
        return None


def encrypt_config_value(value):
    text = str(value or "")
    if not text or text.startswith(ENCRYPTED_PREFIX):
        return text
    f = fernet()
    if not f:
        raise RuntimeError("cryptography package is required to encrypt stored passwords")
    return ENCRYPTED_PREFIX + f.encrypt(text.encode()).decode()


def decrypt_config_value(value):
    text = str(value or "")
    if not text.startswith(ENCRYPTED_PREFIX):
        return text
    f = fernet()
    if not f:
        raise RuntimeError("cryptography package is required to decrypt stored passwords")
    try:
        return f.decrypt(text[len(ENCRYPTED_PREFIX):].encode()).decode()
    except InvalidToken:
        print("Config password decrypt failed: invalid encryption key")
        return ""
    except Exception as e:
        print(f"Config password decrypt failed: {e}")
        return ""


app.secret_key = get_or_create_session_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def cfg():
    INSTALL_ROOT.mkdir(parents=True, exist_ok=True)
    CONFIG_ROOT.mkdir(parents=True, exist_ok=True)
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2))

    try:
        raw_data = json.loads(CONFIG_PATH.read_text())
        data = raw_data.copy()
        if not isinstance(data, dict):
            raise ValueError("config root must be a JSON object")
    except Exception as e:
        print(f"Config load failed, using defaults: {e}")
        data = DEFAULT_CONFIG.copy()
        data["app_name"] = "NetSpecter"
        data["tagline"] = "Monitor | Filter | Protect"
        return data

    unsupported_keys = set(data) - set(DEFAULT_CONFIG)
    changed = bool(unsupported_keys)
    if unsupported_keys:
        data = {key: value for key, value in data.items() if key in DEFAULT_CONFIG}

    for key, value in DEFAULT_CONFIG.items():
        if key not in data:
            data[key] = value
            changed = True

    plaintext_sensitive = False
    for key in SENSITIVE_CONFIG_KEYS:
        if data.get(key) and not str(data.get(key)).startswith(ENCRYPTED_PREFIX):
            plaintext_sensitive = True
        if key in data:
            data[key] = decrypt_config_value(data.get(key))

    data["app_name"] = "NetSpecter"
    data["tagline"] = "Monitor | Filter | Protect"

    if changed or plaintext_sensitive:
        save_cfg(data)

    return data


def save_cfg(data):
    CONFIG_ROOT.mkdir(parents=True, exist_ok=True)
    out = data.copy()
    for key in SENSITIVE_CONFIG_KEYS:
        if key in out:
            out[key] = encrypt_config_value(out.get(key))
    secure_file_write(CONFIG_PATH, json.dumps(out, indent=2))


def cfg_list(value):
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return [x.strip() for x in str(value or "").split(",") if x.strip()]


def default_gateway_from_prefix(prefix):
    text = str(prefix or "").strip()
    if text.endswith("."):
        return text + "1"
    return ""


def ignored_ips(config=None):
    c = config or cfg()
    ips = cfg_list(c.get("ignore_ips", []))
    gateway = str(c.get("gateway_ip", "") or "").strip() or default_gateway_from_prefix(c.get("lan_prefix"))
    if gateway and gateway not in ips:
        ips.insert(0, gateway)
    return ips


def today():
    return datetime.now().strftime("%Y-%m-%d")


def range_days():
    value = request.args.get("range", "1d")
    return {"1d": 1, "7d": 7, "30d": 30}.get(value, 1)


def range_key():
    days = range_days()
    return "30d" if days == 30 else "7d" if days == 7 else "1d"


def range_start_day():
    seconds = (range_days() - 1) * 86400
    return datetime.fromtimestamp(time.time() - seconds).strftime("%Y-%m-%d")


def range_query_suffix(extra=""):
    suffix = f"?range={range_key()}"
    if extra:
        suffix += "&" + extra.lstrip("&")
    return suffix


def time_picker():
    options = [("1d", "Today"), ("7d", "7 Days"), ("30d", "30 Days")]
    current = range_key()
    links = ""
    path = h(request.path)
    for key, label in options:
        cls = "active" if key == current else ""
        links += f'<a class="{cls}" href="{path}?range={key}">{label}</a>'
    return f'<div class="time-picker">{links}</div>'


def auth_required():
    c = cfg()
    return bool(c.get("auth_enabled", True))


def admin_password_set():
    return bool(cfg().get("admin_password_hash"))


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def csrf_input():
    return f'<input type="hidden" name="_csrf_token" value="{h(csrf_token())}">'


def setup_missing_items(config=None):
    c = config or cfg()
    missing = []

    if not str(c.get("lan_prefix", "") or "").strip():
        missing.append("LAN Prefix")

    if not str(c.get("packet_iface", "") or "").strip():
        missing.append("Live Traffic Interface")

    if not str(c.get("gateway_ip", "") or "").strip() and not default_gateway_from_prefix(c.get("lan_prefix")):
        missing.append("Gateway IP")

    if not str(c.get("adguard_url", "") or "").strip():
        missing.append("AdGuard URL")

    if str(c.get("adguard_url", "")).strip() == DEFAULT_CONFIG["adguard_url"]:
        missing.append("Confirm AdGuard URL")

    return missing


def setup_banner():
    missing = setup_missing_items()
    if not missing and request.args.get("setup"):
        return '<div class="setup-ok">Setup looks complete. You can continue to the dashboard.</div>'
    if not missing:
        return ""
    items = "".join(f"<li>{h(item)}</li>" for item in missing)
    return f"""
<div class="setup-warning">
  <h2>Finish NetSpecter Setup</h2>
  <p>These deployment settings still need attention before the dashboard opens normally:</p>
  <ul>{items}</ul>
  <p>Save this page after updating them.</p>
</div>
"""


def login_template(title, body):
    return f"""<!DOCTYPE html>
<html>
<head>
<title>{h(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/static/favicon.png">
<link rel="stylesheet" href="/static/theme.css?v=20260526m">
</head>
<body class="login-body">
  <div class="login-card">
    <img src="/static/netspecter-logo-sidebar.png" class="login-logo">
    {body}
  </div>
</body>
</html>"""


@app.before_request
def require_csrf_token():
    if request.method == "POST":
        expected = session.get("_csrf_token", "")
        submitted = request.form.get("_csrf_token", "")
        if not expected or not secrets.compare_digest(str(expected), str(submitted)):
            return Response("Invalid CSRF token.", status=400, mimetype="text/plain")
    return None


@app.before_request
def require_login():
    if request.endpoint in ["static", "login", "logout", "setup_admin"]:
        return None

    if not auth_required():
        return None

    if not admin_password_set():
        return redirect("/setup-admin")

    if session.get("authenticated"):
        if request.endpoint not in ["settings", "logout"] and setup_missing_items():
            return redirect("/settings?setup=1")
        return None

    return redirect("/login")


@app.after_request
def set_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com; "
        "font-src 'self' data: https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https://tile.openstreetmap.org; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'",
    )
    return response


@app.route("/setup-admin", methods=["GET", "POST"])
def setup_admin():
    if admin_password_set():
        return redirect("/login")

    error = ""
    if request.method == "POST":
        username = request.form.get("username", "admin").strip() or "admin"
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            c = cfg()
            c["admin_user"] = username
            c["admin_password_hash"] = generate_password_hash(password)
            c["auth_enabled"] = True
            save_cfg(c)
            session["authenticated"] = True
            session["admin_user"] = username
            return redirect("/")

    body = f"""
<h1>Create Admin Login</h1>
<p>Set the first NetSpecter administrator password.</p>
{f'<div class="login-error">{h(error)}</div>' if error else ''}
<form method="post">
  {csrf_input()}
  <label>Username</label>
  <input name="username" value="admin">
  <label>Password</label>
  <input name="password" type="password" autofocus>
  <label>Confirm Password</label>
  <input name="confirm" type="password">
  <button type="submit">Create Login</button>
</form>
"""
    return login_template("Create Admin Login", body)


@app.route("/login", methods=["GET", "POST"])
def login():
    if not admin_password_set():
        return redirect("/setup-admin")

    error = ""
    if request.method == "POST":
        c = cfg()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username == c.get("admin_user", "admin") and check_password_hash(c.get("admin_password_hash", ""), password):
            session["authenticated"] = True
            session["admin_user"] = username
            return redirect(request.args.get("next") or "/")
        error = "Invalid username or password."

    body = f"""
<h1>Sign In</h1>
<p>Enter your NetSpecter admin credentials.</p>
{f'<div class="login-error">{h(error)}</div>' if error else ''}
<form method="post">
  {csrf_input()}
  <label>Username</label>
  <input name="username" value="{h(cfg().get('admin_user', 'admin'))}">
  <label>Password</label>
  <input name="password" type="password" autofocus>
  <button type="submit">Sign In</button>
</form>
"""
    return login_template("NetSpecter Login", body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


def query(sql, params=()):
    try:
        init_db()
        con = connect_db()
        con.row_factory = sqlite3.Row
        rows = con.execute(sql, params).fetchall()
        con.close()
        return rows
    except Exception as e:
        print(f"DB query failed: {e}")
        return []


def run_sql(sql, params=()):
    try:
        init_db()
        con = connect_db()
        cur = con.execute(sql, params)
        con.commit()
        con.close()
        return cur.rowcount
    except Exception as e:
        print(f"DB write failed: {e}")
        return 0


def load_json(path, default):
    try:
        p = Path(path)
        return json.loads(p.read_text()) if p.exists() else default
    except Exception:
        return default


def save_json(path, data):
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2))
    except Exception as e:
        print(f"JSON save failed for {path}: {e}")


def h(value):
    return html.escape(str(value or ""), quote=True)


def connect_db():
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=30000")
    return con



def init_db():
    """Create the minimum database schema required by the web UI and collector."""
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    con = connect_db()
    con.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            name TEXT,
            mac TEXT,
            vendor TEXT,
            device_type TEXT DEFAULT 'Unknown',
            status TEXT DEFAULT 'Active',
            first_seen TEXT,
            last_seen TEXT,
            owner TEXT,
            location TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS traffic_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            name TEXT,
            mac TEXT,
            downloaded_mb REAL DEFAULT 0,
            uploaded_mb REAL DEFAULT 0,
            total_mb REAL DEFAULT 0,
            live_bps REAL DEFAULT 0,
            day TEXT,
            ts TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_traffic_day_ip ON traffic_samples(day, ip)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_traffic_ip_ts ON traffic_samples(ip, ts)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS traffic_intervals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            name TEXT,
            mac TEXT,
            downloaded_mb REAL DEFAULT 0,
            uploaded_mb REAL DEFAULT 0,
            total_mb REAL DEFAULT 0,
            live_bps REAL DEFAULT 0,
            day TEXT,
            ts TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_intervals_day_ip ON traffic_intervals(day, ip)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_intervals_ip_ts ON traffic_intervals(ip, ts)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS estimated_app_traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            category TEXT NOT NULL,
            downloaded_mb REAL DEFAULT 0,
            uploaded_mb REAL DEFAULT 0,
            total_mb REAL DEFAULT 0,
            day TEXT,
            ts TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_estimated_app_day_ip ON estimated_app_traffic(day, category, ip)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS remote_traffic_intervals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            remote_ip TEXT NOT NULL,
            category TEXT NOT NULL,
            downloaded_mb REAL DEFAULT 0,
            uploaded_mb REAL DEFAULT 0,
            total_mb REAL DEFAULT 0,
            day TEXT,
            ts TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_remote_traffic_day_ip ON remote_traffic_intervals(day, remote_ip, category)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS remote_ip_locations (
            remote_ip TEXT PRIMARY KEY,
            city TEXT,
            region TEXT,
            country TEXT,
            country_code TEXT,
            latitude REAL,
            longitude REAL,
            lookup_ts TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS dns_querylog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            day TEXT,
            ts TEXT,
            client TEXT,
            domain TEXT,
            blocked INTEGER DEFAULT 0,
            category TEXT DEFAULT 'Other'
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_day ON dns_querylog(day)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_client ON dns_querylog(client)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS dns_import_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            cleared_at TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS live_device_speed (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            rx_bps REAL DEFAULT 0,
            tx_bps REAL DEFAULT 0,
            total_bps REAL DEFAULT 0,
            updated_at TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS collector_heartbeat (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            updated_at TEXT,
            packet_iface TEXT,
            status TEXT,
            note TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS device_overrides (
            ip TEXT PRIMARY KEY,
            name TEXT,
            vendor TEXT,
            device_type TEXT,
            status TEXT,
            updated_at TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS device_override_unlocks (
            ip TEXT PRIMARY KEY,
            updated_at TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS speed_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            source TEXT NOT NULL,
            latency_ms REAL,
            download_mbps REAL,
            upload_mbps REAL,
            result_text TEXT,
            success INTEGER DEFAULT 0
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_speed_tests_ts ON speed_tests(ts)")
    con.commit()
    con.close()

def ensure_device_overrides_table():
    if not DB_PATH.exists():
        return

    con = connect_db()
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS device_overrides (
            ip TEXT PRIMARY KEY,
            name TEXT,
            vendor TEXT,
            device_type TEXT,
            status TEXT,
            updated_at TEXT
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS device_override_unlocks (
            ip TEXT PRIMARY KEY,
            updated_at TEXT
        )
        """
    )
    con.commit()
    con.close()


def has_real_vendor(vendor):
    text = str(vendor or "").strip().lower()
    return bool(text and text not in ["unknown", "unknown vendor", "private / random mac", "n/a", "none", "-"])


def private_mac_address(mac):
    """Detect locally administered addresses used by Private Wi-Fi/Randomized MAC."""
    text = str(mac or "").strip().replace(":", "").replace("-", "")
    try:
        return len(text) >= 2 and bool(int(text[:2], 16) & 0x02)
    except ValueError:
        return False


def auto_lock_known_vendors():
    """Lock collector-discovered vendors so later collector passes do not erase good metadata."""
    ensure_device_overrides_table()
    rows = query(
        """
        SELECT d.ip, d.name, d.vendor, d.device_type, d.status
        FROM devices d
        LEFT JOIN device_overrides o ON o.ip=d.ip
        LEFT JOIN device_override_unlocks u ON u.ip=d.ip
        WHERE o.ip IS NULL AND u.ip IS NULL
        """
    )
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for r in rows:
        vendor = r["vendor"] or ""
        if not has_real_vendor(vendor):
            continue
        name = r["name"] or r["ip"]
        dtype = r["device_type"] or classify_device("", vendor, "")
        status = r["status"] or "Active"
        run_sql(
            """
            INSERT OR IGNORE INTO device_overrides
                (ip, name, vendor, device_type, status, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (r["ip"], name, vendor, dtype, status, now),
        )


def cache_get(key, max_age):
    data = load_json(CACHE_PATH, {})
    item = data.get(key)

    if not item:
        return None

    if time.time() - item.get("ts", 0) > max_age:
        return None

    return item.get("value")


def cache_set(key, value):
    data = load_json(CACHE_PATH, {})
    data[key] = {"ts": time.time(), "value": value}
    save_json(CACHE_PATH, data)


def public_ip():
    c = cfg()
    cached = cache_get("public_ip", int(c.get("public_ip_cache_seconds", 1800)))

    if cached:
        return cached

    try:
        r = requests.get("https://api.ipify.org", timeout=5)
        if r.status_code == 200 and r.text.strip():
            ip = r.text.strip()
            cache_set("public_ip", ip)
            return ip
    except Exception:
        pass

    return "Unknown"




def fmt_mb(value):
    """Format megabytes as MB below 1000, otherwise GB."""
    try:
        mb = float(value or 0)
    except Exception:
        mb = 0.0

    if abs(mb) >= 1000:
        return f"{mb / 1024:.2f} GB"

    return f"{mb:.2f} MB"


def fmt_bps(value):
    """Format bits-per-second values cleanly for live speed displays."""
    try:
        bps = float(value or 0)
    except Exception:
        bps = 0.0

    if abs(bps) >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"

    if abs(bps) >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Mbps"

    if abs(bps) >= 1_000:
        return f"{bps / 1_000:.1f} Kbps"

    return "0.0 Kbps" if bps == 0 else f"{bps:.0f} bps"


def fmt_bytes_per_sec(value):
    """Format bytes-per-second as KB/s, MB/s or GB/s."""
    try:
        bps = float(value or 0)
    except Exception:
        bps = 0.0

    if abs(bps) >= 1024 ** 3:
        return f"{bps / (1024 ** 3):.2f} GB/s"

    if abs(bps) >= 1024 ** 2:
        return f"{bps / (1024 ** 2):.2f} MB/s"

    if abs(bps) >= 1024:
        return f"{bps / 1024:.2f} KB/s"

    return "0 B/s" if bps == 0 else f"{bps:.0f} B/s"


def fmt_bits_as_bytes(value):
    """Display collector throughput, stored as bits/sec, in byte-rate units."""
    try:
        bits = float(value or 0)
    except Exception:
        bits = 0.0

    return fmt_bytes_per_sec(bits / 8)


def live_sample_max_age():
    """Keep a collector sample live until the next configured write can arrive."""
    try:
        interval = max(1, int(cfg().get("collect_interval_seconds", 2) or 2))
    except Exception:
        interval = 2
    return max(20, interval * 2 + 5)


def live_packet_speed(ip):
    """Read live per-device speed from the lightweight packet collector.

    live_device_speed stores bytes/sec. The existing UI formatter expects bits/sec
    and converts to KB/s/MB/s, so we multiply by 8 here to keep all existing
    dashboard/device/traffic displays working safely.
    """
    key = str(ip or "").strip()
    if not key:
        return {}

    try:
        con = connect_db()
        con.row_factory = sqlite3.Row
        row = con.execute(
            """
            SELECT rx_bps, tx_bps, total_bps, updated_at
            FROM live_device_speed
            WHERE ip=?
            """,
            (key,),
        ).fetchone()
        con.close()
    except Exception:
        return {}

    if not row:
        return {}

    # Ignore samples only after enough time for the configured next flush.
    try:
        updated = datetime.strptime(str(row["updated_at"])[:19], "%Y-%m-%d %H:%M:%S")
        if (datetime.now() - updated).total_seconds() > live_sample_max_age():
            return {}
    except Exception:
        pass

    return {
        "rx_bps": float(row["rx_bps"] or 0) * 8,
        "tx_bps": float(row["tx_bps"] or 0) * 8,
        "total_bps": float(row["total_bps"] or 0) * 8,
        "source": "packet",
    }


def live_host_speed(ip_or_name):
    """Live speed comes ONLY from the NetSpecter packet collector.

    Source table: live_device_speed
    Stored values are bytes/sec; live_packet_speed converts to bits/sec
    so the existing formatter can display KB/s, MB/s and GB/s correctly.
    No external traffic-analyser fallback is used for speed values.
    """
    key = str(ip_or_name or "").strip()
    packet = live_packet_speed(key)
    if packet:
        return packet

    return {"rx_bps": 0.0, "tx_bps": 0.0, "total_bps": 0.0, "source": "collector"}


def live_network_speed():
    """Sum current live throughput from the packet collector table only."""
    try:
        freshness = f"-{live_sample_max_age()} seconds"
        rows = query(
            """
            SELECT
                SUM(rx_bps) AS rx,
                SUM(tx_bps) AS tx,
                SUM(total_bps) AS total
            FROM live_device_speed
            WHERE updated_at >= datetime('now', 'localtime', ?)
            """,
            (freshness,),
        )
    except Exception:
        rows = []

    if not rows:
        return {"rx_bps": 0.0, "tx_bps": 0.0, "total_bps": 0.0, "source": "collector"}

    r = rows[0]
    # Table stores bytes/sec; convert to bits/sec for the display formatter.
    return {
        "rx_bps": float(r["rx"] or 0) * 8,
        "tx_bps": float(r["tx"] or 0) * 8,
        "total_bps": float(r["total"] or 0) * 8,
        "source": "collector",
    }


def collector_service_action(action):
    try:
        result = subprocess.run(
            ["systemctl", action, "netspecter-collector"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Collector {action} failed: {e}")
        return False


def restart_collector_service():
    return collector_service_action("restart")

def latest_hosts(limit=100):
    ensure_device_overrides_table()
    ignore = ignored_ips()
    ignore_clause = ""
    params = [today()]
    if ignore:
        placeholders = ",".join(["?"] * len(ignore))
        ignore_clause = f"AND t.ip NOT IN ({placeholders})"
        params.extend(ignore)
    params.append(limit)

    return query(
        f"""
        WITH usage AS (
            SELECT
                ip,
                MAX(id) AS max_id,
                SUM(downloaded_mb) AS downloaded_mb,
                SUM(uploaded_mb) AS uploaded_mb,
                SUM(total_mb) AS total_mb
            FROM traffic_intervals
            WHERE day = ?
            GROUP BY ip
        )
        SELECT
            COALESCE(o.name, d.name, t.name, t.ip) AS name,
            COALESCE(o.vendor, d.vendor, 'Unknown Vendor') AS vendor,
            COALESCE(o.device_type, d.device_type, 'Unknown') AS device_type,
            COALESCE(o.status, d.status, 'Active') AS status,
            d.first_seen,
            d.last_seen,
            d.owner,
            d.location,
            CASE WHEN o.ip IS NOT NULL THEN 1 ELSE 0 END AS manual_locked,
            t.id,
            t.ip,
            t.mac,
            u.downloaded_mb,
            u.uploaded_mb,
            u.total_mb,
            t.live_bps,
            t.day,
            t.ts
        FROM usage u
        JOIN traffic_intervals t
            ON t.id = u.max_id
        LEFT JOIN devices d
            ON d.ip = t.ip
        LEFT JOIN device_overrides o
            ON o.ip = t.ip
        WHERE 1=1 {ignore_clause}
        ORDER BY u.total_mb DESC
        LIMIT ?
        """,
        tuple(params),
    )


def classify_device(name="", vendor="", mac=""):
    text = f"{name or ''} {vendor or ''} {mac or ''}".lower()

    if any(x in text for x in ["ubiquiti", "unifi"]):
        return "Network Device"

    if any(x in text for x in ["hp", "epson", "canon", "brother", "printer"]):
        return "Printer"

    if any(x in text for x in ["hikvision", "dahua", "ezviz", "camera"]):
        return "Camera"

    if any(x in text for x in ["iphone", "ipad", "apple"]):
        return "Apple Device"

    if any(x in text for x in ["samsung", "galaxy", "xiaomi", "huawei", "oppo"]):
        return "Mobile Device"

    if any(x in text for x in ["intel", "asustek", "gigabyte", "dell", "lenovo", "hp inc"]):
        return "Computer"

    if any(x in text for x in ["debian", "ubuntu", "proxmox", "server"]):
        return "Server"

    if any(x in text for x in ["google", "chromecast", "roku", "tv", "media"]):
        return "Media Device"

    return "Unknown"


def totals():
    start_day = range_start_day()
    ignore = ignored_ips()
    ignore_clause = ""
    params = [start_day]
    if ignore:
        placeholders = ",".join(["?"] * len(ignore))
        ignore_clause = f"AND t.ip NOT IN ({placeholders})"
        params.extend(ignore)
    rows = query(
        f"""
        WITH usage AS (
            SELECT
                ip,
                MAX(name) AS name,
                MAX(mac) AS mac,
                SUM(downloaded_mb) AS downloaded_mb,
                SUM(uploaded_mb) AS uploaded_mb,
                SUM(total_mb) AS total_mb
            FROM traffic_intervals
            WHERE day >= ?
            GROUP BY ip
        )
        SELECT
            COALESCE(o.name, d.name, u.name, u.ip) AS name,
            u.ip,
            u.mac,
            u.downloaded_mb,
            u.uploaded_mb,
            u.total_mb
        FROM usage u
        LEFT JOIN devices d ON d.ip=u.ip
        LEFT JOIN device_overrides o ON o.ip=u.ip
        WHERE 1=1 {ignore_clause.replace("t.ip", "u.ip")}
        ORDER BY u.total_mb DESC
        LIMIT 500
        """,
        tuple(params),
    )

    down = round(sum(float(r["downloaded_mb"] or 0) for r in rows), 2)
    up = round(sum(float(r["uploaded_mb"] or 0) for r in rows), 2)
    total = round(sum(float(r["total_mb"] or 0) for r in rows), 2)

    blocked = query(
        """
        SELECT COUNT(*) AS total
        FROM dns_querylog
        WHERE day>=? AND blocked=1
        """,
        (start_day,),
    )

    blocked_total = int(blocked[0]["total"] or 0) if blocked else 0

    topcat = query(
        """
        SELECT category, COUNT(*) AS q
        FROM dns_querylog
        WHERE day>=?
        GROUP BY category
        ORDER BY q DESC
        LIMIT 1
        """,
        (start_day,),
    )

    top_category = topcat[0]["category"] if topcat else "None"

    return down, up, total, len(rows), blocked_total, top_category

def system_health():
    db_size = round(DB_PATH.stat().st_size / 1024 / 1024, 2) if DB_PATH.exists() else 0

    if psutil:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        uptime_seconds = int(time.time() - psutil.boot_time())
    else:
        cpu = mem = disk = 0
        uptime_seconds = 0

    uptime = f"{uptime_seconds // 86400}d {(uptime_seconds % 86400) // 3600}h"

    last = query("SELECT updated_at AS ts FROM collector_heartbeat WHERE id=1")
    last_seen = last[0]["ts"] if last and last[0]["ts"] else "No data"

    if last_seen == "No data":
        last = query("SELECT MAX(updated_at) AS ts FROM live_device_speed")
        last_seen = last[0]["ts"] if last and last[0]["ts"] else "No data"

    collector_state = "Unknown"
    if last_seen != "No data":
        try:
            dt = datetime.strptime(last_seen[:19], "%Y-%m-%d %H:%M:%S")
            age = (datetime.now() - dt).total_seconds()
            collector_state = "OK" if age < 120 else "Stale"
        except Exception:
            collector_state = "Unknown"

    return {
        "cpu": cpu,
        "mem": mem,
        "disk": disk,
        "db_size": db_size,
        "uptime": uptime,
        "last_seen": last_seen,
        "collector_state": collector_state,
    }


def icon_for_app(category):
    return APP_ICONS.get(category or "Other", APP_ICONS["Other"])


def icon_for_device(dtype):
    """Return a Font Awesome icon for a device type.

    This accepts both old labels and newer labels used by the collector/UI.
    It is display-only and does not change the saved device type.
    """
    key = str(dtype or "Unknown").strip()

    aliases = {
        "Computer": "PC",
        "PC": "PC",
        "Laptop": "PC",
        "Mobile Device": "Phone",
        "Phone": "Phone",
        "Apple Device": "Phone",
        "Media Device": "TV",
        "TV": "TV",
        "Camera": "Camera",
        "Server": "Server",
        "Network Device": "Gateway",
        "Gateway": "Gateway",
        "Printer": "Printer",
        "IoT": "IoT",
        "Unknown": "Unknown",
    }

    mapped = aliases.get(key, key)
    return DEVICE_ICONS.get(mapped, DEVICE_ICONS["Unknown"])


def parse_local_dt(value):
    """Parse a NetSpecter timestamp safely. Returns None if invalid."""
    try:
        if not value:
            return None
        return datetime.strptime(str(value)[:19], "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def device_age_seconds(value):
    """Return age in seconds from a timestamp to now. Returns None if unknown."""
    dt = parse_local_dt(value)
    if not dt:
        return None
    return (datetime.now() - dt).total_seconds()


def device_lifecycle_badges(first_seen, last_seen):
    """Build New/Offline/Online badges for the Devices page.

    New: first seen within the last 24 hours.
    Offline: not seen for more than 5 minutes.
    Online: seen within the last 5 minutes.
    """
    badges = []

    first_age = device_age_seconds(first_seen)
    last_age = device_age_seconds(last_seen)

    if first_age is not None and first_age <= 86400:
        badges.append('<span class="badge-new">New</span>')

    if last_age is None:
        badges.append('<span class="badge-unknown">Unknown</span>')
    elif last_age > 300:
        badges.append('<span class="badge-offline">Offline</span>')
    else:
        badges.append('<span class="badge-online">Online</span>')

    return " ".join(badges)


def is_noise(domain):
    d = (domain or "").lower()
    return any(x in d for x in NOISE_DOMAINS)


def top_categories(limit=8):
    return query(
        """
        SELECT category, COUNT(*) AS total
        FROM dns_querylog
        WHERE day>=?
        GROUP BY category
        ORDER BY total DESC
        LIMIT ?
        """,
        (range_start_day(), limit),
    )


def estimated_app_usage(limit=10):
    """Return DNS-attributed measured bytes, kept separate from total device usage."""
    return query(
        """
        SELECT
            e.category,
            e.ip,
            COALESCE(NULLIF(o.name, ''), NULLIF(d.name, ''), e.ip) AS name,
            SUM(e.downloaded_mb) AS downloaded_mb,
            SUM(e.uploaded_mb) AS uploaded_mb,
            SUM(e.total_mb) AS total_mb
        FROM estimated_app_traffic e
        LEFT JOIN devices d ON d.ip=e.ip
        LEFT JOIN device_overrides o ON o.ip=e.ip
        WHERE e.day>=?
        GROUP BY e.category, e.ip, name
        ORDER BY total_mb DESC
        LIMIT ?
        """,
        (range_start_day(), limit),
    )


def ag_auth():
    c = cfg()
    return (c.get("adguard_user"), c.get("adguard_pass"))


def ag_control(endpoint):
    return cfg().get("adguard_url", "").rstrip("/") + "/control" + endpoint


def ag_get(endpoint, params=None):
    try:
        r = requests.get(ag_control(endpoint), auth=ag_auth(), params=params, timeout=8)
        if r.status_code == 200:
            try:
                return True, r.json()
            except Exception:
                return True, {"ok": True}
        return False, {"error": f"HTTP {r.status_code}", "body": r.text[:300]}
    except Exception as e:
        return False, {"error": str(e)}


def ag_post(endpoint, payload=None):
    try:
        if payload is None:
            r = requests.post(ag_control(endpoint), auth=ag_auth(), timeout=8)
        else:
            r = requests.post(ag_control(endpoint), auth=ag_auth(), json=payload, timeout=8)

        if r.status_code == 200:
            try:
                return True, r.json()
            except Exception:
                return True, {"ok": True}

        return False, {"error": f"HTTP {r.status_code}", "body": r.text[:300]}
    except Exception as e:
        return False, {"error": str(e)}


def shell(title, body, active="Dashboard"):
    """
    Main HTML wrapper used by all NetSpecter pages.

    What this section does:
    - Builds the left sidebar navigation.
    - Loads the global CSS, favicon, Font Awesome icons and Chart.js.
    - Wraps each page's own HTML inside the standard layout.
    - Adds shared JavaScript used by multiple pages.

    Shared JavaScript included here:
    - Device table search/filter.
    - Device inline edit/save/cancel.
    - Live speed polling from /api/live every 2 seconds.
    - Live update support for Dashboard, Devices and individual Device View pages.

    Live update HTML requirements:
    - Per-device values must use:
        data-live-ip="DEVICE_IP"
        data-live-field="total|down|up"

    - Network-wide values must use:
        data-live-network="1"
        data-live-field="total|down|up"
    """

    c = cfg()

    # ---------------------------------------------------
    # Sidebar navigation items
    # ---------------------------------------------------
    # Each tuple is:
    #   Display name, URL, Font Awesome icon
    # ---------------------------------------------------

    nav_items = [
        ("Dashboard", "/", "fa-chart-line"),
        ("Devices", "/devices", "fa-desktop"),
        ("Traffic", "/traffic", "fa-arrow-trend-up"),
        ("History", "/history", "fa-clock-rotate-left"),
        ("Applications", "/applications", "fa-layer-group"),
        ("Blocked", "/blocked", "fa-ban"),
        ("Services", "/blocked-services", "fa-filter-circle-xmark"),
        ("Map", "/map", "fa-diagram-project"),
        ("Exports", "/exports", "fa-file-export"),
        ("AdGuard", "/adguard", "fa-shield-halved"),
        ("Speed Tests", "/speed-tests", "fa-gauge-high"),
        ("Integrations", "/integrations", "fa-plug"),
        ("Health", "/health", "fa-heart-pulse"),
        ("Settings", "/settings", "fa-gear"),
        ("System", "/system", "fa-server"),
        ("Logout", "/logout", "fa-right-from-bracket"),
    ]

    nav = ""

    for label, url, icon in nav_items:
        cls = "active" if label == active else ""
        nav += f'<a class="{cls}" href="{url}"><i class="fa-solid {icon}"></i>{label}</a>'

    # ---------------------------------------------------
    # Standard page shell
    # ---------------------------------------------------
    # The body parameter is the page-specific HTML.
    # ---------------------------------------------------

    return f"""<!DOCTYPE html>
<html>
<head>
<title>{title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/static/favicon.png">
<link rel="stylesheet" href="/static/theme.css?v=20260526m">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>

<!-- ===================================================
     SIDEBAR
     ===================================================
     Left navigation shown on every page.
     =================================================== -->

<div class="sidebar">
  <div class="designer-credit">Designed by Gavin Reniers</div>
  <img src="/static/netspecter-logo-sidebar.png" class="brand-logo">
  <div class="nav">{nav}</div>
</div>

<!-- ===================================================
     CONTENT
     ===================================================
     Page-specific content is injected here.
     =================================================== -->

<div class="content">
{body}
</div>

<!-- ===================================================
     GLOBAL JAVASCRIPT
     ===================================================
     Shared browser-side logic for all NetSpecter pages.
     =================================================== -->

<script>

// ---------------------------------------------------
// Device table live search
// ---------------------------------------------------
// Used on /devices. Filters visible rows as you type.
// ---------------------------------------------------
function filterDevices() {{
  const input = document.getElementById("deviceSearch");
  const table = document.getElementById("deviceTable");

  if (!input || !table) return;

  const filter = input.value.toLowerCase().trim();
  const rows = table.getElementsByTagName("tr");

  for (let i = 1; i < rows.length; i++) {{
    const row = rows[i];
    let text = row.innerText.toLowerCase();

    row.querySelectorAll("input, select").forEach(el => {{
      text += " " + (el.value || "").toLowerCase();
    }});

    row.style.display = text.includes(filter) ? "" : "none";
  }}
}}

// ---------------------------------------------------
// Enable inline device editing
// ---------------------------------------------------
// Converts display fields into editable inputs/selects.
// ---------------------------------------------------
function editDeviceRow(button) {{
  const row = button.closest("tr");
  if (!row) return;

  row.querySelectorAll(".view-val").forEach(el => el.style.display = "none");
  row.querySelectorAll(".edit-field").forEach(el => el.style.display = "inline-block");

  const save = row.querySelector(".save-btn");
  const cancel = row.querySelector(".cancel-btn");
  const view = row.querySelector(".view-btn");

  if (save) save.style.display = "inline-block";
  if (cancel) cancel.style.display = "inline-block";
  if (view) view.style.display = "none";

  button.style.display = "none";
}}

// ---------------------------------------------------
// Cancel inline editing
// ---------------------------------------------------
// Reloads the page to discard unsaved edits.
// ---------------------------------------------------
function cancelDeviceEdit(button) {{
  window.location.reload();
}}

// ---------------------------------------------------
// Save inline device editing
// ---------------------------------------------------
// Builds a hidden POST form and submits to /devices.
// ---------------------------------------------------
function saveDeviceRow(button) {{
  const row = button.closest("tr");
  if (!row) return;

  const form = document.createElement("form");
  form.method = "POST";
  form.action = "/devices";

  const addField = (name, value) => {{
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = value || "";
    form.appendChild(input);
  }};

  addField("ip", row.dataset.ip);

  row.querySelectorAll(".edit-field").forEach(el => {{
    addField(el.dataset.field, el.value);
  }});

  addField("_csrf_token", "{h(csrf_token())}");

  document.body.appendChild(form);
  form.submit();
}}

// ---------------------------------------------------
// Live speed refresh engine
// ---------------------------------------------------
// Polls /api/live every 2 seconds and updates matching
// elements without refreshing the page.
//
// Per-device fields:
//   data-live-ip="LAN device IP"
//   data-live-field="total|down|up"
//
// Network fields:
//   data-live-network="1"
//   data-live-field="total|down|up"
// ---------------------------------------------------
async function refreshLiveSpeeds() {{
  try {{
    const res = await fetch('/api/live?t=' + Date.now(), {{cache: 'no-store'}});
    if (!res.ok) return;

    const data = await res.json();

    // Update per-device live values.
    document.querySelectorAll('[data-live-ip][data-live-field]').forEach(el => {{
      const ip = el.dataset.liveIp;
      const field = el.dataset.liveField;

      if (data[ip] && data[ip][field] !== undefined) {{
        el.textContent = data[ip][field];
      }}
    }});

    // Update network-wide live values.
    document.querySelectorAll('[data-live-network][data-live-field]').forEach(el => {{
      const field = el.dataset.liveField;

      if (data['__network__'] && data['__network__'][field] !== undefined) {{
        el.textContent = data['__network__'][field];
      }}
    }});
  }} catch (e) {{
    console.log('Live speed refresh failed:', e);
  }}
}}

// Start live polling globally on every page.
setInterval(refreshLiveSpeeds, 2000);
refreshLiveSpeeds();

</script>
</body>
</html>"""


def topbar(title="Dashboard"):
    c = cfg()
    adguard_url = str(c.get("adguard_url", "") or "#")

    return f"""
<div class="topbar">
  <div>
    <h1>{title}</h1>
    <div class="sub">Network visibility + privacy protection</div>
  </div>
  <div class="badges">
    <span>Observed IPv4 traffic</span>
    <span>Public IP: {public_ip()}</span>
    <a href="{h(adguard_url)}" target="_blank"><span>AdGuard</span></a>
    <a href="{h(adguard_url)}/#blocked_services" target="_blank"><span>Blocked Services</span></a>
    <span>LAN: {c.get('lan_prefix')}0/24</span>
  </div>
</div>
"""



@app.route("/api/live")
def api_live():
    """Live speed API used by the web UI polling.

    Source: live_device_speed written by live_packet_collector.py.
    Values in DB are bytes/sec. UI receives already formatted strings.
    """
    freshness = f"-{live_sample_max_age()} seconds"
    rows = query(
        """
        SELECT ip, rx_bps, tx_bps, total_bps, updated_at
        FROM live_device_speed
        WHERE updated_at >= datetime('now', 'localtime', ?)
        """,
        (freshness,),
    )

    data = {}
    total_rx = 0.0
    total_tx = 0.0
    total_all = 0.0

    for r in rows:
        ip = str(r["ip"] or "")
        rx = float(r["rx_bps"] or 0)
        tx = float(r["tx_bps"] or 0)
        total = float(r["total_bps"] or 0)

        total_rx += rx
        total_tx += tx
        total_all += total

        data[ip] = {
            "down": fmt_bytes_per_sec(rx),
            "up": fmt_bytes_per_sec(tx),
            "total": fmt_bytes_per_sec(total),
            "updated": r["updated_at"] or "",
        }

    data["__network__"] = {
        "down": fmt_bytes_per_sec(total_rx),
        "up": fmt_bytes_per_sec(total_tx),
        "total": fmt_bytes_per_sec(total_all),
        "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    return data


@app.route("/api/dashboard-summary")
def api_dashboard_summary():
    """Refresh accumulated dashboard counters from measured history."""
    down, up, total, active, blocked, _top = totals()
    start_day = range_start_day()
    dns_rows = query(
        "SELECT COUNT(*) AS total, COUNT(DISTINCT domain) AS domains FROM dns_querylog WHERE day>=?",
        (start_day,),
    )
    blocked_rows = query(
        "SELECT COUNT(DISTINCT domain) AS domains FROM dns_querylog WHERE day>=? AND blocked=1",
        (start_day,),
    )
    dns_total = int(dns_rows[0]["total"] or 0) if dns_rows else 0
    unique_domains = int(dns_rows[0]["domains"] or 0) if dns_rows else 0
    blocked_domains = int(blocked_rows[0]["domains"] or 0) if blocked_rows else 0
    blocked_pct = round((blocked / dns_total * 100), 1) if dns_total else 0

    return {
        "traffic_total": fmt_mb(total),
        "traffic_down": fmt_mb(down),
        "traffic_up": fmt_mb(up),
        "active_devices": active,
        "blocked": blocked,
        "blocked_domains": blocked_domains,
        "blocked_pct": blocked_pct,
        "dns_total": dns_total,
        "unique_domains": unique_domains,
    }


@app.route("/")
def dashboard():
    c = cfg()
    down, up, total, active, blocked, top = totals()
    health = system_health()

    hosts = latest_hosts(20)
    top_device = hosts[0] if hosts else None
    top_device_name = top_device["name"] if top_device else "None"
    top_device_total = fmt_mb(top_device["total_mb"]) if top_device else "0.00 MB"
    live_net = live_network_speed()
    live_down_bps = live_net.get("rx_bps", 0)
    live_up_bps = live_net.get("tx_bps", 0)
    live_total_bps = live_net.get("total_bps", 0)

    start_day = range_start_day()
    dns_today = query("SELECT COUNT(*) AS total, COUNT(DISTINCT domain) AS domains FROM dns_querylog WHERE day>=?", (start_day,))
    dns_total = int(dns_today[0]["total"] or 0) if dns_today else 0
    unique_domains = int(dns_today[0]["domains"] or 0) if dns_today else 0
    blocked_pct = round((blocked / dns_total * 100), 1) if dns_total else 0
    traffic_range_label = {"1d": "Today", "7d": "Last 7 Days", "30d": "Last 30 Days"}.get(range_key(), "Today")
    dashboard_period = {"1d": "24h", "7d": "7d", "30d": "30d"}.get(range_key(), "24h")
    adguard_ok, adguard_status = ag_get("/status")
    protection_enabled = adguard_status.get("protection_enabled") if adguard_ok and isinstance(adguard_status, dict) else None
    protection_text = "ON" if protection_enabled is True else "OFF" if protection_enabled is False else "UNKNOWN"
    protection_class = "green" if protection_enabled is True else "red" if protection_enabled is False else "yellow"
    protection_detail = "AdGuard filtering" if protection_enabled is not None else "AdGuard unavailable"

    blocked_today = query(
        """
        SELECT COUNT(*) AS total, COUNT(DISTINCT domain) AS domains
        FROM dns_querylog
        WHERE day>=? AND blocked=1
        """,
        (start_day,),
    )
    blocked_domains = int(blocked_today[0]["domains"] or 0) if blocked_today else 0

    cats = top_categories(6)
    cat_total = sum(int(x["total"] or 0) for x in cats) or 1
    max_count = max([int(x["total"] or 1) for x in cats], default=1)
    app_rows = ""

    for r in cats:
        count = int(r["total"] or 0)
        width = max(4, min(count / max_count * 100, 100))
        pct = round(count / cat_total * 100, 1)
        app_rows += f"""
<div class="dash-app-row">
  <div class="dash-app-name">{icon_for_app(r['category'])}<span>{h(r['category'])}</span></div>
  <div class="dash-app-bar"><span style="width:{width}%"></span></div>
  <b>{count}</b>
  <em>{pct}%</em>
</div>
"""

    health_cards = f"""
<div class="dash-card slim"><i class="fa-solid fa-wave-square"></i><div><span>CPU</span><b class="blue">{health['cpu']}%</b></div></div>
<div class="dash-card slim"><i class="fa-solid fa-microchip purple"></i><div><span>Memory</span><b class="purple">{health['mem']}%</b></div></div>
<div class="dash-card slim"><i class="fa-solid fa-hard-drive"></i><div><span>Disk / HDD</span><b class="{'red' if health['disk'] > 85 else 'green'}">{health['disk']}%</b></div></div>
<div class="dash-card slim"><i class="fa-solid fa-database"></i><div><span>Database</span><b class="teal">{health['db_size']} MB</b></div></div>
<div class="dash-card slim"><i class="fa-solid fa-plug-circle-check"></i><div><span>Collector</span><b class="{'green' if health['collector_state'] == 'OK' else 'yellow'}">{health['collector_state']}</b></div></div>
<div class="dash-card slim"><i class="fa-regular fa-clock"></i><div><span>Uptime</span><b>{health['uptime']}</b></div></div>
"""

    body = f"""
{topbar("Dashboard")}
<style>
.dash-wrap {{ display:flex; flex-direction:column; gap:18px; }}
.dash-grid {{ display:grid; grid-template-columns:repeat(6, minmax(130px, 1fr)); gap:12px; }}
.dash-grid.big {{ grid-template-columns:repeat(6, minmax(150px, 1fr)); }}
.dash-card {{
  background:#142136;
  border:1px solid rgba(148,163,184,.16);
  border-radius:12px;
  padding:16px 18px;
  box-shadow:0 16px 42px rgba(0,0,0,.28);
  color:#f4f7fb;
  text-decoration:none;
}}
.dash-card:hover {{ border-color:rgba(147,197,253,.55); transform:none; }}
.dash-card .label {{ color:#9aa7bb; font-size:13px; margin-bottom:9px; font-weight:800; }}
.dash-card .big {{ display:block; font-size:26px; font-weight:900; line-height:1.1; }}
.dash-card small {{ display:block; margin-top:7px; color:#9aa7bb; font-weight:700; }}
.dash-card.slim {{ display:flex; align-items:center; gap:14px; min-height:62px; padding:13px 15px; }}
.dash-card.slim i {{
  font-size:22px;
  color:#c0c8d7;
  width:38px;
  height:38px;
  border-radius:50%;
  display:grid;
  place-items:center;
  background:#1c2a41;
}}
.dash-card.slim span {{ display:block; color:#9aa7bb; font-size:12px; font-weight:800; }}
.dash-card.slim b {{ font-size:18px; }}
.dash-summary {{
  display:grid;
  grid-template-columns: 120px repeat(4, 1fr) 116px;
  align-items:center;
  gap:18px;
  background:#071126;
  border:1px solid rgba(148,163,184,.2);
  border-radius:12px;
  padding:10px 12px;
}}
.dash-ring {{
  width:96px;
  height:96px;
  border-radius:50%;
  position:relative;
}}
.dash-ring::after {{
  content:"";
  position:absolute;
  inset:24px;
  border-radius:50%;
  background:#071126;
}}
.dash-summary .dash-card {{
  box-shadow:none;
  border:0;
  border-radius:0;
  background:transparent;
  padding:10px 4px;
}}
.dash-total-card {{
  background:#142136 !important;
  border-radius:9px !important;
  padding:14px !important;
  text-align:right;
}}
.dash-two {{ display:grid; grid-template-columns:1.35fr .9fr; gap:16px; }}
.dash-panel {{ background:#142136; border:1px solid rgba(148,163,184,.16); border-radius:12px; padding:20px; box-shadow:0 16px 42px rgba(0,0,0,.28); }}
.dash-panel h2 {{ margin:0 0 18px; font-size:20px; }}
.dash-panel h2 small {{ display:block; color:#9aa7bb; font-size:12px; margin-top:6px; font-weight:700; }}
.dash-actions {{ display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }}
.speed-test-form {{ display:flex; align-items:center; gap:10px; }}
.speed-test-form button {{ border:1px solid rgba(91,168,255,.42); background:rgba(91,168,255,.16); color:#e9f3ff; border-radius:10px; padding:9px 14px; cursor:pointer; font-weight:800; }}
.speed-test-form small {{ color:#9aa7bb; font-weight:700; }}
.dash-app-row {{ display:grid; grid-template-columns:150px 1fr 54px 54px; align-items:center; gap:12px; margin:12px 0; padding:8px 10px; border-radius:8px; background:#0d172a; }}
.dash-app-name {{ display:flex; align-items:center; gap:12px; }}
.dash-app-name i {{ font-size:23px; width:26px; text-align:center; }}
.dash-app-bar {{ height:8px; background:#2a374b; border-radius:999px; overflow:hidden; }}
.dash-app-bar span {{ display:block; height:100%; background:linear-gradient(90deg, #00ddc7, #5ba8ff); border-radius:999px; }}
.dash-app-row em {{ color:#b7c7d8; font-style:normal; }}
.dash-chart {{ height:168px; }}
.dash-chart canvas {{ max-height:168px; }}
.legend {{ display:flex; align-items:center; gap:18px; color:#cbd6e3; margin-bottom:8px; flex-wrap:wrap; }}
.legend .legend-live {{ margin-left:auto; font-size:16px; }}
.chart-legend {{ display:flex; align-items:center; gap:14px; margin-top:8px; color:#b8c7da; font-size:13px; font-weight:800; }}
.chart-legend span {{ display:flex; align-items:center; gap:7px; }}
.chart-legend b {{ display:inline-block; width:26px; height:4px; border-radius:999px; }}
.chart-legend .download {{ background:#18aaff; }}
.chart-legend .upload {{ background:#9c6cff; }}
.blue {{ color:#5ba8ff !important; }} .purple {{ color:#a68bff !important; }} .teal {{ color:#00ddc7 !important; }} .green {{ color:#20df9f !important; }} .red {{ color:#ff526c !important; }} .yellow {{ color:#f8c84e !important; }}
@media (max-width:1200px) {{ .dash-grid, .dash-grid.big, .dash-summary, .dash-two {{ grid-template-columns:1fr 1fr; }} .dash-ring {{ display:none; }} }}
@media (max-width:700px) {{
  .dash-grid, .dash-grid.big, .dash-summary, .dash-two {{ grid-template-columns:1fr; }}
  .dash-actions {{ align-items:stretch; }}
  .speed-test-form {{ flex-direction:column; align-items:stretch; }}
  .dash-panel {{ padding:14px; }}
  .dash-total-card {{ text-align:left; }}
  .legend .legend-live {{ margin-left:0; font-size:13px; }}
  .dash-app-row {{ grid-template-columns:minmax(0, 1fr) auto; gap:9px; }}
  .dash-app-name, .dash-app-bar {{ grid-column:1 / -1; }}
}}
</style>

<div class="dash-wrap">
  <div class="dash-actions">
    {time_picker()}
    <form method="post" action="/speed-test" class="speed-test-form">
      {csrf_input()}
      <small>Uses internet data once</small>
      <button type="submit"><i class="fa-solid fa-gauge-high"></i> Run Speed Test</button>
    </form>
  </div>
  <div class="dash-summary">
    <div id="dashboardBlockRing" class="dash-ring" title="DNS blocked share: {blocked_pct}%" style="background:conic-gradient(#ff526c 0 {blocked_pct}%, #00ddc7 {blocked_pct}% 100%);"></div>
    <a class="dash-card" href="/blocked"><div class="label">Total Blocked</div><span id="dashboardBlocked" class="big red">{blocked:,}</span><small>Blocked domains: <span id="dashboardBlockedDomains">{blocked_domains:,}</span></small></a>
    <a class="dash-card" href="/adguard"><div class="label">Protection</div><span class="big {protection_class}">{protection_text}</span><small>{protection_detail}</small></a>
    <a class="dash-card" href="/devices"><div class="label">Traffic Devices</div><span id="dashboardTrafficDevices" class="big blue">{active}</span><small>Seen in selected range</small></a>
    <a class="dash-card" href="/traffic"><div class="label">Traffic {traffic_range_label}</div><span id="dashboardTrafficTotal" class="big teal">{fmt_mb(total)}</span><small>Down <span id="dashboardTrafficDown">{fmt_mb(down)}</span> | Up <span id="dashboardTrafficUp">{fmt_mb(up)}</span></small></a>
    <a class="dash-card dash-total-card" href="/applications"><div class="label">Total Queries</div><span id="dashboardDnsTotal" class="big">{dns_total:,}</span><small><span id="dashboardUniqueDomains">{unique_domains:,}</span> domains</small></a>
  </div>

  <div class="dash-two">
    <div class="dash-panel">
      <h2>Network Traffic</h2>
      <div class="legend">
        <span><i class="fa-solid fa-circle blue"></i> Download / Downstream</span>
        <span><i class="fa-solid fa-circle purple"></i> Upload / Upstream</span>
        <b class="blue legend-live">Live collector: DL <span data-live-network="1" data-live-field="down">{fmt_bits_as_bytes(live_down_bps)}</span> | UL <span data-live-network="1" data-live-field="up">{fmt_bits_as_bytes(live_up_bps)}</span> | Total <span data-live-network="1" data-live-field="total">{fmt_bits_as_bytes(live_total_bps)}</span></b>
      </div>
      <div class="dash-chart"><canvas id="dashboardTrafficChart"></canvas></div>
      <div class="chart-legend">
        <span><b class="download"></b> Download</span>
        <span><b class="upload"></b> Upload</span>
      </div>
    </div>

    <div class="dash-panel">
      <h2>Top Applications</h2>
      {app_rows or '<p>No application data yet</p>'}
    </div>
  </div>

  <div class="dash-grid">
    {health_cards}
  </div>

</div>
<script>
let dashboardTrafficChart = null;
async function loadDashboardSummary() {{
  try {{
    const response = await fetch("/api/dashboard-summary?range={range_key()}", {{cache: "no-store"}});
    if (!response.ok) return;
    const data = await response.json();
    const setText = (id, value) => {{
      const el = document.getElementById(id);
      if (el) el.textContent = value;
    }};
    setText("dashboardTrafficTotal", data.traffic_total);
    setText("dashboardTrafficDown", data.traffic_down);
    setText("dashboardTrafficUp", data.traffic_up);
    setText("dashboardTrafficDevices", Number(data.active_devices).toLocaleString());
    setText("dashboardBlocked", Number(data.blocked).toLocaleString());
    setText("dashboardBlockedDomains", Number(data.blocked_domains).toLocaleString());
    setText("dashboardDnsTotal", Number(data.dns_total).toLocaleString());
    setText("dashboardUniqueDomains", Number(data.unique_domains).toLocaleString());
    const ring = document.getElementById("dashboardBlockRing");
    if (ring) {{
      ring.title = "DNS blocked share: " + data.blocked_pct + "%";
      ring.style.background = "conic-gradient(#ff526c 0 " + data.blocked_pct + "%, #00ddc7 " + data.blocked_pct + "% 100%)";
    }}
  }} catch (error) {{
    console.log("Dashboard summary refresh failed:", error);
  }}
}}
async function loadDashboardTraffic() {{
  const response = await fetch("/api/history?period={dashboard_period}", {{cache: "no-store"}});
  const data = await response.json();
  const context = document.getElementById("dashboardTrafficChart").getContext("2d");
  if (dashboardTrafficChart) dashboardTrafficChart.destroy();
  dashboardTrafficChart = new Chart(context, {{
    type: "line",
    data: {{
      labels: data.labels,
      datasets: [
        {{ label: "Download", data: data.downloaded, borderColor: "#18aaff", backgroundColor: "rgba(24,170,255,.08)", borderWidth: 2.5, tension: .25, pointRadius: 0, fill: true }},
        {{ label: "Upload", data: data.uploaded, borderColor: "#9c6cff", backgroundColor: "rgba(156,108,255,.04)", borderWidth: 2.5, tension: .25, pointRadius: 0, fill: true }}
      ]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {{ legend: {{ display: false }} }},
      scales: {{
        y: {{ beginAtZero: true, title: {{ display: true, text: "MB" }} }},
        x: {{ ticks: {{ maxTicksLimit: 8 }} }}
      }}
    }}
  }});
}}
loadDashboardSummary();
loadDashboardTraffic();
setInterval(loadDashboardSummary, 5000);
setInterval(loadDashboardTraffic, 5000);
</script>
"""

    return shell("NetSpecter Dashboard", body, "Dashboard")


@app.route("/devices", methods=["GET", "POST"])
def devices():
    ensure_device_overrides_table()
    auto_lock_known_vendors()

    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        name = request.form.get("name", "").strip()
        vendor = request.form.get("vendor", "").strip() or "Unknown Vendor"
        device_type = request.form.get("device_type", "").strip() or "Unknown"
        status = request.form.get("status", "").strip() or "Active"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if ip:
            run_sql("DELETE FROM device_override_unlocks WHERE ip=?", (ip,))

            # Save manual override in a separate table so collector pulls cannot overwrite it.
            run_sql(
                """
                INSERT INTO device_overrides (ip, name, vendor, device_type, status, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    name=excluded.name,
                    vendor=excluded.vendor,
                    device_type=excluded.device_type,
                    status=excluded.status,
                    updated_at=excluded.updated_at
                """,
                (ip, name, vendor, device_type, status, now),
            )

            # Also write to devices for compatibility, but the override is the source of truth.
            run_sql(
                """
                UPDATE devices
                SET name=?,
                    vendor=?,
                    device_type=?,
                    status=?
                WHERE ip=?
                """,
                (name, vendor, device_type, status, ip),
            )

        return redirect("/devices")

    sort = request.args.get("sort", "last")
    direction = request.args.get("dir", "desc")
    sort_map = {
        "name": "COALESCE(o.name, d.name, d.ip) COLLATE NOCASE",
        "ip": "d.ip COLLATE NOCASE",
        "mac": "COALESCE(d.mac, '') COLLATE NOCASE",
        "vendor": "COALESCE(o.vendor, d.vendor, 'Unknown Vendor') COLLATE NOCASE",
        "type": "COALESCE(o.device_type, d.device_type, 'Unknown') COLLATE NOCASE",
        "status": "COALESCE(o.status, d.status, 'Active') COLLATE NOCASE",
        "last": "d.last_seen",
    }
    sort_col = sort_map.get(sort, "d.last_seen")
    direction_sql = "ASC" if direction == "asc" else "DESC"

    rows = query(f"""
        SELECT
            d.*,
            COALESCE(o.name, d.name) AS display_name,
            COALESCE(o.vendor, d.vendor, 'Unknown Vendor') AS display_vendor,
            COALESCE(o.device_type, d.device_type, 'Unknown') AS display_type,
            COALESCE(o.status, d.status, 'Active') AS display_status,
            CASE WHEN o.ip IS NOT NULL THEN 1 ELSE 0 END AS manual_locked,
            o.updated_at AS override_updated_at
        FROM devices d
        LEFT JOIN device_overrides o
            ON o.ip = d.ip
        ORDER BY
            CASE WHEN {sort_col} IS NULL OR {sort_col}='' THEN 1 ELSE 0 END,
            {sort_col} {direction_sql},
            d.ip
    """)

    def sort_link(label, key):
        next_dir = "desc"
        marker = ""
        if sort == key:
            next_dir = "asc" if direction == "desc" else "desc"
            marker = " v" if direction == "desc" else " ^"
        return f'<a class="sort-link" href="/devices?sort={h(key)}&dir={next_dir}">{h(label)}{marker}</a>'

    type_options = [
        "Unknown", "Computer", "Mobile Device", "Apple Device", "Server",
        "Network Device", "Printer", "Camera", "Media Device", "IoT", "Gateway"
    ]
    status_options = ["Active", "Known", "Watch", "DNS Blocked", "Blocked", "OK"]

    table = ""

    for r in rows:
        ip = h(r["ip"])
        name = h(r["display_name"] or r["ip"])
        mac = h(r["mac"])
        vendor = h(r["display_vendor"] or "Unknown Vendor")
        dtype = h(r["display_type"] or "Unknown")
        status = h(r["display_status"] or "Active")
        last_seen = h(r["last_seen"])
        device_icon = icon_for_device(r["display_type"] or "Unknown")
        lifecycle_badges = device_lifecycle_badges(r["first_seen"], r["last_seen"])
        lock_badge = (
            f'<form class="unlock-device-form" method="post" action="/device/unlock/{ip}" '
            f'onsubmit="return confirm(\'Unlock this device and clear its saved identity details?\');">'
            f'{csrf_input()}<button class="badge-lock unlock-badge" type="submit" '
            f'title="Unlock and clear saved identity details">Locked <i class="fa-solid fa-lock-open"></i></button></form>'
        ) if r["manual_locked"] else ''
        private_badge = '<span class="badge-private">Private MAC</span>' if private_mac_address(r["mac"]) else ''

        type_select = '<select class="edit-field" data-field="device_type" style="display:none; max-width:150px;">'
        for opt in type_options:
            selected = " selected" if opt == (r["display_type"] or "Unknown") else ""
            type_select += f'<option value="{h(opt)}"{selected}>{h(opt)}</option>'
        type_select += '</select>'

        status_select = '<select class="edit-field" data-field="status" style="display:none; max-width:120px;">'
        for opt in status_options:
            selected = " selected" if opt == (r["display_status"] or "Active") else ""
            status_select += f'<option value="{h(opt)}"{selected}>{h(opt)}</option>'
        status_select += '</select>'

        live_data = live_host_speed(str(r["ip"]))
        live_total = fmt_bits_as_bytes(live_data.get("total_bps", 0))
        live_rx = fmt_bits_as_bytes(live_data.get("rx_bps", 0))
        live_tx = fmt_bits_as_bytes(live_data.get("tx_bps", 0))

        table += f"""
<tr data-ip="{ip}">
  <td>
    <span class="view-val"><span class="device-type-icon">{device_icon}</span><b>{name}</b> {lock_badge} {private_badge} {lifecycle_badges}</span>
    <input class="edit-field" data-field="name" value="{name}" style="display:none; max-width:170px;">
  </td>
  <td class="mono">{ip}</td>
  <td class="mono">{mac}</td>
  <td>
    <span class="view-val">{vendor}</span>
    <input class="edit-field" data-field="vendor" value="{vendor}" style="display:none; max-width:190px;">
  </td>
  <td>
    <span class="view-val"><span class="device-type-icon">{device_icon}</span>{dtype}</span>
    {type_select}
  </td>
  <td>
    <span class="view-val">{status}</span>
    {status_select}
  </td>
  <td><b data-live-ip="{ip}" data-live-field="total">{live_total}</b><br><small>DL <span data-live-ip="{ip}" data-live-field="down">{live_rx}</span> | UL <span data-live-ip="{ip}" data-live-field="up">{live_tx}</span></small></td>
  <td>{last_seen}</td>
  <td class="actions" style="white-space:nowrap;">
    <button class="btn edit-btn" type="button" onclick="editDeviceRow(this)" style="padding:7px 12px; font-size:13px;">Edit</button>
    <button class="btn save-btn" type="button" onclick="saveDeviceRow(this)" style="display:none; padding:7px 12px; font-size:13px;">Save</button>
    <button class="btn cancel-btn" type="button" onclick="cancelDeviceEdit(this)" style="display:none; padding:7px 12px; font-size:13px;">Cancel</button>
    <a class="btn view-btn" href="/device/{ip}" style="padding:7px 12px; font-size:13px;">View</a>
  </td>
</tr>
"""

    body = f"""
{topbar("Devices")}
<style>
.badge-lock,
.badge-new,
.badge-online,
.badge-offline,
.badge-unknown {{
  display:inline-block;
  margin-left:8px;
  padding:2px 7px;
  border-radius:999px;
  font-size:11px;
  border:1px solid rgba(255,255,255,.12);
}}
.badge-lock {{ background:rgba(0, 220, 200, 0.16); color:#28e0d5; }}
.unlock-device-form {{ display:inline; margin:0; }}
.unlock-badge {{ font:inherit; cursor:pointer; }}
.unlock-badge:hover {{ background:rgba(0, 220, 200, 0.28); color:#eaffff; }}
.badge-private {{ display:inline-block; margin-left:8px; padding:2px 7px; border-radius:999px; font-size:11px; border:1px solid rgba(248,200,78,.28); background:rgba(248,200,78,.12); color:#f8c84e; }}
.badge-new {{ background:rgba(0, 170, 255, 0.16); color:#58c7ff; }}
.badge-online {{ background:rgba(54, 239, 126, 0.14); color:#36ef7e; }}
.badge-offline {{ background:rgba(255, 56, 96, 0.14); color:#ff6b85; }}
.badge-unknown {{ background:rgba(255, 209, 102, 0.14); color:#ffd166; }}
.device-type-icon {{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  width:26px;
  height:26px;
  margin-right:8px;
  border-radius:8px;
  background:rgba(0, 190, 255, .10);
  color:#5fc7ff;
}}
#deviceTable td {{ vertical-align: middle; }}
#deviceTable input, #deviceTable select {{
  border-radius:6px;
  border:1px solid rgba(255,255,255,.25);
  padding:6px 8px;
}}
</style>
<input class="searchbar" id="deviceSearch" placeholder="Search device, IP, MAC, vendor, type, status..." onkeyup="filterDevices()">
<div class="panel">
<p class="sub">Manual edits are locked and will override collector updates.</p>
<p class="sub">Private MAC means an iPhone or Android privacy address. To keep one stable identity, disable Private Wi-Fi Address / Randomized MAC for this trusted home network, or manually rename the current address.</p>
<table id="deviceTable">
<tr>
<th>{sort_link('Name', 'name')}</th>
<th>{sort_link('IP', 'ip')}</th>
<th>{sort_link('MAC', 'mac')}</th>
<th>{sort_link('Vendor', 'vendor')}</th>
<th>{sort_link('Type', 'type')}</th>
<th>{sort_link('Status', 'status')}</th>
<th>Live</th>
<th>{sort_link('Last Seen', 'last')}</th>
<th>Action</th>
</tr>
{table or '<tr><td colspan="9">No devices yet</td></tr>'}
</table>
</div>
"""

    return shell("Devices", body, "Devices")


def valid_lan_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


@app.route("/device/unlock/<ip>", methods=["POST"])
def unlock_device(ip):
    if not valid_lan_ip(ip):
        return shell("Invalid IP", f"{topbar('Invalid IP')}<div class='panel'>Invalid IP address.</div>", "Devices")

    ensure_device_overrides_table()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    run_sql("DELETE FROM device_overrides WHERE ip=?", (ip,))
    run_sql(
        """
        INSERT INTO device_override_unlocks (ip, updated_at)
        VALUES (?, ?)
        ON CONFLICT(ip) DO UPDATE SET updated_at=excluded.updated_at
        """,
        (ip, now),
    )
    run_sql(
        """
        UPDATE devices
        SET name=ip,
            vendor='Unknown Vendor',
            device_type='Unknown'
        WHERE ip=?
        """,
        (ip,),
    )
    if request.form.get("return_to") == "device":
        return_range = request.form.get("range", "1d")
        if return_range not in ["1d", "7d", "30d"]:
            return_range = "1d"
        return redirect(f"/device/{ip}?range={return_range}")
    return redirect("/devices")


def set_manual_status(ip, status):
    ensure_device_overrides_table()
    rows = query("SELECT name, vendor, device_type FROM device_overrides WHERE ip=?", (ip,))
    unlocked = query("SELECT 1 FROM device_override_unlocks WHERE ip=? LIMIT 1", (ip,))

    if rows:
        run_sql(
            """
            UPDATE device_overrides
            SET status=?, updated_at=?
            WHERE ip=?
            """,
            (status, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip),
        )
    elif not unlocked:
        d = query("SELECT name, vendor, device_type FROM devices WHERE ip=? LIMIT 1", (ip,))
        name = d[0]["name"] if d and d[0]["name"] else ip
        vendor = d[0]["vendor"] if d and d[0]["vendor"] else "Unknown Vendor"
        dtype = d[0]["device_type"] if d and d[0]["device_type"] else "Unknown"

        run_sql(
            """
            INSERT INTO device_overrides (ip, name, vendor, device_type, status, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                status=excluded.status,
                updated_at=excluded.updated_at
            """,
            (ip, name, vendor, dtype, status, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )

    run_sql("UPDATE devices SET status=? WHERE ip=?", (status, ip))


def adguard_access_list():
    ok, data = ag_get("/access/list")
    if ok and isinstance(data, dict):
        return data

    return {
        "allowed_clients": [],
        "disallowed_clients": [],
        "blocked_hosts": [],
    }


def adguard_set_disallowed(ip, blocked=True):
    data = adguard_access_list()
    allowed = data.get("allowed_clients") or []
    disallowed = data.get("disallowed_clients") or []
    blocked_hosts = data.get("blocked_hosts") or []

    if blocked:
        if ip not in disallowed:
            disallowed.append(ip)
        allowed = [x for x in allowed if x != ip]
    else:
        disallowed = [x for x in disallowed if x != ip]

    ok, resp = ag_post("/access/set", {
        "allowed_clients": allowed,
        "disallowed_clients": disallowed,
        "blocked_hosts": blocked_hosts,
    })

    return ok, resp


@app.route("/device/pause/<ip>", methods=["POST"])
def pause_device(ip):
    if not valid_lan_ip(ip):
        return shell("Invalid IP", f"{topbar('Invalid IP')}<div class='panel'>Invalid IP address.</div>", "Devices")

    ok, resp = adguard_set_disallowed(ip, True)
    set_manual_status(ip, "DNS Blocked" if ok else "DNS Block Failed")
    return redirect(f"/device/{ip}")


@app.route("/device/resume/<ip>", methods=["POST"])
def resume_device(ip):
    if not valid_lan_ip(ip):
        return shell("Invalid IP", f"{topbar('Invalid IP')}<div class='panel'>Invalid IP address.</div>", "Devices")

    ok, resp = adguard_set_disallowed(ip, False)
    set_manual_status(ip, "Active" if ok else "Resume Failed")
    return redirect(f"/device/{ip}")


@app.route("/ping/<ip>")
def ping_device(ip):
    if not valid_lan_ip(ip):
        return shell("Invalid IP", f"{topbar('Invalid IP')}<div class='panel'>Invalid IP address.</div>", "Devices")

    try:
        out = subprocess.check_output(
            ["ping", "-c", "4", "-W", "2", ip],
            stderr=subprocess.STDOUT,
            timeout=12,
        ).decode(errors="replace")
    except Exception as e:
        out = str(e)

    body = f"""
{topbar('Ping Test')}
<div class="panel">
<h2>Ping {h(ip)}</h2>
<pre>{h(out)}</pre>
<p><a class="btn" href="/device/{h(ip)}">Back to Device</a></p>
</div>
"""
    return shell("Ping", body, "Devices")


@app.route("/scan/<ip>")
def scan_device(ip):
    if not valid_lan_ip(ip):
        return shell("Invalid IP", f"{topbar('Invalid IP')}<div class='panel'>Invalid IP address.</div>", "Devices")

    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP",
        81: "Alt HTTP", 88: "Kerberos", 135: "RPC", 139: "NetBIOS",
        443: "HTTPS", 445: "SMB", 554: "RTSP", 631: "IPP/Printer",
        1883: "MQTT", 3000: "Web UI", 3389: "RDP", 5000: "UPnP/Web",
        8000: "HTTP Alt", 8080: "HTTP Proxy", 8123: "Home Assistant",
        8443: "HTTPS Alt", 9100: "JetDirect Printer",
    }

    rows = ""
    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.35)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                link = ""
                if port in [80, 81, 3000, 5000, 8000, 8080, 8123]:
                    link = f' <a class="btn" href="http://{h(ip)}:{port}" target="_blank">Open</a>'
                elif port in [443, 8443]:
                    link = f' <a class="btn" href="https://{h(ip)}:{port}" target="_blank">Open</a>'
                rows += f"<tr><td>{port}</td><td>{h(service)}</td><td><span class='green'>Open</span>{link}</td></tr>"
        except Exception:
            pass
        finally:
            sock.close()

    if not rows:
        rows = "<tr><td colspan='3'>No common ports open.</td></tr>"

    body = f"""
{topbar('Port Scan')}
<div class="panel">
<h2>Quick Port Scan: {h(ip)}</h2>
<p class="sub">This is a light scan of common LAN ports only.</p>
<table>
<tr><th>Port</th><th>Service</th><th>Status</th></tr>
{rows}
</table>
<p><a class="btn" href="/device/{h(ip)}">Back to Device</a></p>
</div>
"""
    return shell("Port Scan", body, "Devices")


def quick_detect_services(ip):
    common_ports = {
        22: "SSH",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        554: "RTSP",
        631: "Printer",
        1883: "MQTT",
        3000: "Web UI",
        3389: "RDP",
        5000: "Web UI",
        8000: "HTTP Alt",
        8080: "HTTP Alt",
        8123: "Home Assistant",
        8443: "HTTPS Alt",
        9100: "Printer",
    }

    found = []

    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.12)
        try:
            if sock.connect_ex((ip, port)) == 0:
                proto = "TCP"
                open_url = ""

                if port in [80, 3000, 5000, 8000, 8080, 8123]:
                    open_url = f"http://{ip}:{port}"
                elif port in [443, 8443]:
                    open_url = f"https://{ip}:{port}"

                found.append({
                    "port": port,
                    "service": service,
                    "proto": proto,
                    "url": open_url,
                })
        except Exception:
            pass
        finally:
            sock.close()

    return found



@app.route("/device/<ip>")
def device(ip):
    ensure_device_overrides_table()
    start_day = range_start_day()

    rows = query(
        """
        WITH usage AS (
            SELECT
                t.ip,
                MAX(t.id) AS max_id,
                SUM(t.downloaded_mb) AS downloaded_mb,
                SUM(t.uploaded_mb) AS uploaded_mb,
                SUM(t.total_mb) AS total_mb
            FROM traffic_intervals t
            WHERE t.ip=? AND t.day >= ?
        )
        SELECT
            COALESCE(o.name, d.name, t.name, t.ip) AS display_name,
            COALESCE(o.vendor, d.vendor, 'Unknown Vendor') AS display_vendor,
            COALESCE(o.device_type, d.device_type, 'Unknown') AS display_type,
            COALESCE(o.status, d.status, 'Active') AS display_status,
            CASE WHEN o.ip IS NOT NULL THEN 1 ELSE 0 END AS manual_locked,
            t.id,
            t.ip,
            t.name,
            t.mac,
            u.downloaded_mb,
            u.uploaded_mb,
            u.total_mb,
            t.live_bps,
            t.day,
            t.ts
        FROM usage u
        JOIN traffic_intervals t
            ON t.id = u.max_id
        LEFT JOIN devices d
            ON d.ip = t.ip
        LEFT JOIN device_overrides o
            ON o.ip = t.ip
        """,
        (ip, start_day),
    )

    if not rows:
        inventory = query(
            """
            SELECT
                d.*,
                COALESCE(o.name, d.name, d.ip) AS display_name,
                COALESCE(o.vendor, d.vendor, 'Unknown Vendor') AS display_vendor,
                COALESCE(o.device_type, d.device_type, 'Unknown') AS display_type,
                COALESCE(o.status, d.status, 'Active') AS display_status
            FROM devices d
            LEFT JOIN device_overrides o ON o.ip=d.ip
            WHERE d.ip=?
            LIMIT 1
            """,
            (ip,),
        )
        if inventory:
            d = inventory[0]
            inventory_body = f"""
{topbar(h(d['display_name'] or ip))}
<div class="panel">
  <h2>Device Identity</h2>
  <p>This device was discovered from network inventory or DNS activity. No measured bridge traffic is available for the selected period.</p>
  <table>
    <tr><th>Name</th><td>{h(d['display_name'] or ip)}</td></tr>
    <tr><th>IP Address</th><td>{h(ip)}</td></tr>
    <tr><th>MAC Address</th><td>{h(d['mac'] or '-')}</td></tr>
    <tr><th>Manufacturer</th><td>{h(d['display_vendor'] or 'Unknown Vendor')}</td></tr>
    <tr><th>Type</th><td>{h(d['display_type'] or 'Unknown')}</td></tr>
    <tr><th>Status</th><td>{h(d['display_status'] or 'Active')}</td></tr>
    <tr><th>First Seen</th><td>{h(d['first_seen'] or '-')}</td></tr>
    <tr><th>Last Seen</th><td>{h(d['last_seen'] or '-')}</td></tr>
  </table>
</div>
"""
            return shell("Device", inventory_body, "Devices")
        empty_body = f"{topbar('Device')}{time_picker()}<div class='panel'>No data for {h(ip)} in this period.</div>"
        return shell("Device", empty_body, "Devices")

    r = rows[0]
    device_name = r["display_name"] or ip
    vendor = r["display_vendor"] or "Unknown Vendor"
    dtype = r["display_type"] or "Unknown"
    status = r["display_status"] or "Active"
    manual_locked = bool(r["manual_locked"])
    private_mac = private_mac_address(r["mac"])

    # Per-device DNS activity must be an exact client match.
    # Do NOT use LIKE here: a gateway IP could also match longer client IPs.
    client_keys = []
    for key in [ip, r["mac"], device_name]:
        if key and key not in client_keys:
            client_keys.append(key)

    placeholders = ",".join(["?"] * len(client_keys))

    domains = query(
        f"""
        SELECT domain, category, COUNT(*) AS total
        FROM dns_querylog
        WHERE client IN ({placeholders}) AND day >= ?
        GROUP BY domain, category
        ORDER BY total DESC
        LIMIT 60
        """,
        tuple(client_keys) + (start_day,),
    )

    category_counts = {}
    domain_rows = ""

    for d in domains:
        if is_noise(d["domain"]):
            continue

        cat = d["category"] or "Other"
        count = int(d["total"] or 0)
        category_counts[cat] = category_counts.get(cat, 0) + count

        domain_rows += f"""
<tr>
  <td>{icon_for_app(cat)} {h(d['domain'])}</td>
  <td>{h(cat)}</td>
  <td>{count}</td>
</tr>
"""

    app_rows = ""
    max_count = max(category_counts.values(), default=1)
    total_queries = sum(category_counts.values())

    for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:8]:
        width = max(5, min(count / max_count * 100, 100))
        pct = round((count / total_queries * 100), 1) if total_queries else 0
        app_rows += f"""
<div class="device-app-row">
  <div class="device-app-name">{icon_for_app(cat)}<span>{h(cat)}</span></div>
  <div class="device-app-bar"><div style="width:{width}%"></div></div>
  <b>{count}</b>
  <span>{pct}%</span>
</div>
"""

    services = quick_detect_services(ip)
    service_rows = ""
    web_url = ""

    for s in services:
        if not web_url and s["url"]:
            web_url = s["url"]

        open_link = ""
        if s["url"]:
            open_link = f'<a class="mini-link" target="_blank" href="{h(s["url"])}">Open</a>'

        service_rows += f"""
<tr>
  <td>{s['port']}</td>
  <td>{h(s['service'])}</td>
  <td>{h(s['proto'])}</td>
  <td><span class="pill-open">Open</span> {open_link}</td>
</tr>
"""

    if not service_rows:
        service_rows = "<tr><td colspan='4'>No common LAN services detected. Use Port Scan for a fuller check.</td></tr>"

    open_web_button = ""
    if web_url:
        open_web_button = f'<a class="tool-btn blue" href="{h(web_url)}" target="_blank"><i class="fa-solid fa-arrow-up-right-from-square"></i> Open Web UI</a>'

    live_speed_data = live_host_speed(ip)
    if not live_speed_data.get("total_bps") and device_name:
        live_speed_data = live_host_speed(device_name)
    live_speed = fmt_bits_as_bytes(live_speed_data.get("total_bps") or r["live_bps"] or 0)
    live_rx = fmt_bits_as_bytes(live_speed_data.get("rx_bps") or 0)
    live_tx = fmt_bits_as_bytes(live_speed_data.get("tx_bps") or 0)
    detail_lock_badge = ""
    if manual_locked:
        detail_lock_badge = (
            f'<form class="unlock-device-form" method="post" action="/device/unlock/{h(ip)}" '
            f'onsubmit="return confirm(\'Unlock this device and clear its saved identity details?\');">'
            f'{csrf_input()}<input type="hidden" name="return_to" value="device">'
            f'<input type="hidden" name="range" value="{range_key()}">'
            f'<button class="badge-lock unlock-badge" type="submit" '
            f'title="Unlock and clear saved identity details">Locked <i class="fa-solid fa-lock-open"></i></button></form>'
        )

    body = f"""
{topbar(h(device_name))}
<style>
.device-range-controls {{ display:flex; align-items:center; margin-bottom:14px; }}
.device-range-controls .time-picker {{ margin-left:8px; }}
.device-hero {{ display:grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap:14px; margin-bottom:16px; }}
.device-stat {{ padding:18px; border:1px solid rgba(0,190,255,.22); border-radius:14px; background:linear-gradient(145deg, rgba(6,22,36,.94), rgba(3,12,22,.96)); box-shadow:0 0 24px rgba(0,190,255,.04); }}
.device-stat .label {{ color:#b7c8d9; font-size:13px; }}
.device-stat .value {{ display:block; margin-top:8px; font-size:22px; font-weight:800; }}
.device-grid-main {{ display:grid; grid-template-columns: 1.55fr 1fr; gap:16px; margin-bottom:16px; }}
.device-grid-bottom {{ display:grid; grid-template-columns: 1.25fr 1fr; gap:16px; }}
.identity-card {{ display:grid; grid-template-columns: 110px 1fr; gap:18px; align-items:center; }}
.device-avatar {{ width:92px; height:92px; border-radius:24px; display:flex; align-items:center; justify-content:center; font-size:46px; background:radial-gradient(circle at top, rgba(0,220,255,.22), rgba(0,40,65,.82)); border:1px solid rgba(0,220,255,.22); }}
.identity-title {{ font-size:24px; font-weight:800; margin-bottom:8px; }}
.identity-line {{ display:grid; grid-template-columns: 110px 1fr; gap:8px; margin:5px 0; color:#d7e6f5; }}
.identity-line span:first-child {{ color:#93a7ba; }}
.device-tools {{ display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap:10px; margin-top:16px; }}
.tool-btn {{ text-align:center; padding:12px 10px; border-radius:10px; font-weight:700; border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.04); color:#dff7ff; }}
.tool-action {{ display:flex; margin:0; }}
.tool-action .tool-btn {{ width:100%; margin:0; }}
.tool-btn.blue {{ color:#22b8ff; border-color:rgba(0,150,255,.35); }}
.tool-btn.green {{ color:#38f07b; border-color:rgba(50,240,120,.35); }}
.tool-btn.yellow {{ color:#ffca3a; border-color:rgba(255,202,58,.35); }}
.tool-btn.red {{ color:#ff4b6d; border-color:rgba(255,75,109,.35); }}
.device-app-row {{ display:grid; grid-template-columns: 150px 1fr 70px 60px; gap:14px; align-items:center; margin:16px 0; }}
.device-app-name {{ display:flex; align-items:center; gap:10px; }}
.device-app-bar {{ height:10px; border-radius:999px; background:rgba(130,170,200,.15); overflow:hidden; }}
.device-app-bar div {{ height:100%; border-radius:999px; background:linear-gradient(90deg, #00a9ff, #20f0d0, #9b5cff); }}
.device-scroll {{ max-height:440px; overflow:auto; }}
.pill-open {{ display:inline-block; padding:3px 9px; border-radius:999px; border:1px solid rgba(62,240,120,.5); color:#52ef86; font-weight:700; }}
.badge-lock {{ display:inline-block; padding:3px 8px; border-radius:999px; background:rgba(0,220,200,.16); color:#28e0d5; font-size:12px; font-weight:700; }}
.unlock-device-form {{ display:inline; margin:0; }}
.unlock-badge {{ border:1px solid rgba(0,220,200,.24); font:inherit; cursor:pointer; }}
.unlock-badge:hover {{ background:rgba(0,220,200,.28); color:#eaffff; }}
.badge-private {{ display:inline-block; padding:3px 8px; border-radius:999px; border:1px solid rgba(248,200,78,.28); background:rgba(248,200,78,.12); color:#f8c84e; font-size:12px; font-weight:700; }}
.mini-link {{ margin-left:8px; color:#28d7ff; font-weight:700; }}
@media (max-width: 1100px) {{ .device-hero, .device-grid-main, .device-grid-bottom {{ grid-template-columns:1fr; }} .device-tools {{ grid-template-columns:1fr; }} }}
@media (max-width: 600px) {{
  .device-stat {{ padding:14px; }}
  .identity-card {{ grid-template-columns:1fr; justify-items:center; }}
  .identity-title {{ text-align:center; font-size:20px; }}
  .identity-line {{ grid-template-columns:1fr; gap:2px; margin:9px 0; }}
  .device-app-row {{ grid-template-columns:minmax(0, 1fr) auto; gap:10px; }}
  .device-app-name, .device-app-bar {{ grid-column:1 / -1; }}
}}
</style>

<div class="device-range-controls">
  {time_picker()}
</div>
<div class="device-hero">
  <div class="device-stat"><div class="label">Download</div><span class="value blue">{fmt_mb(r['downloaded_mb'])}</span></div>
  <div class="device-stat"><div class="label">Upload</div><span class="value purple">{fmt_mb(r['uploaded_mb'])}</span></div>
  <div class="device-stat"><div class="label">Total</div><span class="value teal">{fmt_mb(r['total_mb'])}</span></div>
  <div class="device-stat"><div class="label">Live Speed</div><span class="value green" data-live-ip="{h(ip)}" data-live-field="total">{live_speed}</span><small>DL <span data-live-ip="{h(ip)}" data-live-field="down">{live_rx}</span> | UL <span data-live-ip="{h(ip)}" data-live-field="up">{live_tx}</span></small></div>
  <div class="device-stat"><div class="label">DNS Queries</div><span class="value blue">{total_queries}</span></div>
  <div class="device-stat"><div class="label">Alerts</div><span class="value red">{r['alerts'] if 'alerts' in r.keys() else 0}</span></div>
</div>

<div class="device-grid-main">
  <div class="panel">
    <h2>Applications For This Device <span class="sub" style="float:right;">Total Queries: {total_queries}</span></h2>
    {app_rows or 'No per-device app data yet. Wait for AdGuard querylog collection.'}
  </div>

  <div class="panel">
    <h2>Device Identity</h2>
    <div class="identity-card">
      <div class="device-avatar">{icon_for_device(dtype)}</div>
      <div>
        <div class="identity-title">{h(device_name)} {detail_lock_badge} {'<span class="badge-private">Private MAC</span>' if private_mac else ''}</div>
        <div class="identity-line"><span>IP Address</span><b>{h(ip)}</b></div>
        <div class="identity-line"><span>MAC Address</span><b>{h(r['mac'])}</b></div>
        <div class="identity-line"><span>Vendor</span><b>{h(vendor)}</b></div>
        <div class="identity-line"><span>Type</span><b>{h(dtype)}</b></div>
        <div class="identity-line"><span>Status</span><b>{h(status)}</b></div>
        <div class="identity-line"><span>Manual Lock</span><b>{'Yes' if manual_locked else 'No'}</b></div>
        {f'<div class="identity-line"><span>Identity</span><b>Randomized by device privacy setting; disable it for this home Wi-Fi to keep tracking stable.</b></div>' if private_mac else ''}
      </div>
    </div>

    <div class="device-tools">
      <a class="tool-btn blue" href="/ping/{h(ip)}"><i class="fa-solid fa-satellite-dish"></i> Ping</a>
      <a class="tool-btn blue" href="/scan/{h(ip)}"><i class="fa-solid fa-magnifying-glass"></i> Port Scan</a>
      <form class="tool-action" method="post" action="/device/pause/{h(ip)}">{csrf_input()}<button class="tool-btn yellow" type="submit"><i class="fa-solid fa-ban"></i> Block DNS</button></form>
      <form class="tool-action" method="post" action="/device/resume/{h(ip)}">{csrf_input()}<button class="tool-btn green" type="submit"><i class="fa-solid fa-check"></i> Allow DNS</button></form>
      <a class="tool-btn red" href="/device/block/{h(ip)}"><i class="fa-solid fa-ban"></i> Block Device</a>
      <a class="tool-btn blue" href="/devices"><i class="fa-solid fa-pen-to-square"></i> Edit Device</a>
      {open_web_button}
      <button class="tool-btn" onclick="navigator.clipboard.writeText('{h(ip)}')"><i class="fa-regular fa-copy"></i> Copy IP</button>
      <a class="tool-btn blue" href="/history?ip={h(ip)}"><i class="fa-solid fa-clock-rotate-left"></i> History</a>
    </div>
  </div>
</div>

<div class="device-grid-bottom">
  <div class="panel device-scroll">
    <h2>Recent Activity / Top Domains</h2>
    <table>
      <tr><th>Domain</th><th>Category</th><th>Hits</th></tr>
      {domain_rows or '<tr><td colspan="3">No per-device domains yet</td></tr>'}
    </table>
  </div>

  <div class="panel">
    <h2>Detected Services</h2>
    <p class="sub">Quick scan of common LAN ports. Use Port Scan for the fuller result.</p>
    <table>
      <tr><th>Port</th><th>Service</th><th>Protocol</th><th>Status</th></tr>
      {service_rows}
    </table>
  </div>
</div>
"""

    return shell(device_name, body, "Devices")



# ===================================================
# HISTORICAL TRAFFIC GRAPH API
# ===================================================

@app.route("/api/history")
def api_history():
    period = request.args.get("period", "1h").strip().lower()
    ip = request.args.get("ip", "").strip()

    if period not in ["1h", "24h", "7d", "30d"]:
        period = "1h"

    if period == "1h":
        bucket_expr = "substr(ts, 1, 16)"
        since_expr = "datetime('now','localtime','-1 hour')"
    elif period == "24h":
        bucket_expr = "substr(ts, 1, 13) || ':00'"
        since_expr = "datetime('now','localtime','-24 hours')"
    elif period == "7d":
        bucket_expr = "day"
        since_expr = "date('now','localtime','-7 days')"
    else:
        bucket_expr = "day"
        since_expr = "date('now','localtime','-30 days')"

    if ip:
        rows = query(
            f"""
            SELECT
                {bucket_expr} AS bucket,
                SUM(downloaded_mb) AS downloaded,
                SUM(uploaded_mb) AS uploaded,
                SUM(total_mb) AS total
            FROM traffic_intervals
            WHERE ip=?
              AND ts >= {since_expr}
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            (ip,),
        )
    else:
        rows = query(
            f"""
            SELECT
                bucket,
                SUM(downloaded) AS downloaded,
                SUM(uploaded) AS uploaded,
                SUM(total) AS total
            FROM (
                SELECT
                    {bucket_expr} AS bucket,
                    ip,
                    SUM(downloaded_mb) AS downloaded,
                    SUM(uploaded_mb) AS uploaded,
                    SUM(total_mb) AS total
                FROM traffic_intervals
                WHERE ts >= {since_expr}
                GROUP BY bucket, ip
            )
            GROUP BY bucket
            ORDER BY bucket ASC
            """
        )

    labels = []
    downloaded = []
    uploaded = []
    total = []

    for r in rows:
        labels.append(str(r["bucket"] or ""))
        downloaded.append(round(float(r["downloaded"] or 0), 2))
        uploaded.append(round(float(r["uploaded"] or 0), 2))
        total.append(round(float(r["total"] or 0), 2))

    return {
        "period": period,
        "ip": ip,
        "labels": labels,
        "downloaded": downloaded,
        "uploaded": uploaded,
        "total": total,
    }


@app.route("/history")
def history():
    ip = request.args.get("ip", "").strip()

    title = "Network History"
    subtitle = "Network-wide traffic history"

    if ip:
        title = f"Device History: {h(ip)}"
        subtitle = "Per-device traffic history"

    body = f"""
{topbar(title)}
<style>
.history-controls {{
  display:flex;
  gap:10px;
  flex-wrap:wrap;
  margin-bottom:14px;
}}
.history-btn {{
  display:inline-block;
  padding:9px 13px;
  border-radius:10px;
  background:rgba(0,190,255,.12);
  border:1px solid rgba(0,190,255,.25);
  color:#eaf6ff;
  text-decoration:none;
  cursor:pointer;
}}
.history-btn:hover {{
  border-color:rgba(0,220,255,.55);
}}
.chart-box {{
  min-height:340px;
}}
.chart-box canvas {{
  max-height:300px;
}}
.history-sub {{
  color:#9db0c4;
  margin-top:-6px;
  margin-bottom:14px;
}}
.device-history-form {{
  display:flex;
  gap:8px;
  flex-wrap:wrap;
  margin-bottom:14px;
}}
.device-history-form input {{
  background:#071624;
  border:1px solid rgba(0,190,255,.25);
  border-radius:10px;
  color:#eaf6ff;
  padding:10px 12px;
  min-width:220px;
}}
</style>

<div class="panel">
  <h2>{subtitle}</h2>
  <p class="history-sub">Graphs show measured traffic used within each time bucket.</p>

  <form class="device-history-form" method="GET" action="/history">
    <input name="ip" placeholder="Optional device IP, e.g. {h(cfg().get('lan_prefix', DEFAULT_CONFIG['lan_prefix']))}58" value="{h(ip)}">
    <button class="history-btn" type="submit">Show Device</button>
    <a class="history-btn" href="/history">Network-wide</a>
  </form>

  <div class="history-controls">
    <button class="history-btn" onclick="loadHistory('1h')">Last 1 Hour</button>
    <button class="history-btn" onclick="loadHistory('24h')">Last 24 Hours</button>
    <button class="history-btn" onclick="loadHistory('7d')">Last 7 Days</button>
    <button class="history-btn" onclick="loadHistory('30d')">Last 30 Days</button>
  </div>

  <div class="chart-box">
    <canvas id="historyChart"></canvas>
  </div>
</div>

<script>
let historyChart = null;
const historyIp = "{h(ip)}";

async function loadHistory(period) {{
  const url = "/api/history?period=" + encodeURIComponent(period) +
              (historyIp ? "&ip=" + encodeURIComponent(historyIp) : "");

  const res = await fetch(url, {{cache: "no-store"}});
  if (!res.ok) return;

  const data = await res.json();

  const ctx = document.getElementById("historyChart");
  if (!ctx) return;

  if (historyChart) {{
    historyChart.destroy();
  }}

  historyChart = new Chart(ctx, {{
    type: "line",
    data: {{
      labels: data.labels,
      datasets: [
        {{
          label: "Downloaded MB",
          data: data.downloaded,
          tension: 0.25
        }},
        {{
          label: "Uploaded MB",
          data: data.uploaded,
          tension: 0.25
        }},
        {{
          label: "Total MB",
          data: data.total,
          tension: 0.25
        }}
      ]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      interaction: {{
        mode: "index",
        intersect: false
      }},
      plugins: {{
        legend: {{
          display: true
        }},
        title: {{
          display: true,
          text: (historyIp ? "Device " + historyIp + " - " : "Network - ") + period.toUpperCase()
        }}
      }},
      scales: {{
        y: {{
          beginAtZero: true,
          title: {{
            display: true,
            text: "MB"
          }}
        }},
        x: {{
          ticks: {{
            maxTicksLimit: 12
          }}
        }}
      }}
    }}
  }});
}}

loadHistory("1h");
</script>
"""
    return shell(title, body, "History")


@app.route("/traffic")
def traffic():
    mode = request.args.get("type", "total")
    sort = request.args.get("sort", "total")
    direction = request.args.get("dir", "desc")
    start_day = range_start_day()

    title = "Total Traffic"
    if mode == "download":
        title = "Download Usage"
    elif mode == "upload":
        title = "Upload Usage"

    sort_map = {
        "device": "name",
        "ip": "ip_sort",
        "download": "downloaded_mb",
        "upload": "uploaded_mb",
        "total": "total_mb",
    }

    sort_col = sort_map.get(sort, "total_mb")
    direction_sql = "ASC" if direction == "asc" else "DESC"

    rows = query(
        f"""
        WITH usage AS (
            SELECT
                ip,
                MAX(name) AS name,
                MAX(mac) AS mac,
                SUM(downloaded_mb) AS downloaded_mb,
                SUM(uploaded_mb) AS uploaded_mb,
                SUM(total_mb) AS total_mb,
                MAX(live_bps) AS live_bps,
                MAX(day) AS day,
                MAX(ts) AS ts
            FROM traffic_intervals
            WHERE day>=?
            GROUP BY ip
        )
        SELECT
            COALESCE(o.name, d.name, u.name, u.ip) AS name,
            u.ip AS ip_sort,
            u.*
        FROM usage u
        LEFT JOIN devices d ON d.ip = u.ip
        LEFT JOIN device_overrides o ON o.ip = u.ip
        ORDER BY {sort_col} {direction_sql}
        LIMIT 200
        """,
        (start_day,),
    )

    def sort_link(label, key):
        next_dir = "desc"
        marker = ""
        if sort == key:
            next_dir = "asc" if direction == "desc" else "desc"
            marker = " ↓" if direction == "desc" else " ↑"
        return f'<a class="sort-link" href="/traffic?range={range_key()}&type={h(mode)}&sort={h(key)}&dir={next_dir}">{label}{marker}</a>'

    table = ""
    for r in rows:
        table += f"""
<tr onclick="location.href='/device/{h(r['ip'])}?range={range_key()}'">
  <td>{h(r['name'])}</td>
  <td>{h(r['ip'])}</td>
  <td>{fmt_mb(r['downloaded_mb'])}</td>
  <td>{fmt_mb(r['uploaded_mb'])}</td>
  <td>{fmt_mb(r['total_mb'])}</td>
  <td><span data-live-ip="{h(r['ip'])}" data-live-field="total">{fmt_bits_as_bytes(live_host_speed(str(r['ip'])).get('total_bps', 0))}</span></td>
</tr>
"""

    clear_notice = ""
    if request.args.get("cleared") == "1":
        clear_notice = "<div class='traffic-cleared'>Traffic history cleared. New traffic is now collecting from zero.</div>"
    elif request.args.get("clear_error") == "1":
        clear_notice = "<div class='traffic-clear-error'>Traffic history could not be cleared. Check the NetSpecter service log and try again.</div>"
    elif request.args.get("collector_error") == "1":
        clear_notice = "<div class='traffic-clear-error'>Traffic was cleared, but the collector did not start again. Run systemctl start netspecter-collector.</div>"

    body = f"""
{topbar(title)}
<div class="traffic-controls">
  {time_picker()}
  <a class="traffic-clear-btn" href="/traffic/clear?range={range_key()}">Clear Traffic History</a>
</div>
<style>
.traffic-controls {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:14px; }}
.traffic-controls .time-picker {{ margin-left:8px; }}
.traffic-clear-btn {{ display:inline-block; color:#ffdbe0; border:1px solid rgba(255,77,94,.42); background:rgba(255,77,94,.12); padding:9px 13px; border-radius:14px; font-size:12px; font-weight:800; text-decoration:none; }}
.traffic-clear-btn:hover {{ background:rgba(255,77,94,.24); color:#fff; }}
.traffic-cleared {{ margin:0 0 14px 8px; padding:11px 14px; border-radius:10px; border:1px solid rgba(0,214,183,.3); background:rgba(0,214,183,.10); color:#7df5df; font-weight:700; }}
.traffic-clear-error {{ margin:0 0 14px 8px; padding:11px 14px; border-radius:10px; border:1px solid rgba(255,77,94,.38); background:rgba(255,77,94,.12); color:#ffdbe0; font-weight:700; }}
.sort-link {{ color:#eaf6ff; text-decoration:none; }}
.sort-link:hover {{ color:#14d8ff; }}
tr[onclick] {{ cursor:pointer; }}
tr[onclick]:hover {{ background:rgba(0,190,255,.07); }}
</style>
{clear_notice}
<div class="panel">
<table>
<tr>
<th>{sort_link('Device', 'device')}</th>
<th>{sort_link('IP', 'ip')}</th>
<th>{sort_link('Download', 'download')}</th>
<th>{sort_link('Upload', 'upload')}</th>
<th>{sort_link('Total', 'total')}</th>
<th>Throughput</th>
</tr>
{table}
</table>
</div>
"""
    return shell(title, body, "Traffic")


@app.route("/traffic/clear", methods=["GET", "POST"])
def clear_traffic_history():
    if request.method == "POST":
        if not collector_service_action("stop"):
            return redirect(f"/traffic?range={range_key()}&clear_error=1")

        try:
            init_db()
            con = connect_db()
            con.execute("DELETE FROM traffic_intervals")
            con.execute("DELETE FROM traffic_samples")
            con.execute("DELETE FROM estimated_app_traffic")
            con.execute("DELETE FROM remote_traffic_intervals")
            con.execute("DELETE FROM live_device_speed")
            con.commit()
            con.close()
        except Exception as e:
            print(f"Traffic history clear failed: {e}")
            collector_service_action("start")
            return redirect(f"/traffic?range={range_key()}&clear_error=1")

        if not collector_service_action("start"):
            return redirect("/traffic?range=1d&collector_error=1")
        return redirect("/traffic?range=1d&cleared=1")

    sample_rows = query("SELECT COUNT(*) AS total FROM traffic_intervals")
    sample_count = int(sample_rows[0]["total"] or 0) if sample_rows else 0

    body = f"""
{topbar('Clear Traffic History')}
<style>
.clear-warning {{ max-width:620px; }}
.clear-warning p {{ color:#b8c7da; line-height:1.55; }}
.clear-warning strong {{ color:#ff8997; }}
.clear-actions {{ display:flex; gap:10px; align-items:center; margin-top:20px; }}
.clear-actions a {{ color:#c5d3e4; text-decoration:none; font-weight:700; padding:11px 15px; }}
</style>
<div class="panel clear-warning">
  <h2>Are you sure?</h2>
  <p>This will permanently delete <strong>{sample_count:,} measured traffic intervals</strong> and reset the live traffic totals to zero.</p>
  <p>Your DNS history, settings, login and edited device names will not be changed.</p>
  <form method="post" class="clear-actions">
    {csrf_input()}
    <button class="btn-red" type="submit">Yes, Clear Traffic History</button>
    <a href="/traffic?range={range_key()}">Cancel</a>
  </form>
</div>
"""
    return shell("Clear Traffic History", body, "Traffic")


@app.route("/applications")
def applications():
    start_day = range_start_day()
    sort = request.args.get("sort", "queries")
    direction = request.args.get("dir", "desc")
    sort_map = {
        "app": "category COLLATE NOCASE",
        "activity": "total",
        "devices": "devices",
        "domains": "domains",
        "queries": "total",
        "share": "total",
    }
    sort_col = sort_map.get(sort, "total")
    direction_sql = "ASC" if direction == "asc" else "DESC"
    rows = query(
        f"""
        SELECT
            category,
            COUNT(*) AS total,
            COUNT(DISTINCT client) AS devices,
            COUNT(DISTINCT domain) AS domains,
            MAX(ts) AS last_seen
        FROM dns_querylog
        WHERE day>=?
        GROUP BY category
        ORDER BY {sort_col} {direction_sql}, category COLLATE NOCASE ASC
        LIMIT 100
        """,
        (start_day,),
    )

    def sort_link(label, key):
        next_dir = "desc"
        marker = ""
        if sort == key:
            next_dir = "asc" if direction == "desc" else "desc"
            marker = " v" if direction == "desc" else " ^"
        return f'<a class="sort-link" href="/applications?range={range_key()}&sort={h(key)}&dir={next_dir}">{h(label)}{marker}</a>'

    max_count = max([int(r["total"] or 1) for r in rows], default=1)
    total_queries = sum([int(r["total"] or 0) for r in rows])
    device_count_rows = query(
        "SELECT COUNT(DISTINCT client) AS total FROM dns_querylog WHERE day>=?",
        (start_day,),
    )
    total_devices = int(device_count_rows[0]["total"] or 0) if device_count_rows else 0

    app_rows = ""
    for r in rows:
        category = str(r["category"] or "Other")
        monitor_badge = '<small class="monitor-badge">Data monitored</small>' if category in MONITORED_APP_CATEGORIES else ""
        total = int(r["total"] or 0)
        devices = int(r["devices"] or 0)
        domains = int(r["domains"] or 0)
        width = max(5, min(total / max_count * 100, 100))
        pct = round((total / total_queries * 100), 1) if total_queries else 0
        href = "/applications/" + quote(category, safe="") + f"?range={range_key()}"
        app_rows += f"""
<a class="app-row app-link" href="{href}">
  <span class="app-icon">{icon_for_app(category)}</span>
  <span class="app-name">{h(category)}{monitor_badge}</span>
  <div class="bar"><div style="width:{width}%"></div></div>
  <span class="app-meta">{devices} devices</span>
  <span class="app-meta">{domains} domains</span>
  <b>{total:,}</b>
  <span class="app-meta">{pct}%</span>
</a>
"""

    if not app_rows:
        app_rows = "<div class='empty-state'>No application activity recorded today.</div>"

    clear_notice = ""
    if request.args.get("cleared") == "1":
        clear_notice = "<div class='apps-cleared'>Application history cleared. New AdGuard activity will appear as it is imported.</div>"
    elif request.args.get("clear_error") == "1":
        clear_notice = "<div class='apps-clear-error'>Application history could not be cleared. Check the NetSpecter service log and try again.</div>"

    body = f"""
{topbar('Applications')}
<div class="apps-controls">
  {time_picker()}
  <a class="apps-clear-btn" href="/applications/clear?range={range_key()}">Clear App History</a>
</div>
<style>
.apps-controls {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:14px; }}
.apps-controls .time-picker {{ margin-left:8px; }}
.apps-clear-btn {{ display:inline-block; color:#ffdbe0; border:1px solid rgba(255,77,94,.42); background:rgba(255,77,94,.12); padding:9px 13px; border-radius:14px; font-size:12px; font-weight:800; text-decoration:none; }}
.apps-clear-btn:hover {{ background:rgba(255,77,94,.24); color:#fff; }}
.apps-cleared {{ margin:0 0 14px 8px; padding:11px 14px; border-radius:10px; border:1px solid rgba(0,214,183,.3); background:rgba(0,214,183,.10); color:#7df5df; font-weight:700; }}
.apps-clear-error {{ margin:0 0 14px 8px; padding:11px 14px; border-radius:10px; border:1px solid rgba(255,77,94,.38); background:rgba(255,77,94,.12); color:#ffdbe0; font-weight:700; }}
.monitor-badge {{ display:block; width:max-content; margin-top:4px; color:#00ddc7; font-size:10px; font-weight:800; letter-spacing:.05em; text-transform:uppercase; }}
</style>
{clear_notice}
<div class="apps-summary">
  <div class="mini-card"><span>DNS Queries</span><b>{total_queries:,}</b></div>
  <div class="mini-card"><span>Categories</span><b>{len(rows):,}</b></div>
  <div class="mini-card"><span>Devices</span><b>{total_devices:,}</b></div>
</div>
<div class="panel apps-panel">
  <div class="apps-header">
    <span>{sort_link('App', 'app')}</span>
    <span>{sort_link('Activity', 'activity')}</span>
    <span>{sort_link('Devices', 'devices')}</span>
    <span>{sort_link('Domains', 'domains')}</span>
    <span>{sort_link('Queries', 'queries')}</span>
    <span>{sort_link('Share', 'share')}</span>
  </div>
  <div class="apps-list">
    {app_rows}
  </div>
</div>
"""
    return shell("Applications", body, "Applications")


@app.route("/applications/clear", methods=["GET", "POST"])
def clear_application_history():
    if request.method == "POST":
        try:
            init_db()
            con = connect_db()
            con.execute("DELETE FROM dns_querylog")
            con.execute(
                "INSERT INTO dns_import_state (id, cleared_at) VALUES (1, ?) "
                "ON CONFLICT(id) DO UPDATE SET cleared_at=excluded.cleared_at",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
            )
            con.commit()
            con.close()
        except Exception as e:
            print(f"Application history clear failed: {e}")
            return redirect(f"/applications?range={range_key()}&clear_error=1")

        return redirect("/applications?range=1d&cleared=1")

    log_rows = query("SELECT COUNT(*) AS total FROM dns_querylog")
    query_count = int(log_rows[0]["total"] or 0) if log_rows else 0

    body = f"""
{topbar('Clear App History')}
<style>
.clear-warning {{ max-width:620px; }}
.clear-warning p {{ color:#b8c7da; line-height:1.55; }}
.clear-warning strong {{ color:#ff8997; }}
.clear-actions {{ display:flex; gap:10px; align-items:center; margin-top:20px; }}
.clear-actions a {{ color:#c5d3e4; text-decoration:none; font-weight:700; padding:11px 15px; }}
</style>
<div class="panel clear-warning">
  <h2>Are you sure?</h2>
  <p>This will permanently delete <strong>{query_count:,} stored DNS/application activity records</strong> and clear Top Applications.</p>
  <p>Your traffic history, settings, login and edited device names will not be changed.</p>
  <form method="post" class="clear-actions">
    {csrf_input()}
    <button class="btn-red" type="submit">Yes, Clear App History</button>
    <a href="/applications?range={range_key()}">Cancel</a>
  </form>
</div>
"""
    return shell("Clear App History", body, "Applications")


@app.route("/applications/<path:category>")
def application_detail(category):
    category = unquote(category or "Other")
    monitoring_enabled = category in MONITORED_APP_CATEGORIES
    start_day = range_start_day()
    sort = request.args.get("sort", "queries")
    direction = request.args.get("dir", "desc")

    sort_map = {
        "device": "device_name",
        "client": "l.client",
        "domains": "domains",
        "queries": "total",
        "estimated": "estimated_total_mb",
        "last": "last_seen",
    }
    sort_col = sort_map.get(sort, "total")
    direction_sql = "ASC" if direction == "asc" else "DESC"

    device_rows = query(
        f"""
        SELECT
            l.client,
            COALESCE(o.name, d.name, l.client) AS device_name,
            COALESCE(o.device_type, d.device_type, 'Unknown') AS device_type,
            COALESCE(o.vendor, d.vendor, 'Unknown Vendor') AS vendor,
            COALESCE(d.ip, l.client) AS device_ip,
            COUNT(*) AS total,
            COUNT(DISTINCT l.domain) AS domains,
            MAX(l.ts) AS last_seen,
            COALESCE(MAX(m.downloaded_mb), 0) AS estimated_downloaded_mb,
            COALESCE(MAX(m.total_mb), 0) AS estimated_total_mb
        FROM dns_querylog l
        LEFT JOIN devices d
            ON d.ip = l.client
            OR LOWER(d.mac) = LOWER(l.client)
        LEFT JOIN device_overrides o
            ON o.ip = COALESCE(d.ip, l.client)
        LEFT JOIN (
            SELECT ip, SUM(downloaded_mb) AS downloaded_mb, SUM(total_mb) AS total_mb
            FROM estimated_app_traffic
            WHERE day>=? AND category=?
            GROUP BY ip
        ) m ON m.ip = COALESCE(d.ip, l.client)
        WHERE l.day>=? AND l.category=?
        GROUP BY l.client
        ORDER BY {sort_col} {direction_sql}
        LIMIT 200
        """,
        (start_day, category, start_day, category),
    )

    domain_rows = query(
        """
        SELECT domain, COUNT(*) AS total, COUNT(DISTINCT client) AS devices, MAX(ts) AS last_seen
        FROM dns_querylog
        WHERE day>=? AND category=?
        GROUP BY domain
        ORDER BY total DESC
        LIMIT 100
        """,
        (start_day, category),
    )

    total_queries = sum(int(r["total"] or 0) for r in device_rows)
    max_device_queries = max([int(r["total"] or 1) for r in device_rows], default=1)
    measured_rows = query(
        """
        SELECT
            ip,
            SUM(downloaded_mb) AS downloaded_mb,
            SUM(uploaded_mb) AS uploaded_mb,
            SUM(total_mb) AS total_mb
        FROM estimated_app_traffic
        WHERE day>=? AND category=?
        GROUP BY ip
        """,
        (start_day, category),
    ) if monitoring_enabled else []
    estimated_down = sum(float(r["downloaded_mb"] or 0) for r in measured_rows)
    estimated_up = sum(float(r["uploaded_mb"] or 0) for r in measured_rows)
    estimated_total = sum(float(r["total_mb"] or 0) for r in measured_rows)
    estimated_cards = f"""
  <div class="mini-card"><span>Estimated Download</span><b>{fmt_mb(estimated_down)}</b></div>
  <div class="mini-card"><span>Estimated Upload</span><b>{fmt_mb(estimated_up)}</b></div>
  <div class="mini-card"><span>Estimated Data</span><b>{fmt_mb(estimated_total)}</b></div>
""" if monitoring_enabled else ""
    estimated_note = (
        "<p>Estimated data is measured from DNS-attributed delivery traffic for this monitored app.</p>"
        if monitoring_enabled
        else ""
    )
    empty_colspan = 7 if monitoring_enabled else 6

    def sort_link(label, key):
        next_dir = "desc"
        marker = ""
        if sort == key:
            next_dir = "asc" if direction == "desc" else "desc"
            marker = " ↓" if direction == "desc" else " ↑"
        href = f"/applications/{quote(category, safe='')}?range={range_key()}&sort={h(key)}&dir={next_dir}"
        return f'<a class="sort-link" href="{href}">{h(label)}{marker}</a>'

    estimated_header = f"<th>{sort_link('Est. Download / Total', 'estimated')}</th>" if monitoring_enabled else ""

    devices_table = ""
    for r in device_rows:
        device_ip = str(r["device_ip"] or r["client"] or "")
        total = int(r["total"] or 0)
        width = max(5, min(total / max_device_queries * 100, 100))
        href = f"/device/{h(device_ip)}" if valid_lan_ip(device_ip) else "#"
        estimated_cell = (
            f"<td>{fmt_mb(r['estimated_downloaded_mb'])} / "
            f"<b>{fmt_mb(r['estimated_total_mb'])}</b></td>"
            if monitoring_enabled
            else ""
        )
        devices_table += f"""
<tr onclick="location.href='{href}'">
  <td>{icon_for_device(r['device_type'])} <b>{h(r['device_name'])}</b><br><span>{h(r['vendor'])}</span></td>
  <td>{h(r['client'])}</td>
  <td>{int(r['domains'] or 0):,}</td>
  <td><div class="bar table-bar"><div style="width:{width}%"></div></div></td>
  <td><b>{total:,}</b></td>
  {estimated_cell}
  <td>{h(r['last_seen'])}</td>
</tr>
"""

    domains_table = ""
    for r in domain_rows:
        domains_table += f"""
<tr>
  <td>{h(r['domain'])}</td>
  <td>{int(r['devices'] or 0):,}</td>
  <td>{int(r['total'] or 0):,}</td>
  <td>{h(r['last_seen'])}</td>
</tr>
"""

    body = f"""
{topbar(category)}
{time_picker()}
<div class="app-detail-title">
  <a class="btn" href="/applications">Back to Applications</a>
  <div class="app-detail-icon">{icon_for_app(category)}</div>
  <div>
    <h2>{h(category)}</h2>
    <p>{len(device_rows):,} devices used this app today across {len(domain_rows):,} domains.</p>
  </div>
</div>
<div class="apps-summary">
  <div class="mini-card"><span>DNS Hits</span><b>{total_queries:,}</b></div>
  <div class="mini-card"><span>Devices</span><b>{len(device_rows):,}</b></div>
  <div class="mini-card"><span>Domains</span><b>{len(domain_rows):,}</b></div>
  {estimated_cards}
</div>
<div class="layout">
  <div class="panel">
    <h2>Devices Using {h(category)}</h2>
    {estimated_note}
    <table>
      <tr>
        <th>{sort_link('Device', 'device')}</th>
        <th>{sort_link('Client', 'client')}</th>
        <th>{sort_link('Domains', 'domains')}</th>
        <th>Activity</th>
        <th>{sort_link('DNS Hits', 'queries')}</th>
        {estimated_header}
        <th>{sort_link('Last Seen', 'last')}</th>
      </tr>
      {devices_table or f'<tr><td colspan="{empty_colspan}">No devices recorded for this app today.</td></tr>'}
    </table>
  </div>
  <div class="panel">
    <h2>Top Domains</h2>
    <table>
      <tr><th>Domain</th><th>Devices</th><th>Queries</th><th>Last Seen</th></tr>
      {domains_table or '<tr><td colspan="4">No domains recorded for this app today.</td></tr>'}
    </table>
  </div>
</div>
"""
    return shell(category, body, "Applications")


@app.route("/blocked")
def blocked():
    start_day = range_start_day()
    rows = query(
        """
        SELECT client, domain, category, COUNT(*) AS total
        FROM dns_querylog
        WHERE day>=? AND blocked=1
        GROUP BY client, domain, category
        ORDER BY total DESC
        LIMIT 200
        """,
        (start_day,),
    )

    table = ""
    for r in rows:
        table += f"""
<tr>
  <td><a href="/device/{r['client']}">{r['client']}</a></td>
  <td>{icon_for_app(r['category'])} {r['domain']}</td>
  <td>{r['category']}</td>
  <td>{r['total']}</td>
</tr>
"""

    body = f"""
{topbar('Blocked DNS')}
{time_picker()}
<div class="panel">
<table>
<tr><th>Client</th><th>Domain</th><th>Category</th><th>Blocked</th></tr>
{table or '<tr><td colspan="4">No blocked records yet</td></tr>'}
</table>
</div>
"""
    return shell("Blocked", body, "Blocked")


@app.route("/blocked-services")
def blocked_services():
    start_day = range_start_day()
    sort = request.args.get("sort", "blocked")
    direction = request.args.get("dir", "desc")
    sort_map = {
        "service": "category COLLATE NOCASE",
        "activity": "total",
        "devices": "devices",
        "domains": "domains",
        "blocked": "total",
        "last": "last_seen",
    }
    sort_col = sort_map.get(sort, "total")
    direction_sql = "ASC" if direction == "asc" else "DESC"
    rows = query(
        f"""
        SELECT
            category,
            COUNT(*) AS total,
            COUNT(DISTINCT client) AS devices,
            COUNT(DISTINCT domain) AS domains,
            MAX(ts) AS last_seen
        FROM dns_querylog
        WHERE day>=? AND blocked=1
        GROUP BY category
        ORDER BY {sort_col} {direction_sql}, category COLLATE NOCASE ASC
        LIMIT 100
        """,
        (start_day,),
    )

    def sort_link(label, key):
        next_dir = "desc"
        marker = ""
        if sort == key:
            next_dir = "asc" if direction == "desc" else "desc"
            marker = " v" if direction == "desc" else " ^"
        return f'<a class="sort-link" href="/blocked-services?range={range_key()}&sort={h(key)}&dir={next_dir}">{h(label)}{marker}</a>'

    max_count = max([int(r["total"] or 1) for r in rows], default=1)
    table = ""
    for r in rows:
        total = int(r["total"] or 0)
        width = max(5, min(total / max_count * 100, 100))
        href = "/blocked?range=" + range_key()
        table += f"""
<tr onclick="location.href='{href}'">
  <td>{icon_for_app(r['category'])} <b>{h(r['category'])}</b></td>
  <td><div class="bar table-bar"><div style="width:{width}%"></div></div></td>
  <td>{int(r['devices'] or 0):,}</td>
  <td>{int(r['domains'] or 0):,}</td>
  <td><b>{total:,}</b></td>
  <td>{h(r['last_seen'])}</td>
</tr>
"""

    body = f"""
{topbar('Blocked Services')}
{time_picker()}
<div class="panel">
<table>
<tr><th>{sort_link('Service', 'service')}</th><th>{sort_link('Activity', 'activity')}</th><th>{sort_link('Devices', 'devices')}</th><th>{sort_link('Domains', 'domains')}</th><th>{sort_link('Blocked', 'blocked')}</th><th>{sort_link('Last Seen', 'last')}</th></tr>
{table or '<tr><td colspan="6">No blocked services recorded.</td></tr>'}
</table>
</div>
"""
    return shell("Blocked Services", body, "Services")


@app.route("/map")
def network_map():
    c = cfg()
    rows = query(
        """
        SELECT r.remote_ip, r.category, l.city, l.region, l.country, l.latitude, l.longitude,
               SUM(r.downloaded_mb) AS downloaded_mb,
               SUM(r.uploaded_mb) AS uploaded_mb,
               SUM(r.total_mb) AS total_mb,
               COUNT(DISTINCT r.ip) AS devices
        FROM remote_traffic_intervals r
        JOIN remote_ip_locations l ON l.remote_ip = r.remote_ip
        WHERE r.day >= ? AND l.latitude IS NOT NULL AND l.longitude IS NOT NULL
        GROUP BY r.remote_ip, r.category, l.city, l.region, l.country, l.latitude, l.longitude
        ORDER BY SUM(r.total_mb) DESC
        LIMIT 250
        """,
        (range_start_day(),),
    )
    points = [
        {
            "ip": h(r["remote_ip"]),
            "category": h(r["category"]),
            "location": h(", ".join(x for x in (r["city"], r["region"], r["country"]) if x)),
            "latitude": float(r["latitude"]),
            "longitude": float(r["longitude"]),
            "downloaded": float(r["downloaded_mb"] or 0),
            "uploaded": float(r["uploaded_mb"] or 0),
            "total": float(r["total_mb"] or 0),
            "devices": int(r["devices"] or 0),
        }
        for r in rows
    ]
    points_json = json.dumps(points).replace("</", "<\\/")
    destination_rows = "".join(
        f"""
<tr>
  <td>{h(r['category'])}<br><span>{h(r['remote_ip'])}</span></td>
  <td>{h(', '.join(x for x in (r['city'], r['region'], r['country']) if x))}</td>
  <td>{int(r['devices'] or 0)}</td>
  <td>{fmt_mb(r['downloaded_mb'])}</td>
  <td>{fmt_mb(r['uploaded_mb'])}</td>
  <td><b>{fmt_mb(r['total_mb'])}</b></td>
</tr>"""
        for r in rows[:12]
    )

    body = f"""
{topbar('Network Map')}
<div class="map-flow compact-topology">
  <div class="map-node"><i class="fa-solid fa-globe"></i><b>Internet</b><span>WAN</span></div>
  <div class="map-line"></div>
  <div class="map-node"><i class="fa-solid fa-shield-halved"></i><b>NetSpecter Bridge</b><span>{h(c.get('packet_iface', 'br0'))}</span></div>
  <div class="map-line"></div>
  <div class="map-node"><i class="fa-solid fa-network-wired"></i><b>LAN</b><span>{h(c.get('lan_prefix'))}0/24</span></div>
</div>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin="">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>
<div class="panel destination-map-panel">
  <div class="destination-map-heading">
    <div>
      <h2>Monitored App Destinations</h2>
      <p>Approximate destination locations for monitored app traffic only. Locations are cached and refreshed at most hourly.</p>
    </div>
    <div class="map-legend"><span class="download-dot"></span> Download heavy <span class="upload-dot"></span> Upload heavy</div>
  </div>
  <div id="destinationMap"></div>
  <p class="map-empty" id="mapEmpty" style="display:none">Pins appear after monitored app delivery traffic is measured and its remote IP location is cached.</p>
</div>
<div class="panel">
  <h2>Top Mapped Destinations</h2>
  <table>
    <tr><th>Application / IP</th><th>Approximate Location</th><th>Devices</th><th>Download</th><th>Upload</th><th>Total</th></tr>
    {destination_rows or '<tr><td colspan="6">No mapped monitored-app traffic yet.</td></tr>'}
  </table>
</div>
<script>
const destinationPoints = {points_json};
const destinationMap = L.map("destinationMap", {{worldCopyJump: true, minZoom: 2}}).setView([15, 10], 2);
L.tileLayer("https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png", {{
  maxZoom: 18,
  attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
}}).addTo(destinationMap);
const markerBounds = [];
destinationPoints.forEach((point) => {{
  const downloadHeavy = point.downloaded >= point.uploaded;
  const color = downloadHeavy ? "#5ba8ff" : "#20df9f";
  const radius = Math.min(28, 6 + Math.sqrt(Math.max(point.total, 0)) * 1.7);
  L.circleMarker([point.latitude, point.longitude], {{
    radius: radius, color: color, weight: 2, fillColor: color, fillOpacity: 0.56
  }}).addTo(destinationMap).bindPopup(
    "<b>" + point.category + "</b><br>" + point.location + "<br>" + point.ip +
    "<br>Download: " + point.downloaded.toFixed(2) + " MB" +
    "<br>Upload: " + point.uploaded.toFixed(2) + " MB" +
    "<br>Total: " + point.total.toFixed(2) + " MB" +
    "<br>Devices: " + point.devices
  );
  markerBounds.push([point.latitude, point.longitude]);
}});
if (markerBounds.length) {{
  destinationMap.fitBounds(markerBounds, {{padding: [28, 28], maxZoom: 6}});
}} else {{
  document.getElementById("mapEmpty").style.display = "block";
}}
</script>
"""
    return shell("Network Map", body, "Map")


def csv_response(filename, headers, rows):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(headers)
    for row in rows:
        values = []
        for hh in headers:
            try:
                values.append(row[hh])
            except Exception:
                values.append("")
        writer.writerow(values)
    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/exports")
def exports_page():
    body = f"""
{topbar('Exports')}
{time_picker()}
<div class="grid">
  <a class="card" href="/export/devices"><div class="label">Devices</div><span class="big blue">CSV</span><small>Names, IPs, vendors, status</small></a>
  <a class="card" href="/export/traffic?range={range_key()}"><div class="label">Traffic</div><span class="big teal">CSV</span><small>Usage for selected range</small></a>
  <a class="card" href="/export/dns?range={range_key()}"><div class="label">DNS Logs</div><span class="big purple">CSV</span><small>Queries for selected range</small></a>
  <a class="card" href="/export/blocked?range={range_key()}"><div class="label">Blocked DNS</div><span class="big red">CSV</span><small>Blocked rows for selected range</small></a>
</div>
"""
    return shell("Exports", body, "Exports")


@app.route("/export/<kind>")
def export_csv(kind):
    start_day = range_start_day()
    if kind == "devices":
        rows = query(
            """
            SELECT
                d.ip, COALESCE(o.name, d.name) AS name, d.mac,
                COALESCE(o.vendor, d.vendor) AS vendor,
                COALESCE(o.device_type, d.device_type) AS device_type,
                COALESCE(o.status, d.status) AS status,
                d.first_seen, d.last_seen
            FROM devices d
            LEFT JOIN device_overrides o ON o.ip=d.ip
            ORDER BY d.ip
            """
        )
        headers = ["ip", "name", "mac", "vendor", "device_type", "status", "first_seen", "last_seen"]
        return csv_response("netspecter-devices.csv", headers, rows)

    if kind == "traffic":
        rows = query(
            """
            SELECT
                ip,
                MAX(name) AS name,
                MAX(mac) AS mac,
                SUM(downloaded_mb) AS downloaded_mb,
                SUM(uploaded_mb) AS uploaded_mb,
                SUM(total_mb) AS total_mb,
                MAX(live_bps) AS live_bps,
                day,
                MAX(ts) AS ts
            FROM traffic_intervals
            WHERE day>=?
            GROUP BY day, ip
            ORDER BY ts DESC
            """,
            (start_day,),
        )
        headers = ["ip", "name", "mac", "downloaded_mb", "uploaded_mb", "total_mb", "live_bps", "day", "ts"]
        return csv_response("netspecter-traffic.csv", headers, rows)

    if kind == "dns":
        rows = query(
            """
            SELECT day, ts, client, domain, blocked, category
            FROM dns_querylog
            WHERE day>=?
            ORDER BY ts DESC
            LIMIT 20000
            """,
            (start_day,),
        )
        headers = ["day", "ts", "client", "domain", "blocked", "category"]
        return csv_response("netspecter-dns.csv", headers, rows)

    if kind == "blocked":
        rows = query(
            """
            SELECT day, ts, client, domain, blocked, category
            FROM dns_querylog
            WHERE day>=? AND blocked=1
            ORDER BY ts DESC
            LIMIT 20000
            """,
            (start_day,),
        )
        headers = ["day", "ts", "client", "domain", "blocked", "category"]
        return csv_response("netspecter-blocked.csv", headers, rows)

    return redirect("/exports")


@app.route("/health")
def health_page():
    c = cfg()
    health = system_health()
    ok_adguard, _ = ag_get("/status")
    bridge_ok = False
    if psutil:
        try:
            bridge_ok = str(c.get("packet_iface", "br0")) in psutil.net_if_addrs()
        except Exception:
            bridge_ok = False

    services = [
        ("Collector", health["collector_state"] == "OK", health["last_seen"]),
        ("AdGuard API", ok_adguard, c.get("adguard_url", "")),
        ("Bridge Interface", bridge_ok, c.get("packet_iface", "br0")),
        ("Database", DB_PATH.exists(), f"{health['db_size']} MB"),
        ("Web App", True, "Online"),
    ]
    cards = ""
    for name, ok, detail in services:
        cards += f"""
<div class="card">
  <div class="label">{h(name)}</div>
  <span class="big {'green' if ok else 'red'}">{'OK' if ok else 'Check'}</span>
  <small>{h(detail)}</small>
</div>
"""
    body = f"""
{topbar('Service Health')}
<div class="grid">{cards}</div>
"""
    return shell("Service Health", body, "Health")



def ag_enabled(endpoint):
    ok, data = ag_get(endpoint)
    if ok and isinstance(data, dict):
        return data.get("enabled")
    return None

def toggle_card(label, enabled, on_action, off_action, icon, color="green"):
    if enabled is None:
        txt = "Unknown"
        action = ""
        cls = "yellow"
    elif enabled:
        txt = "ON"
        action = off_action
        cls = color
    else:
        txt = "OFF"
        action = on_action
        cls = "red"
    if not action:
        return f"""
<div class="card">
  <div class="label">{icon} {label}</div>
  <span class="big {cls}">{txt}</span>
</div>
"""
    return f"""
<form class="card" method="post" action="/adguard/action">
  {csrf_input()}
  <input type="hidden" name="action" value="{h(action)}">
  <button type="submit" style="background:none; border:0; padding:0; margin:0; width:100%; min-height:82px; text-align:left; color:inherit;">
    <div class="label">{icon} {label}</div>
    <span class="big {cls}">{txt}</span>
  </button>
</form>
"""

@app.route("/adguard")
def adguard():
    ok_status, status = ag_get("/status")
    ok_stats, stats = ag_get("/stats")

    protection = status.get("protection_enabled") if isinstance(status, dict) else None
    safe_browsing = ag_enabled("/safebrowsing/status")
    parental = ag_enabled("/parental/status")
    safe_search = ag_enabled("/safesearch/status")
    c = cfg()

    body = f"""
{topbar('AdGuard Control')}

<div class="grid">
  <div class="card"><div class="label">API Status</div><span class="big {'green' if ok_status else 'red'}">{'Online' if ok_status else 'Offline'}</span></div>
  <div class="card"><div class="label">DNS Queries</div><span class="big blue">{stats.get('num_dns_queries','-') if ok_stats else '-'}</span></div>
  <div class="card"><div class="label">Blocked</div><span class="big red">{stats.get('num_blocked_filtering','-') if ok_stats else '-'}</span></div>
  {toggle_card("Protection", protection, "protection_on", "protection_off", "Shield")}
  {toggle_card("Parental", parental, "parental_on", "parental_off", "Family", "yellow")}
  {toggle_card("Safe Browsing", safe_browsing, "safebrowsing_on", "safebrowsing_off", "Web")}
  {toggle_card("Safe Search", safe_search, "safesearch_on", "safesearch_off", "Search")}
  <a class="card" href="{c.get('adguard_url')}" target="_blank"><div class="label">Open AdGuard</div><span class="big green">Launch</span></a>
  <a class="card" href="{c.get('adguard_url')}/#blocked_services" target="_blank"><div class="label">Blocked Services</div><span class="big red">Open</span></a>
</div>

<div class="panel">
<h2>Quick Controls</h2>
<form method="post" action="/adguard/action">
  {csrf_input()}
  <button name="action" value="cache_clear">Clear Cache</button>
  <button name="action" value="filter_refresh">Refresh Filters</button>
</form>
</div>
"""
    return shell("AdGuard", body, "AdGuard")


@app.route("/adguard/action", methods=["POST"])
def adguard_action():
    action = request.form.get("action", "")

    mapping = {
        "protection_on": ("/protection", {"enabled": True, "duration": 0}),
        "protection_off": ("/protection", {"enabled": False, "duration": 0}),
        "cache_clear": ("/cache_clear", {}),
        "filter_refresh": ("/filtering/refresh", {"force": True}),
        "safebrowsing_on": ("/safebrowsing/enable", None),
        "safebrowsing_off": ("/safebrowsing/disable", None),
        "parental_on": ("/parental/enable", None),
        "parental_off": ("/parental/disable", None),
        "safesearch_on": ("/safesearch/enable", None),
        "safesearch_off": ("/safesearch/disable", None),
    }

    if action in mapping:
        endpoint, payload = mapping[action]
        ag_post(endpoint, payload)

    return redirect("/adguard")


def unifi_client_endpoint(config):
    base = str(config.get("unifi_connector_url", "") or "").strip().rstrip("/")
    site_id = quote(str(config.get("unifi_site_id", "") or "").strip(), safe="")
    if not base or not site_id:
        return ""
    return f"{base}/v1/sites/{site_id}/clients?offset=0&limit=1"


def unifi_json_response(result):
    content_type = str(result.headers.get("Content-Type", "") or "").lower()
    try:
        return result.json(), ""
    except ValueError:
        detail = "UniFi returned an empty response." if not result.text.strip() else "UniFi returned a non-JSON response."
        if "application/json" not in content_type:
            detail += " Check that this console supports the Network API connector (UniFi OS firmware 5.0.3 or newer)."
        return None, detail


def find_unifi_site(config):
    base = str(config.get("unifi_connector_url", "") or "").strip().rstrip("/")
    api_key = str(config.get("unifi_api_key", "") or "").strip()
    if not base or not api_key:
        return False, "Enter the Connector URL and API key first."
    try:
        result = requests.get(
            f"{base}/v1/sites",
            params={"offset": 0, "limit": 100},
            headers={"Accept": "application/json", "X-API-Key": api_key},
            timeout=12,
        )
        if result.status_code != 200:
            return False, f"UniFi API returned HTTP {result.status_code}. Check the API key."
        payload, response_error = unifi_json_response(result)
        if response_error:
            return False, response_error
        sites = payload.get("data", []) if isinstance(payload, dict) else []
        if not sites:
            return False, "UniFi connected, but it returned no Network sites."
        preferred = next(
            (site for site in sites if str(site.get("name", "")).strip().lower() == "default"),
            sites[0] if len(sites) == 1 else None,
        )
        if not preferred or not preferred.get("id"):
            names = ", ".join(str(site.get("name", "Unnamed")) for site in sites)
            return False, f"Multiple sites found ({names}). Select the correct site ID manually."
        config["unifi_site_id"] = str(preferred["id"]).strip()
        return True, f"Found UniFi site: {preferred.get('name', 'Default')}. Site ID saved."
    except Exception as error:
        return False, f"UniFi site lookup failed: {error}"


def check_unifi_connection(config):
    if not config.get("unifi_enabled"):
        return False, "UniFi integration is disabled."
    endpoint = unifi_client_endpoint(config)
    api_key = str(config.get("unifi_api_key", "") or "").strip()
    if not endpoint or not api_key:
        return False, "Enter the Connector URL, site ID, and API key first."
    try:
        result = requests.get(
            endpoint,
            headers={"Accept": "application/json", "X-API-Key": api_key},
            timeout=12,
        )
        if result.status_code == 200:
            payload, response_error = unifi_json_response(result)
            if response_error:
                return False, response_error
            count = payload.get("totalCount", payload.get("count", 0)) if isinstance(payload, dict) else 0
            return True, f"Connected. UniFi reports {int(count or 0)} connected client(s)."
        return False, f"UniFi API returned HTTP {result.status_code}."
    except Exception as error:
        return False, f"UniFi connection failed: {error}"


@app.route("/integrations", methods=["GET", "POST"])
def integrations():
    c = cfg()
    notice = ""
    notice_class = "setup-ok"
    if request.method == "POST":
        c["unifi_enabled"] = request.form.get("unifi_enabled") == "1"
        c["unifi_connector_url"] = request.form.get("unifi_connector_url", "").strip()
        c["unifi_site_id"] = request.form.get("unifi_site_id", "").strip()
        api_key = request.form.get("unifi_api_key", "")
        if api_key:
            c["unifi_api_key"] = api_key
        if request.form.get("clear_unifi_key") == "1":
            c["unifi_api_key"] = ""
        try:
            c["scheduled_speedtests_per_day"] = min(5, max(0, int(request.form.get("scheduled_speedtests_per_day", "0"))))
        except ValueError:
            c["scheduled_speedtests_per_day"] = 0
        save_cfg(c)
        restart_collector_service()
        action = request.form.get("action")
        if action == "find_unifi_site":
            ok, notice = find_unifi_site(c)
            if ok:
                save_cfg(c)
                restart_collector_service()
            notice_class = "setup-ok" if ok else "setup-warning"
        elif action == "test_unifi":
            ok, notice = check_unifi_connection(c)
            notice_class = "setup-ok" if ok else "setup-warning"
        else:
            notice = "Integration options saved. The collector has restarted."

    enabled_checked = " checked" if c.get("unifi_enabled") else ""
    schedule_options = "".join(
        f'<option value="{number}"{" selected" if int(c.get("scheduled_speedtests_per_day", 0) or 0) == number else ""}>{number if number else "Off"}</option>'
        for number in range(0, 6)
    )
    notice_html = f'<div class="{notice_class}">{h(notice)}</div>' if notice else ""
    body = f"""
{topbar('Integrations')}
{notice_html}
<div class="panel settings">
  <h2>UniFi Device Discovery (Optional)</h2>
  <p>Enable this only if you own a UniFi console. It imports connected client names, IP addresses and MAC addresses so Devices can include UniFi clients even when their traffic does not cross NetSpecter.</p>
  <form method="post">
    {csrf_input()}
    <label><input type="checkbox" name="unifi_enabled" value="1" style="width:auto"{enabled_checked}> Enable UniFi Device Discovery</label>
    <label>UniFi Connector URL</label>
    <input name="unifi_connector_url" value="{h(c.get('unifi_connector_url', ''))}" placeholder="https://api.ui.com/v1/connector/consoles/CONSOLE-ID/proxy/network/integration">
    <small>Use the Network API connector URL for your console, without the site or clients part.</small>
    <label>UniFi Site ID</label>
    <input name="unifi_site_id" value="{h(c.get('unifi_site_id', ''))}" placeholder="Your UniFi site ID">
    <small>Leave this blank and use Find Site Automatically after entering your API key.</small>
    <label>UniFi API Key</label>
    <input name="unifi_api_key" type="password" placeholder="Leave blank to keep saved API key">
    <small>The API key is encrypted in NetSpecter's local config and is never written to GitHub.</small>
    <label><input type="checkbox" name="clear_unifi_key" value="1" style="width:auto"> Clear saved UniFi API key</label>

    <h2 style="margin-top:28px;">Speed Test History (Optional)</h2>
    <p>Manual speed tests are always stored. Scheduled tests consume internet data, so automatic runs are off unless you enable them here.</p>
    <label>Automatic Speed Tests Per Day</label>
    <select name="scheduled_speedtests_per_day">{schedule_options}</select>
    <small>Select up to 5 tests per day, spread across daytime and evening hours.</small>
    <button type="submit" name="action" value="save">Save Options</button>
    <button type="submit" name="action" value="find_unifi_site">Find Site Automatically</button>
    <button type="submit" name="action" value="test_unifi">Save and Test UniFi</button>
  </form>
</div>
"""
    return shell("Integrations", body, "Integrations")


@app.route("/settings", methods=["GET", "POST"])
def settings():
    c = cfg()

    if request.method == "POST":
        for key in list(c.keys()):
            if key == "admin_password_hash":
                continue
            if key in request.form:
                val = request.form.get(key)
                if key in SENSITIVE_CONFIG_KEYS and val == "":
                    continue
                if isinstance(c[key], bool):
                    val = str(val).strip().lower() in ["1", "true", "yes", "on"]
                elif isinstance(c[key], int):
                    try:
                        val = int(val)
                    except Exception:
                        pass
                elif isinstance(c[key], list):
                    val = cfg_list(val)
                c[key] = val

        new_password = request.form.get("admin_new_password", "")
        confirm_password = request.form.get("admin_confirm_password", "")
        if new_password:
            if len(new_password) >= 8 and new_password == confirm_password:
                c["admin_password_hash"] = generate_password_hash(new_password)

        c["app_name"] = "NetSpecter"
        c["tagline"] = "Monitor | Filter | Protect"

        save_cfg(c)
        restart_collector_service()
        return redirect("/settings?saved=1&collector=restarted")

    setting_help = {
        "gateway_ip": "Router/gateway IP. Leave blank to use LAN Prefix + 1. NetSpecter excludes it from device usage totals and live collector stats.",
        "ignore_ips": "Extra IPs to ignore, separated by commas. The gateway IP is always ignored automatically.",
        "packet_iface": "Bridge carrying monitored traffic, usually br0. Linux nftables counts forwarded bytes on this bridge.",
        "lan_prefix": "LAN prefix used to identify local devices, for example 192.168.1.",
        "adguard_url": "AdGuard Home URL used for DNS stats and controls.",
        "collect_interval_seconds": "Seconds between measured traffic interval writes. Live speed freshness follows this value.",
        "traffic_retention_days": "Number of calendar days of measured traffic history to keep. Use 30 for the 30-day view.",
        "dns_retention_days": "Number of calendar days of imported DNS/application activity to keep.",
        "auth_enabled": "Enable or disable the NetSpecter login screen.",
        "admin_user": "Username used to sign in to NetSpecter.",
    }
    setting_labels = {
        "gateway_ip": "Gateway IP",
        "ignore_ips": "Extra Ignored IPs",
        "packet_iface": "Monitored Bridge Interface",
        "lan_prefix": "LAN Prefix",
        "adguard_url": "AdGuard URL",
        "adguard_user": "AdGuard User",
        "adguard_pass": "AdGuard Password",
        "collect_interval_seconds": "Traffic Sample Interval Seconds",
        "traffic_retention_days": "Traffic Retention Days",
        "dns_retention_days": "DNS/App Retention Days",
        "web_host": "Web Host",
        "web_port": "Web Port",
        "auth_enabled": "Login Enabled",
        "admin_user": "Admin Username",
    }
    preferred_order = [
        "gateway_ip", "ignore_ips", "lan_prefix", "packet_iface",
        "adguard_url", "adguard_user", "adguard_pass", "adguard_querylog_interval_seconds",
        "collect_interval_seconds", "traffic_retention_days", "dns_retention_days",
        "web_host", "web_port",
        "auth_enabled", "admin_user",
    ]
    ordered_keys = [k for k in preferred_order if k in c] + [k for k in c.keys() if k not in preferred_order]

    fields = ""
    for key in ordered_keys:
        val = c[key]
        if key in ["app_name", "tagline", "admin_password_hash"] or key in INTEGRATION_SETTINGS_KEYS:
            continue
        typ = "password" if "pass" in key else "text"
        display_val = "" if key in SENSITIVE_CONFIG_KEYS else ", ".join(val) if isinstance(val, list) else val
        help_text = f"<small>{h(setting_help[key])}</small>" if key in setting_help else ""
        placeholder = " placeholder='Leave blank to keep existing password'" if key in SENSITIVE_CONFIG_KEYS else ""
        fields += f"<label>{h(setting_labels.get(key, key))}</label><input type='{typ}' name='{key}' value='{h(display_val)}'{placeholder}>{help_text}"

    fields += """
<label>New Admin Password</label>
<input type="password" name="admin_new_password" placeholder="Leave blank to keep current login password">
<small>Use this to change the NetSpecter login password. Minimum 8 characters.</small>
<label>Confirm New Admin Password</label>
<input type="password" name="admin_confirm_password" placeholder="Repeat new login password">
"""

    body = f"""
{topbar('Settings')}
<div class="panel settings">
{setup_banner()}
<form method="post">
{csrf_input()}
{fields}
<button>Save Settings</button>
</form>
<p class="green">Settings save now automatically restarts the collector service.</p>
</div>
"""
    return shell("Settings", body, "Settings")


def parse_speedtest_metrics(output):
    def value(pattern):
        match = re.search(pattern, output or "", re.IGNORECASE)
        return float(match.group(1)) if match else None
    return (
        value(r"Latency:\s*([0-9.]+)\s*ms"),
        value(r"Download:\s*([0-9.]+)\s*Mbps"),
        value(r"Upload:\s*([0-9.]+)\s*Mbps"),
    )


def run_and_store_speedtest(source="manual"):
    success = False
    try:
        speedtest_env = os.environ.copy()
        speedtest_env.setdefault("HOME", "/root")
        speedtest_env.setdefault("LANG", "C.UTF-8")
        speedtest_env.setdefault("LC_ALL", "C.UTF-8")
        result = subprocess.run(
            ["/usr/bin/speedtest", "--accept-license", "--accept-gdpr"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
            env=speedtest_env,
        )
        output = (result.stdout or "").strip() or "Speed test returned no output."
        if result.returncode != 0:
            output = f"Speed test failed (exit {result.returncode}).\n{output}"
        else:
            success = True
    except FileNotFoundError:
        output = "The official Ookla speedtest client is not installed. Re-run the NetSpecter installer to install it."
    except subprocess.TimeoutExpired:
        output = "Speed test timed out after 120 seconds."
    except Exception as error:
        output = f"Speed test could not run: {error}"
    latency, download, upload = parse_speedtest_metrics(output)
    run_sql(
        """
        INSERT INTO speed_tests (ts, source, latency_ms, download_mbps, upload_mbps, result_text, success)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), source, latency, download, upload, output, 1 if success else 0),
    )
    return output


@app.route("/speed-test", methods=["POST"])
def speed_test():
    """Run an administrator-triggered speed test and store its result."""
    run_and_store_speedtest("manual")
    return redirect("/speed-tests?ran=1")


@app.route("/speed-tests")
def speed_tests():
    rows = query(
        """
        SELECT ts, source, latency_ms, download_mbps, upload_mbps, result_text, success
        FROM speed_tests
        ORDER BY ts DESC
        LIMIT 100
        """
    )
    recent = list(reversed(rows[:30]))
    chart_labels = json.dumps([r["ts"][5:16] for r in recent])
    chart_download = json.dumps([r["download_mbps"] for r in recent])
    chart_upload = json.dumps([r["upload_mbps"] for r in recent])
    latest = rows[0] if rows else None
    schedule_count = int(cfg().get("scheduled_speedtests_per_day", 0) or 0)
    table = ""
    for r in rows[:30]:
        latency_text = f"{r['latency_ms']:.2f} ms" if r["latency_ms"] is not None else "-"
        download_text = f"{r['download_mbps']:.2f} Mbps" if r["download_mbps"] is not None else "-"
        upload_text = f"{r['upload_mbps']:.2f} Mbps" if r["upload_mbps"] is not None else "-"
        table += f"""
<tr>
  <td>{h(r['ts'])}</td>
  <td>{h(str(r['source']).title())}</td>
  <td>{h(latency_text)}</td>
  <td>{h(download_text)}</td>
  <td>{h(upload_text)}</td>
  <td><span class="{'green' if r['success'] else 'red'}">{'OK' if r['success'] else 'Failed'}</span></td>
</tr>
"""
    latest_download = f"{latest['download_mbps']:.2f} Mbps" if latest and latest["download_mbps"] is not None else "-"
    latest_upload = f"{latest['upload_mbps']:.2f} Mbps" if latest and latest["upload_mbps"] is not None else "-"
    latest_latency = f"{latest['latency_ms']:.2f} ms" if latest and latest["latency_ms"] is not None else "-"
    notice = '<div class="setup-ok">Speed test completed and saved.</div>' if request.args.get("ran") == "1" else ""

    body = f"""
{topbar('Speed Test History')}
{notice}
<div class="grid">
  <div class="card"><div class="label">Latest Download</div><span class="big blue">{h(latest_download)}</span></div>
  <div class="card"><div class="label">Latest Upload</div><span class="big purple">{h(latest_upload)}</span></div>
  <div class="card"><div class="label">Latest Latency</div><span class="big teal">{h(latest_latency)}</span></div>
  <div class="card"><div class="label">Automatic Tests</div><span class="big {'green' if schedule_count else 'yellow'}">{schedule_count if schedule_count else 'Off'}</span><small>{'per day' if schedule_count else 'Enable in Integrations'}</small></div>
</div>
<div class="panel">
  <h2>Internet Speed History</h2>
  <p>Tests transfer data over your internet connection. Automatic tests are optional and configured under <a href="/integrations">Integrations</a>.</p>
  <form method="post" action="/speed-test">
    {csrf_input()}
    <button type="submit">Run Speed Test Now</button>
  </form>
  <canvas id="speedHistoryChart" height="88"></canvas>
</div>
<div class="panel">
  <h2>Recent Results</h2>
  <table>
    <tr><th>Time</th><th>Source</th><th>Latency</th><th>Download</th><th>Upload</th><th>Status</th></tr>
    {table or '<tr><td colspan="6">No saved speed tests yet.</td></tr>'}
  </table>
</div>
<script>
const speedCtx = document.getElementById('speedHistoryChart');
if (speedCtx) {{
  new Chart(speedCtx, {{
    type: 'line',
    data: {{
      labels: {chart_labels},
      datasets: [
        {{label: 'Download Mbps', data: {chart_download}, borderColor: '#5ba8ff', tension: .25}},
        {{label: 'Upload Mbps', data: {chart_upload}, borderColor: '#a68bff', tension: .25}}
      ]
    }},
    options: {{responsive:true, plugins:{{legend:{{labels:{{color:'#d7e6f5'}}}}}}, scales:{{x:{{ticks:{{color:'#9aa7bb'}}}}, y:{{ticks:{{color:'#9aa7bb'}}}}}}}}
  }});
}}
</script>
"""
    return shell("Speed Test History", body, "Speed Tests")


@app.route("/system")
def system():
    health = system_health()
    c = cfg()

    body = f"""
{topbar('System')}

<div class="grid">
  <div class="card"><div class="label">CPU</div><span class="big blue">{health['cpu']}%</span></div>
  <div class="card"><div class="label">Memory</div><span class="big purple">{health['mem']}%</span></div>
  <div class="card"><div class="label">Disk / HDD</div><span class="big {'red' if health['disk'] > 85 else 'green'}">{health['disk']}%</span></div>
  <div class="card"><div class="label">Database</div><span class="big teal">{health['db_size']} MB</span></div>
  <div class="card"><div class="label">Collector</div><span class="big {'green' if health['collector_state'] == 'OK' else 'yellow'}">{health['collector_state']}</span></div>
  <div class="card"><div class="label">Uptime</div><span class="big">{health['uptime']}</span></div>
</div>

<div class="panel">
<p><b>Last collector sample:</b> {health['last_seen']}</p>
<p><b>Database:</b> {DB_PATH}</p>
<p><b>Public IP cache:</b> {public_ip()}</p>
<p><b>Web listener:</b> {h(c.get('web_host', '0.0.0.0'))}:{h(c.get('web_port', 5050))}</p>
</div>
"""
    return shell("System", body, "System")


@app.errorhandler(Exception)
def handle_uncaught_error(error):
    if isinstance(error, HTTPException):
        return error

    print(f"Unhandled dashboard error: {error}")
    body = f"""
{topbar('System')}
<div class="panel">
  <h2>NetSpecter hit a recoverable error</h2>
  <p>The dashboard stayed online, but this page could not finish loading.</p>
  <p><b>Error:</b> {h(error)}</p>
  <p><a href="/system">Open System Health</a></p>
</div>
"""
    return shell("Recoverable Error", body, "System"), 500


if __name__ == "__main__":
    init_db()
    c = cfg()
    app.run(
        host=str(c.get("web_host", "0.0.0.0") or "0.0.0.0"),
        port=int(c.get("web_port", 5050) or 5050),
    )
