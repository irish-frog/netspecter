#!/usr/bin/env python3
"""
NetSpecter Live Packet Collector

What this file does:
- Installs private nftables bridge counters for each LAN device IP.
- Reads accurate kernel-counted upload and download byte differences.
- Calculates live speed per device.
- Saves live speed into SQLite.
- Saves device details like IP, MAC, vendor and type.
- Saves measured traffic bytes for each collection interval.
- Ignores the gateway/router so it does not appear as the top user.
- Imports AdGuard Home DNS querylog into dns_querylog.
- Imports AdGuard Home client names for friendly device labels.
- Classifies domains into application categories for Top Applications.
- Estimates bytes for selected apps from device-specific delivery DNS answers.

Important:
- Speeds in live_device_speed are stored as BYTES per second.
- live_bps in traffic_intervals is stored as BITS per second.
- dns_querylog powers Top Applications and per-device application views.
"""

import atexit
import fcntl
import ipaddress
import json
import os
import re
import signal
import smtplib
import sqlite3
import ssl
import subprocess
import threading
import time
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import quote

import requests

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None
    InvalidToken = Exception


# ---------------------------------------------------
# File paths
# ---------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent


def configured_path(env_name, default_path, local_path):
    override = os.environ.get(env_name)
    if override:
        return Path(override)

    default = Path(default_path)
    if default.exists() or default.parent.exists():
        return default

    return Path(local_path)


CONFIG_DIR = configured_path("NETSPECTER_CONFIG_ROOT", "/etc/netspecter", BASE_DIR)
DATA_DIR = configured_path("NETSPECTER_DATA_ROOT", "/var/lib/netspecter", BASE_DIR)
CONFIG_PATH = CONFIG_DIR / "config.json"
DB_PATH = DATA_DIR / "netspecter.db"
OUI_PATH = DATA_DIR / "oui_cache.json"
SYSTEM_OUI_PATH = Path("/usr/share/ieee-data/oui.txt")
SECRET_KEY_PATH = CONFIG_DIR / "secret.key"
COLLECTOR_LOCK_PATH = DATA_DIR / "collector.lock"
SURICATA_FAST_LOG = Path("/var/log/suricata/fast.log")
IDS_EMAIL_STATE_PATH = DATA_DIR / "ids_email_state.json"
ENCRYPTED_PREFIX = "enc:"
SENSITIVE_CONFIG_KEYS = {"adguard_pass", "unifi_api_key", "smtp_password"}
collector_lock_handle = None


# ---------------------------------------------------
# Default settings
# ---------------------------------------------------
# packet_iface:
#   The bridge whose forwarded device traffic is counted by nftables.
#   Example: br0.
#
# ignore_ips:
#   IPs excluded from device totals.
#   Usually your gateway/router.
#
# adguard_url/user/pass:
#   Used to pull /control/querylog from AdGuard Home.
#
# adguard_querylog_interval_seconds:
#   How often AdGuard querylog is imported.
# ---------------------------------------------------

DEFAULT_CONFIG = {
    "lan_prefix": "192.168.1.",
    "packet_iface": "br0",
    "collect_interval_seconds": 2,
    "traffic_retention_days": 30,
    "dns_retention_days": 14,
    "gateway_ip": "",
    "ignore_ips": [],

    "adguard_url": "http://127.0.0.1",
    "adguard_user": "admin",
    "adguard_pass": "",
    "adguard_querylog_interval_seconds": 15,
    "unifi_enabled": False,
    "unifi_connector_url": "",
    "unifi_site_id": "",
    "unifi_api_key": "",
    "unifi_skip_tls_verify": False,
    "ids_unknown_only": False,
    "ids_excluded_ips": [],
    "ids_banned_ips": [],
    "ids_email_enabled": False,
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_security": "starttls",
    "smtp_username": "",
    "smtp_password": "",
    "smtp_from": "",
    "smtp_to": "",
    "ids_email_cooldown_minutes": 30,
}


# ---------------------------------------------------
# Kernel counter state
# ---------------------------------------------------

imported_dns_keys = set()
adguard_client_names = {}
adguard_client_names_lock = threading.Lock()
adguard_client_names_refreshed_at = 0.0
unifi_clients_refreshed_at = 0.0
NFT_FAMILY = "bridge"
NFT_TABLE = "netspecter"
NFT_CHAIN = "forward"
nft_config_signature = None
nft_previous_counters = {}
nft_previous_estimated_counters = {}
nft_active_ips = set()
estimated_app_targets = {}
estimated_targets_lock = threading.Lock()
oui_vendor_cache = None
GEOLOCATION_URL = "https://ipwho.is/"
GEOLOCATION_REFRESH_SECONDS = 3600
ADGUARD_CLIENT_REFRESH_SECONDS = 300
UNIFI_CLIENT_REFRESH_SECONDS = 300
MONITORED_APP_DOMAIN_KEYS = {
    "YouTube": ("googlevideo.com",),
    "Netflix": ("nflxvideo.net", "netflix.com"),
    "TikTok": ("tiktokcdn.com", "tiktokv.com", "byteoversea.com"),
    "Facebook": ("fbcdn.net", "facebook.com"),
    "Instagram": ("cdninstagram.com", "instagram.com"),
    "WhatsApp": ("whatsapp.net", "whatsapp.com"),
    "Microsoft": ("teams.microsoft.com", "officecdn.microsoft.com", "windowsupdate.com"),
    "Spotify": ("spotify.com", "scdn.co", "spotifycdn.com"),
    "Steam": ("steamserver.net", "steamcontent.com", "steampowered.com"),
    "Twitter / X": ("twitter.com", "twimg.com", "x.com"),
    "Snapchat": ("snapchat.com", "sc-cdn.net"),
    "Discord": ("discord.com", "discordapp.com", "discordcdn.com"),
    "Twitch": ("twitch.tv", "ttvnw.net"),
    "Disney+": ("disneyplus.com", "dssott.com", "bamgrid.com"),
    "Prime Video": ("primevideo.com", "aiv-cdn.net"),
}


def acquire_collector_lock():
    """Allow only one collector writer to update measured traffic."""
    global collector_lock_handle
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    handle = COLLECTOR_LOCK_PATH.open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        print("Another NetSpecter collector is already running; exiting.")
        return False

    collector_lock_handle = handle
    return True


def load_json(path, default):
    """Safely load a JSON file. If it fails, return the default."""
    try:
        p = Path(path)
        if p.exists():
            return json.loads(p.read_text())
    except Exception as e:
        print(f"JSON load failed for {path}: {e}")

    return default


def cfg():
    """Load config.json and merge it with defaults."""
    data = DEFAULT_CONFIG.copy()
    loaded = load_json(CONFIG_PATH, {})
    if isinstance(loaded, dict):
        data.update(loaded)
    for key in SENSITIVE_CONFIG_KEYS:
        if key in data:
            data[key] = decrypt_config_value(data.get(key))
    return data


def fernet():
    if not Fernet or not SECRET_KEY_PATH.exists():
        return None
    try:
        return Fernet(SECRET_KEY_PATH.read_text().strip().encode())
    except Exception as e:
        print(f"Encryption setup failed: {e}")
        return None


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
    return set(ips)


def ip_identifier(value):
    """Return a normalized device IP, or an empty string for non-IP identifiers."""
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def adguard_name_for_ip(ip):
    with adguard_client_names_lock:
        return adguard_client_names.get(str(ip or "").strip(), "")


def parse_adguard_client_names(payload):
    """Extract client display names from AdGuard persistent and runtime clients."""
    if not isinstance(payload, dict):
        return {}

    names = {}

    def add_name(item, identifiers):
        if not isinstance(item, dict):
            return
        name = str(item.get("name") or "").strip()
        if not name:
            return
        for identifier in identifiers:
            ip = ip_identifier(identifier)
            if ip:
                names[ip] = name

    # Auto-discovered names are useful fallback labels.
    for item in payload.get("auto_clients", []) or []:
        if isinstance(item, dict):
            identifiers = [item.get("ip"), *(item.get("ids") or []), *(item.get("ip_addrs") or [])]
            add_name(item, identifiers)

    # Explicitly configured clients take precedence over runtime discovery.
    for item in payload.get("clients", []) or []:
        if isinstance(item, dict):
            identifiers = [*(item.get("ip_addrs") or []), *(item.get("ids") or [])]
            add_name(item, identifiers)

    return names


def refresh_adguard_client_names(config):
    """Refresh friendly labels infrequently; manual UI overrides remain authoritative."""
    global adguard_client_names, adguard_client_names_refreshed_at
    now_monotonic = time.monotonic()
    if now_monotonic - adguard_client_names_refreshed_at < ADGUARD_CLIENT_REFRESH_SECONDS:
        return

    base = str(config.get("adguard_url", "")).rstrip("/")
    if not base:
        return

    try:
        res = requests.get(
            f"{base}/control/clients",
            auth=(config.get("adguard_user", "admin"), config.get("adguard_pass", "")),
            timeout=10,
        )
        if res.status_code != 200:
            print(f"AdGuard client name import failed: HTTP {res.status_code}")
            return
        names = parse_adguard_client_names(res.json())
    except Exception as e:
        print(f"AdGuard client name import failed: {e}")
        return

    with adguard_client_names_lock:
        adguard_client_names = names
    adguard_client_names_refreshed_at = now_monotonic

    for ip, name in names.items():
        run_sql("UPDATE devices SET name=? WHERE ip=?", (name, ip))
        # Older builds could auto-lock a discovered device while its label was still its IP.
        run_sql(
            """
            UPDATE device_overrides
            SET name=?, updated_at=?
            WHERE ip=? AND (name IS NULL OR TRIM(name)='' OR name=ip)
            """,
            (name, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip),
        )


def remember_adguard_client_activity(client, ts):
    """Create or label DNS-visible IP clients without overwriting manual UI overrides."""
    ip = ip_identifier(client)
    name = adguard_name_for_ip(ip)
    if not ip or not name:
        return
    run_sql(
        """
        INSERT INTO devices (ip, name, status, first_seen, last_seen)
        VALUES (?, ?, 'Active', ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            name=excluded.name,
            last_seen=CASE
                WHEN devices.last_seen IS NULL OR devices.last_seen < excluded.last_seen
                THEN excluded.last_seen
                ELSE devices.last_seen
            END
        """,
        (ip, name, ts, ts),
    )


def unifi_connector_bases(config):
    base = str(config.get("unifi_connector_url", "") or "").strip().rstrip("/")
    if not base:
        return []
    if "/proxy/network/integration" not in base and "/network/integration" in base:
        base = base.replace("/network/integration", "/proxy/network/integration", 1)
    return [base]


def unifi_verify_tls(config):
    verify = not bool(config.get("unifi_skip_tls_verify"))
    if not verify:
        requests.packages.urllib3.disable_warnings()
    return verify


def refresh_unifi_clients(config):
    """Optionally import connected client inventory through the official UniFi API."""
    global unifi_clients_refreshed_at
    if not config.get("unifi_enabled"):
        return
    now_monotonic = time.monotonic()
    if now_monotonic - unifi_clients_refreshed_at < UNIFI_CLIENT_REFRESH_SECONDS:
        return

    bases = unifi_connector_bases(config)
    site_id = quote(str(config.get("unifi_site_id", "") or "").strip(), safe="")
    api_key = str(config.get("unifi_api_key", "") or "").strip()
    if not bases or not site_id or not api_key:
        return

    imported = 0
    named_imported = 0
    offset = 0
    working_base = None
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        while True:
            payload = None
            failure = ""
            for base in ([working_base] if working_base else bases):
                response = requests.get(
                    f"{base}/v1/sites/{site_id}/clients",
                    params={"offset": offset, "limit": 100},
                    headers={"Accept": "application/json", "X-API-Key": api_key},
                    timeout=12,
                    verify=unifi_verify_tls(config),
                )
                if response.status_code != 200:
                    failure = f"HTTP {response.status_code}"
                    continue
                try:
                    payload = response.json()
                    working_base = base
                    break
                except ValueError:
                    failure = "response was not JSON"
            if payload is None:
                print(f"UniFi client import failed: {failure}")
                return
            clients = payload.get("data", []) if isinstance(payload, dict) else []
            if not isinstance(clients, list):
                return
            for client in clients:
                if not isinstance(client, dict):
                    continue
                ip = ip_identifier(client.get("ipAddress"))
                if not ip:
                    continue
                name = str(client.get("name") or ip).strip()
                has_unifi_name = name != ip
                mac = str(client.get("macAddress") or "").strip().upper()
                vendor = vendor_from_mac(mac)
                dtype = classify_device(vendor)
                connected = parse_adguard_time(client.get("connectedAt")) if client.get("connectedAt") else now
                run_sql(
                    """
                    INSERT INTO devices (ip, name, mac, vendor, device_type, status, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, 'Active', ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        name=CASE WHEN excluded.name != excluded.ip THEN excluded.name ELSE devices.name END,
                        mac=CASE WHEN excluded.mac != '' THEN excluded.mac ELSE devices.mac END,
                        vendor=CASE WHEN excluded.mac != '' THEN excluded.vendor ELSE devices.vendor END,
                        device_type=CASE
                            WHEN devices.device_type IS NULL OR devices.device_type='' OR devices.device_type='Unknown'
                            THEN excluded.device_type ELSE devices.device_type END,
                        last_seen=excluded.last_seen
                    """,
                    (ip, name, mac, vendor, dtype, connected, now),
                )
                if has_unifi_name:
                    named_imported += 1
                    # Replace an automatically locked placeholder, but preserve a user-entered name.
                    run_sql(
                        """
                        UPDATE device_overrides
                        SET name=?, updated_at=?
                        WHERE ip=? AND (name IS NULL OR TRIM(name)='' OR name=ip)
                        """,
                        (name, now, ip),
                    )
                imported += 1
            count = int(payload.get("count", len(clients)) or 0)
            total = int(payload.get("totalCount", count) or count)
            offset += count
            if not clients or offset >= total:
                break
        unifi_clients_refreshed_at = now_monotonic
        print(f"UniFi connected clients imported: {imported} ({named_imported} named)")
    except Exception as e:
        print(f"UniFi client import failed: {e}")


def connect_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=30000")
    return con


def positive_int(value, default, minimum=1):
    try:
        return max(minimum, int(value or default))
    except Exception:
        return max(minimum, int(default))


def private_mac_address(mac):
    """Return True for locally administered MACs used by mobile privacy features."""
    text = str(mac or "").strip().replace(":", "").replace("-", "")
    try:
        return len(text) >= 2 and bool(int(text[:2], 16) & 0x02)
    except ValueError:
        return False


def load_oui_vendors():
    """Load shipped overrides plus Debian's IEEE OUI list once per collector process."""
    global oui_vendor_cache
    if oui_vendor_cache is not None:
        return oui_vendor_cache

    vendors = load_json(OUI_PATH, {})
    try:
        for line in SYSTEM_OUI_PATH.read_text(errors="ignore").splitlines():
            if "(hex)" not in line:
                continue
            prefix, vendor = line.split("(hex)", 1)
            key = prefix.strip().replace("-", "").upper()
            if len(key) == 6 and vendor.strip():
                vendors.setdefault(key, vendor.strip())
    except Exception:
        pass
    oui_vendor_cache = vendors
    return vendors


def vendor_from_mac(mac):
    """Look up a hardware vendor, without guessing from randomized mobile MACs."""
    if not str(mac or "").strip():
        return "Unknown Vendor"
    if private_mac_address(mac):
        return "Private / Random MAC"
    key = str(mac).upper().replace(":", "").replace("-", "")[:6]
    return load_oui_vendors().get(key, "Unknown Vendor")


def classify_device(vendor=""):
    """
    Basic device classification based on MAC vendor.

    This gives sensible default icons/types before you manually rename devices.
    Manual changes in the web UI are protected by device_overrides and will not
    be overwritten by the collector.
    """
    text = str(vendor or "").lower()

    if any(x in text for x in ["ubiquiti", "unifi", "mikrotik", "tp-link", "netgear", "cisco"]):
        return "Network Device"

    if any(x in text for x in ["dahua", "ezviz", "hikvision", "camera"]):
        return "Camera"

    if any(x in text for x in ["epson", "canon", "brother", "hewlett packard", "hp inc", "printer"]):
        return "Printer"

    if any(x in text for x in ["apple"]):
        return "Apple Device"

    if any(x in text for x in ["xiaomi", "samsung", "huawei", "oppo", "vivo", "oneplus", "honor"]):
        return "Mobile Device"

    if any(x in text for x in ["proxmox", "server"]):
        return "Server"

    if any(x in text for x in ["micro-star", "gigabyte", "intel", "dell", "lenovo", "asustek", "msi"]):
        return "Computer"

    if any(x in text for x in ["google", "chromecast", "roku", "lg", "sony", "hisense", "tv"]):
        return "Media Device"

    if any(x in text for x in ["espressif", "tuya", "sonoff", "shelly"]):
        return "IoT"

    return "Unknown"


def app_from_domain(domain):
    """
    Convert a DNS domain into a friendly app/category name.

    Examples:
    - googlevideo.com -> YouTube
    - tiktokcdn.com -> TikTok
    - steamserver.net -> Steam
    - teams.microsoft.com -> Microsoft
    """
    d = str(domain or "").lower().strip(".")
    if not d:
        return "Other"
    if d == "x.com" or d.endswith(".x.com"):
        return "Twitter / X"

    mapping = {
        "YouTube": ["youtube", "googlevideo", "ytimg"],
        "TikTok": ["tiktok", "tiktokcdn", "tiktokv", "byteoversea", "bytedance"],
        "Netflix": ["netflix", "nflx", "nrdp"],
        "Spotify": ["spotify", "spclient"],
        "Steam": ["steam", "steampowered", "steamserver"],
        "Roblox": ["roblox"],
        "GitHub": ["github"],
        "Facebook": ["facebook", "fbcdn", "messenger"],
        "Instagram": ["instagram", "cdninstagram"],
        "WhatsApp": ["whatsapp"],
        "Twitter / X": ["twitter", "twimg"],
        "Snapchat": ["snapchat", "sc-cdn"],
        "Discord": ["discord", "discordapp", "discordcdn"],
        "Twitch": ["twitch", "ttvnw"],
        "Disney+": ["disneyplus", "dssott", "bamgrid"],
        "Prime Video": ["primevideo", "aiv-cdn"],
        "Microsoft": ["microsoft", "office", "office365", "teams", "trouter", "msftconnecttest", "windowsupdate"],
        "Apple": ["apple", "icloud", "aaplimg"],
        "Google": ["google", "gstatic", "googleapis", "androidtvchannels"],
        "Plex": ["plex"],
        "Samsung": ["samsung"],
        "Cloudflare": ["cloudflare"],
        "Amazon": ["amazon", "aws", "cloudfront"],
        "Mozilla": ["mozilla", "firefox"],
        "Gaming": ["xbox", "playstation", "epicgames", "battle.net"],
        "Security": ["telemetry", "analytics", "logs"],
    }

    for app, keys in mapping.items():
        if any(k in d for k in keys):
            return app

    parts = d.split(".")
    if len(parts) >= 2:
        return parts[-2].title()

    return "Other"


def is_blocked_reason(reason):
    """
    Return 1 only if AdGuard actually blocked/filtered the query.
    """

    r = str(reason or "").strip().lower()

    if not r:
        return 0

    # AdGuard allowed reasons
    if r.startswith("notfiltered"):
        return 0

    # Actual blocked/filter reasons
    blocked_markers = [
        "filteredblacklist",
        "filteredblockedservice",
        "filteredsafebrowsing",
        "filteredparental",
        "filteredsafesearch",
        "filteredinvalid",
        "blocked",
        "blacklist",
        "blockedservice",
    ]

    return 1 if any(marker in r for marker in blocked_markers) else 0

def parse_adguard_time(value):
    """Convert AdGuard timestamp into YYYY-MM-DD HH:MM:SS."""
    text = str(value or "")

    if not text:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        # AdGuard sometimes has nanosecond precision; Python wants max 6 digits.
        if "." in text:
            left, right = text.split(".", 1)

            if "+" in right:
                frac, tz = right.split("+", 1)
                text = left + "." + frac[:6] + "+" + tz
            elif "-" in right[1:]:
                # Negative timezone offset.
                pos = right[1:].find("-") + 1
                frac = right[:pos]
                tz = right[pos:]
                text = left + "." + frac[:6] + tz

        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone()
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def init_db():
    """
    Create required database tables if they do not exist.

    live_device_speed:
      Current live speed per device.

    devices:
      Known devices and metadata.

    traffic_samples:
      Legacy cumulative samples kept only so older databases remain readable.

    traffic_intervals:
      Additive measured bytes seen during each collection interval.

    dns_querylog:
      Imported AdGuard DNS logs for applications/blocked views.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    con = connect_db()

    con.execute(
        """
        CREATE TABLE IF NOT EXISTS live_device_speed (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            rx_bps REAL DEFAULT 0,
            tx_bps REAL DEFAULT 0,
            total_bps REAL DEFAULT 0,
            updated_at TEXT
        )
        """
    )

    con.execute(
        """
        CREATE TABLE IF NOT EXISTS collector_heartbeat (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            updated_at TEXT,
            packet_iface TEXT,
            status TEXT,
            note TEXT
        )
        """
    )

    con.execute(
        """
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
        """
    )

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
        """
    )

    con.execute(
        """
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
        """
    )

    con.execute(
        """
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
        """
    )

    con.execute(
        """
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
        """
    )

    con.execute(
        """
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
        """
    )

    con.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_querylog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            day TEXT,
            ts TEXT,
            client TEXT,
            domain TEXT,
            blocked INTEGER DEFAULT 0,
            category TEXT DEFAULT 'Other'
        )
        """
    )

    con.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_import_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            cleared_at TEXT
        )
        """
    )

    con.execute("CREATE INDEX IF NOT EXISTS idx_traffic_day_ip ON traffic_samples(day, ip)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_traffic_ip_ts ON traffic_samples(ip, ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_intervals_day_ip ON traffic_intervals(day, ip)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_intervals_ip_ts ON traffic_intervals(ip, ts)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_estimated_app_day_ip ON estimated_app_traffic(day, category, ip)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_remote_traffic_day_ip ON remote_traffic_intervals(day, remote_ip, category)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_day ON dns_querylog(day)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_client ON dns_querylog(client)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_dns_category ON dns_querylog(category)")

    # Prevent duplicate imports from AdGuard.
    con.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_unique
        ON dns_querylog(ts, client, domain)
        """
    )

    con.commit()
    con.close()


def run_sql(sql, params=()):
    """Run a database write safely."""
    try:
        con = connect_db()
        con.execute(sql, params)
        con.commit()
        con.close()
    except Exception as e:
        print(f"DB write failed: {e}")


def ids_known_ips():
    try:
        con = connect_db()
        rows = con.execute("SELECT ip FROM devices").fetchall()
        con.close()
        return {str(row[0]) for row in rows}
    except Exception:
        return set()


def send_ids_email(config, alert):
    host = str(config.get("smtp_host", "") or "").strip()
    username = str(config.get("smtp_username", "") or "").strip()
    password = str(config.get("smtp_password", "") or "")
    from_address = str(config.get("smtp_from", "") or username).strip()
    to_address = str(config.get("smtp_to", "") or "").strip()
    security = str(config.get("smtp_security", "starttls") or "starttls").strip().lower()
    if not host or not from_address or not to_address:
        return False
    message = EmailMessage()
    message["Subject"] = f"NetSpecter IDS P{alert['priority']}: {alert['signature']}"
    message["From"] = from_address
    message["To"] = to_address
    message.set_content(
        "NetSpecter detected a new visible IDS alert.\n\n"
        f"Time: {alert['ts']}\n"
        f"Priority: {alert['priority']}\n"
        f"Alert: {alert['signature']}\n"
        f"Classification: {alert['classification']}\n"
        f"Protocol: {alert['protocol']}\n"
        f"Source: {alert['source']}\n"
        f"Destination: {alert['destination']}\n"
    )
    try:
        port = int(config.get("smtp_port", 587) or 587)
        if security == "ssl":
            smtp = smtplib.SMTP_SSL(host, port, timeout=12, context=ssl.create_default_context())
        else:
            smtp = smtplib.SMTP(host, port, timeout=12)
        with smtp:
            if security == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if username:
                smtp.login(username, password)
            smtp.send_message(message)
        return True
    except Exception as error:
        print(f"IDS email send failed: {error}")
        return False


def process_ids_email_alerts(config):
    """Email newly appended visible IDS alerts, with signature/source cooldown."""
    if not config.get("ids_email_enabled") or not SURICATA_FAST_LOG.exists():
        return
    try:
        result = subprocess.run(
            ["tail", "-n", "400", str(SURICATA_FAST_LOG)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=4,
            check=False,
        )
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception as error:
        print(f"IDS email log read failed: {error}")
        return
    if not lines:
        return
    state = load_json(IDS_EMAIL_STATE_PATH, {})
    previous = str(state.get("last_line", "") or "")
    if not previous:
        IDS_EMAIL_STATE_PATH.write_text(json.dumps({"last_line": lines[-1], "sent": {}}, indent=2))
        return
    try:
        start = lines.index(previous) + 1
    except ValueError:
        IDS_EMAIL_STATE_PATH.write_text(json.dumps({"last_line": lines[-1], "sent": state.get("sent", {})}, indent=2))
        return
    pattern = re.compile(
        r"^(?P<ts>\S+)\s+\[\*\*\]\s+\[(?P<sid>[^\]]+)\]\s+"
        r"(?P<signature>.*?)\s+\[\*\*\]\s+\[Classification:\s*(?P<classification>.*?)\]\s+"
        r"\[Priority:\s*(?P<priority>\d+)\]\s+\{(?P<protocol>[^}]+)\}\s+"
        r"(?P<source>\S+)\s+->\s+(?P<destination>\S+)$"
    )
    known_ips = ids_known_ips()
    excluded_ips = set(cfg_list(config.get("ids_excluded_ips", [])))
    try:
        cooldown_minutes = max(1, int(config.get("ids_email_cooldown_minutes", 30) or 30))
    except (TypeError, ValueError):
        cooldown_minutes = 30
    cooldown_seconds = cooldown_minutes * 60
    now = time.time()
    sent = {key: float(ts) for key, ts in state.get("sent", {}).items() if now - float(ts) < cooldown_seconds}
    for line in lines[start:]:
        match = pattern.match(line)
        if not match:
            continue
        alert = match.groupdict()
        source_ip = alert["source"].rsplit(":", 1)[0].strip()
        if source_ip in excluded_ips or (config.get("ids_unknown_only") and source_ip in known_ips):
            continue
        key = f"{source_ip}|{alert['signature']}"
        if key in sent:
            continue
        if send_ids_email(config, alert):
            sent[key] = now
            print(f"IDS email notification sent: {alert['signature']} from {source_ip}")
    IDS_EMAIL_STATE_PATH.write_text(json.dumps({"last_line": lines[-1], "sent": sent}, indent=2))


def write_heartbeat(status="OK", note=""):
    c = cfg()
    run_sql(
        """
        INSERT INTO collector_heartbeat (id, updated_at, packet_iface, status, note)
        VALUES (1, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            updated_at=excluded.updated_at,
            packet_iface=excluded.packet_iface,
            status=excluded.status,
            note=excluded.note
        """,
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            str(c.get("packet_iface") or "br0"),
            status,
            str(note or "")[:300],
        ),
    )


def prune_history(config=None):
    """Apply configured history retention without altering today's totals."""
    c = config or cfg()
    traffic_days = positive_int(c.get("traffic_retention_days", 30), 30, 1)
    dns_days = positive_int(c.get("dns_retention_days", 14), 14, 1)
    traffic_cutoff = f"-{traffic_days - 1} days"
    dns_cutoff = f"-{dns_days - 1} days"

    try:
        con = connect_db()
        con.execute(
            "DELETE FROM traffic_intervals WHERE day < date('now', 'localtime', ?)",
            (traffic_cutoff,),
        )
        con.execute(
            "DELETE FROM traffic_samples WHERE day < date('now', 'localtime', ?)",
            (traffic_cutoff,),
        )
        con.execute(
            "DELETE FROM estimated_app_traffic WHERE day < date('now', 'localtime', ?)",
            (traffic_cutoff,),
        )
        con.execute(
            "DELETE FROM remote_traffic_intervals WHERE day < date('now', 'localtime', ?)",
            (traffic_cutoff,),
        )
        con.execute(
            "DELETE FROM dns_querylog WHERE day < date('now', 'localtime', ?)",
            (dns_cutoff,),
        )
        con.commit()
        con.close()
    except Exception as e:
        print(f"History retention cleanup failed: {e}")


def lan_network(config=None):
    """Convert the LAN prefix setting into the IPv4 subnet counted by nftables."""
    text = str((config or cfg()).get("lan_prefix", DEFAULT_CONFIG["lan_prefix"]) or "").strip()
    if text.endswith("."):
        text = f"{text}0/24"
    elif "/" not in text:
        text = f"{text}/24"
    network = ipaddress.ip_network(text, strict=False)
    if network.version != 4:
        raise ValueError("LAN Prefix must identify an IPv4 network")
    if network.num_addresses > 1024:
        raise ValueError("LAN Prefix is too large; use a /22 or smaller network")
    return network


def monitored_app_for_domain(domain):
    """Return an app only when its DNS domain is specific enough for attribution."""
    normalized_domain = str(domain or "").lower().strip(".")
    for category, keys in MONITORED_APP_DOMAIN_KEYS.items():
        if any(normalized_domain == key or normalized_domain.endswith(f".{key}") for key in keys):
            return category
    return ""


def remember_estimated_app_targets(config, client, domain, answers, observed_at="", blocked=False):
    """Remember client/destination pairs for explicitly monitored app categories."""
    if blocked:
        return
    category = monitored_app_for_domain(domain)
    if not category:
        return
    try:
        client_ip = ipaddress.ip_address(str(client or "").strip())
        network = lan_network(config)
        if client_ip.version != 4 or client_ip not in network:
            return
    except ValueError:
        return

    now = time.time()
    try:
        observed_epoch = datetime.strptime(str(observed_at)[:19], "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        observed_epoch = now
    for answer in answers if isinstance(answers, list) else []:
        if not isinstance(answer, dict) or str(answer.get("type") or "").upper() != "A":
            continue
        try:
            destination = ipaddress.ip_address(str(answer.get("value") or "").strip())
        except ValueError:
            continue
        if destination.version != 4 or destination.is_unspecified or destination in network:
            continue
        ttl = positive_int(answer.get("ttl", 900), 900, 1)
        expires = observed_epoch + min(max(ttl, 900), 21600)
        if expires <= now:
            continue
        key = (str(client_ip), str(destination))
        with estimated_targets_lock:
            existing = estimated_app_targets.get(key)
            if not existing or existing[0] == category or existing[1] <= now:
                estimated_app_targets[key] = (category, max(existing[1] if existing and existing[0] == category else 0, expires))


def active_estimated_app_targets():
    """Return unexpired monitored app client/destination pairs for nftables attribution."""
    now = time.time()
    with estimated_targets_lock:
        expired = [key for key, (_category, expires) in estimated_app_targets.items() if expires <= now]
        for key in expired:
            estimated_app_targets.pop(key, None)
        return tuple(sorted((category, client, destination) for (client, destination), (category, _expires) in estimated_app_targets.items()))


def update_one_remote_location():
    """Refresh at most one used destination location per DNS import cycle."""
    cutoff = datetime.fromtimestamp(time.time() - GEOLOCATION_REFRESH_SECONDS).strftime("%Y-%m-%d %H:%M:%S")
    con = connect_db()
    row = con.execute(
        """
        SELECT r.remote_ip
        FROM remote_traffic_intervals r
        LEFT JOIN remote_ip_locations l ON l.remote_ip = r.remote_ip
        GROUP BY r.remote_ip
        HAVING MAX(l.lookup_ts) IS NULL OR MAX(l.lookup_ts) < ?
        ORDER BY MAX(r.ts) DESC
        LIMIT 1
        """,
        (cutoff,),
    ).fetchone()
    con.close()
    if not row:
        return

    remote_ip = str(row[0])
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    location = {}
    try:
        response = requests.get(
            f"{GEOLOCATION_URL}{remote_ip}",
            params={"fields": "success,city,region,country,country_code,latitude,longitude"},
            timeout=5,
        )
        if response.status_code == 200:
            payload = response.json()
            if isinstance(payload, dict) and payload.get("success"):
                location = payload
    except Exception as e:
        print(f"Remote destination location lookup failed for {remote_ip}: {e}")

    run_sql(
        """
        INSERT INTO remote_ip_locations
            (remote_ip, city, region, country, country_code, latitude, longitude, lookup_ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(remote_ip) DO UPDATE SET
            city=excluded.city,
            region=excluded.region,
            country=excluded.country,
            country_code=excluded.country_code,
            latitude=excluded.latitude,
            longitude=excluded.longitude,
            lookup_ts=excluded.lookup_ts
        """,
        (
            remote_ip,
            str(location.get("city") or ""),
            str(location.get("region") or ""),
            str(location.get("country") or ""),
            str(location.get("country_code") or ""),
            location.get("latitude"),
            location.get("longitude"),
            now,
        ),
    )


def nft_signature(config=None):
    c = config or cfg()
    banned_ips = []
    for value in cfg_list(c.get("ids_banned_ips", [])):
        try:
            if isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address):
                banned_ips.append(value)
        except ValueError:
            continue
    return (
        str(c.get("packet_iface") or "br0"),
        str(lan_network(c)),
        tuple(sorted(ignored_ips(c))),
        tuple(sorted(set(banned_ips))),
        active_estimated_app_targets(),
    )


def install_nft_counters(config=None):
    """Create bridge traffic counters and any configured IDS endpoint drop rules."""
    global nft_config_signature, nft_previous_counters, nft_previous_estimated_counters, nft_active_ips
    c = config or cfg()
    signature = nft_signature(c)
    interface, network_text, ignored, banned_ips, app_targets = signature
    network = ipaddress.ip_network(network_text)
    ignored_set = set(ignored)
    hosts = [str(ip) for ip in network.hosts() if str(ip) not in ignored_set]

    subprocess.run(
        ["nft", "delete", "table", NFT_FAMILY, NFT_TABLE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    lines = [
        f"table {NFT_FAMILY} {NFT_TABLE} {{",
        "  chain ids_input {",
        "    type filter hook input priority filter; policy accept;",
    ]
    for ip in banned_ips:
        lines.append(
            f'    ip saddr {ip} drop comment "netspecter:ids-ban:input:{ip}"'
        )
    lines.extend([
        "  }",
        "  chain ids_output {",
        "    type filter hook output priority filter; policy accept;",
    ])
    for ip in banned_ips:
        lines.append(
            f'    ip daddr {ip} drop comment "netspecter:ids-ban:output:{ip}"'
        )
    lines.extend([
        "  }",
        f"  chain {NFT_CHAIN} {{",
        "    type filter hook forward priority filter; policy accept;",
    ])
    for ip in banned_ips:
        lines.append(
            f'    ip saddr {ip} drop comment "netspecter:ids-ban:forward-source:{ip}"'
        )
        lines.append(
            f'    ip daddr {ip} drop comment "netspecter:ids-ban:forward-destination:{ip}"'
        )
    for ip in hosts:
        lines.append(
            f'    ip saddr {ip} ip daddr != {network} counter comment "netspecter:tx:{ip}"'
        )
        lines.append(
            f'    ip daddr {ip} ip saddr != {network} counter comment "netspecter:rx:{ip}"'
        )
    for category, client, destination in app_targets:
        lines.append(
            f'    ip saddr {client} ip daddr {destination} counter comment "netspecter:estimated:{category}:tx:{client}:{destination}"'
        )
        lines.append(
            f'    ip daddr {client} ip saddr {destination} counter comment "netspecter:estimated:{category}:rx:{client}:{destination}"'
        )
    lines.extend(["  }", "}"])
    result = subprocess.run(
        ["nft", "-f", "-"],
        input="\n".join(lines) + "\n",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"nftables counter setup failed: {result.stderr.strip()}")

    nft_config_signature = signature
    nft_previous_counters = {}
    nft_previous_estimated_counters = {}
    nft_active_ips = set()
    print(
        f"nftables traffic counters installed for {network_text} on bridge traffic ({interface}); "
        f"{len(app_targets)} monitored app attribution target(s); {len(banned_ips)} IDS banned endpoint(s)"
    )


def remove_nft_counters():
    """Remove NetSpecter's private counter table during an orderly shutdown."""
    global nft_config_signature, nft_previous_counters, nft_previous_estimated_counters, nft_active_ips
    if nft_config_signature is None:
        return
    subprocess.run(
        ["nft", "delete", "table", NFT_FAMILY, NFT_TABLE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    nft_config_signature = None
    nft_previous_counters = {}
    nft_previous_estimated_counters = {}
    nft_active_ips = set()
    print("NetSpecter nftables traffic counters removed")


def shutdown_collector(signum, _frame):
    print(f"Collector shutting down after signal {signum}")
    remove_nft_counters()
    raise SystemExit(0)


def read_nft_counters():
    """Return device totals and DNS-attributed app totals from nftables."""
    result = subprocess.run(
        ["nft", "-j", "list", "chain", NFT_FAMILY, NFT_TABLE, NFT_CHAIN],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"nftables counter read failed: {result.stderr.strip()}")

    payload = json.loads(result.stdout)
    counters = {}
    estimated_counters = {}
    for item in payload.get("nftables", []):
        rule = item.get("rule") if isinstance(item, dict) else None
        if not rule:
            continue
        comment = str(rule.get("comment") or "")
        if not comment.startswith("netspecter:"):
            continue
        total_bytes = 0
        for expr in rule.get("expr", []):
            if isinstance(expr, dict) and isinstance(expr.get("counter"), dict):
                total_bytes = int(expr["counter"].get("bytes", 0) or 0)
                break
        parts = comment.split(":")
        if len(parts) == 3 and parts[1] in ("rx", "tx"):
            counters[(parts[1], parts[2])] = total_bytes
        elif len(parts) == 6 and parts[1] == "estimated" and parts[3] in ("rx", "tx"):
            estimated_counters[(parts[2], parts[3], parts[4], parts[5])] = total_bytes
    return counters, estimated_counters


def read_arp_macs():
    """Use locally known ARP entries when available; traffic counting does not depend on this."""
    macs = {}
    try:
        for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 4 and fields[3] != "00:00:00:00:00:00":
                macs[fields[0]] = fields[3].upper()
    except Exception:
        pass
    return macs


def flush_loop():
    """
    Kernel-counter database update loop.

    Every few seconds it:
    - Reads per-device byte counter differences from nftables
    - Calculates live RX/TX speed from those differences
    - Updates live_device_speed
    - Updates devices
    - Inserts additive traffic_intervals rows
    """
    global nft_config_signature, nft_previous_counters, nft_previous_estimated_counters, nft_active_ips
    init_db()
    last_flush_at = time.monotonic()
    last_prune_day = ""

    while True:
        c = cfg()
        interval = positive_int(c.get("collect_interval_seconds", 2), 2, 1)
        try:
            signature = nft_signature(c)
            if signature != nft_config_signature:
                install_nft_counters(c)

            current_counters, current_estimated_counters = read_nft_counters()
            flush_at = time.monotonic()
            elapsed = max(flush_at - last_flush_at, 0.001)
            last_flush_at = flush_at
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            day = datetime.now().strftime("%Y-%m-%d")
            macs = read_arp_macs()
            deltas = {}
            for (direction, ip), total_bytes in current_counters.items():
                previous = nft_previous_counters.get((direction, ip), 0)
                delta = max(total_bytes - previous, 0)
                nft_previous_counters[(direction, ip)] = total_bytes
                if delta:
                    nft_active_ips.add(ip)
                if delta or ip in nft_active_ips:
                    deltas.setdefault(ip, {"rx": 0, "tx": 0})
                    deltas[ip][direction] = delta
            estimated_deltas = {}
            remote_destination_deltas = {}
            for (category, direction, ip, destination), total_bytes in current_estimated_counters.items():
                key = (category, direction, ip, destination)
                previous = nft_previous_estimated_counters.get(key, 0)
                delta = max(total_bytes - previous, 0)
                nft_previous_estimated_counters[key] = total_bytes
                if delta:
                    estimated_deltas.setdefault((category, ip), {"rx": 0, "tx": 0})
                    estimated_deltas[(category, ip)][direction] += delta
                    remote_destination_deltas.setdefault((category, ip, destination), {"rx": 0, "tx": 0})
                    remote_destination_deltas[(category, ip, destination)][direction] += delta
            write_heartbeat("OK", "nftables counters running")
        except Exception as e:
            print(f"nftables traffic collection failed: {e}")
            write_heartbeat("Counter Retry", str(e))
            time.sleep(interval)
            continue

        for ip, cur in deltas.items():
            rx_delta = cur["rx"]
            tx_delta = cur["tx"]

            rx_Bps = rx_delta / elapsed
            tx_Bps = tx_delta / elapsed
            total_Bps = rx_Bps + tx_Bps

            mac = macs.get(ip, "")
            vendor = vendor_from_mac(mac)
            dtype = classify_device(vendor)
            name = adguard_name_for_ip(ip) or ip

            run_sql(
                """
                INSERT INTO live_device_speed
                    (ip, mac, rx_bps, tx_bps, total_bps, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac=excluded.mac,
                    rx_bps=excluded.rx_bps,
                    tx_bps=excluded.tx_bps,
                    total_bps=excluded.total_bps,
                    updated_at=excluded.updated_at
                """,
                (ip, mac, rx_Bps, tx_Bps, total_Bps, now),
            )

            run_sql(
                """
                INSERT INTO devices
                    (ip, name, mac, vendor, device_type, status, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, 'Active', ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac=CASE WHEN excluded.mac != '' THEN excluded.mac ELSE devices.mac END,
                    vendor=CASE WHEN excluded.mac != '' THEN excluded.vendor ELSE devices.vendor END,
                    device_type=CASE
                        WHEN devices.device_type IS NULL
                          OR devices.device_type=''
                          OR devices.device_type='Unknown'
                        THEN excluded.device_type
                        ELSE devices.device_type
                    END,
                    name=CASE WHEN excluded.name != excluded.ip THEN excluded.name ELSE devices.name END,
                    last_seen=excluded.last_seen
                """,
                (ip, name, mac, vendor, dtype, now, now),
            )

            interval_rx_mb = rx_delta / 1024 / 1024
            interval_tx_mb = tx_delta / 1024 / 1024
            interval_total_mb = interval_rx_mb + interval_tx_mb

            if interval_total_mb > 0:
                run_sql(
                    """
                    INSERT INTO traffic_intervals
                        (ip, name, mac, downloaded_mb, uploaded_mb, total_mb, live_bps, day, ts)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ip,
                        name,
                        mac,
                        interval_rx_mb,
                        interval_tx_mb,
                        interval_total_mb,
                        (rx_delta + tx_delta) / elapsed * 8,
                        day,
                        now,
                    ),
                )

        for (category, ip), cur in estimated_deltas.items():
            interval_rx_mb = cur["rx"] / 1024 / 1024
            interval_tx_mb = cur["tx"] / 1024 / 1024
            interval_total_mb = interval_rx_mb + interval_tx_mb
            if interval_total_mb > 0:
                run_sql(
                    """
                    INSERT INTO estimated_app_traffic
                        (ip, category, downloaded_mb, uploaded_mb, total_mb, day, ts)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (ip, category, interval_rx_mb, interval_tx_mb, interval_total_mb, day, now),
                )

        for (category, ip, destination), cur in remote_destination_deltas.items():
            interval_rx_mb = cur["rx"] / 1024 / 1024
            interval_tx_mb = cur["tx"] / 1024 / 1024
            interval_total_mb = interval_rx_mb + interval_tx_mb
            if interval_total_mb > 0:
                run_sql(
                    """
                    INSERT INTO remote_traffic_intervals
                        (ip, remote_ip, category, downloaded_mb, uploaded_mb, total_mb, day, ts)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (ip, destination, category, interval_rx_mb, interval_tx_mb, interval_total_mb, day, now),
                )

        if day != last_prune_day:
            prune_history(c)
            last_prune_day = day
        time.sleep(interval)


def import_adguard_querylog():
    """
    Pull DNS querylog from AdGuard Home and insert into dns_querylog.

    This powers:
    - Top Applications
    - Per-device application data
    - Blocked domains
    """
    c = cfg()

    base = str(c.get("adguard_url", "")).rstrip("/")
    user = c.get("adguard_user", "admin")
    password = c.get("adguard_pass", "")

    if not base:
        return

    try:
        res = requests.get(
            f"{base}/control/querylog",
            auth=(user, password),
            timeout=10,
        )

        if res.status_code != 200:
            print(f"AdGuard querylog import failed: HTTP {res.status_code}")
            return

        payload = res.json()

    except Exception as e:
        print(f"AdGuard querylog import failed: {e}")
        return

    rows = payload.get("data", []) if isinstance(payload, dict) else []

    if not isinstance(rows, list):
        return

    cutoff = ""
    try:
        con = connect_db()
        state = con.execute("SELECT cleared_at FROM dns_import_state WHERE id=1").fetchone()
        con.close()
        cutoff = str(state[0] or "") if state else ""
    except Exception as e:
        print(f"DNS history cutoff read failed: {e}")

    imported = 0

    for item in rows:
        if not isinstance(item, dict):
            continue

        question = item.get("question") or {}

        domain = str(question.get("name") or "").strip(".")
        client = str(item.get("client") or "").strip()
        reason = str(item.get("reason") or "")
        ts = parse_adguard_time(item.get("time"))
        day = ts[:10]
        blocked = is_blocked_reason(reason)
        category = app_from_domain(domain)

        if not domain or not client:
            continue

        remember_adguard_client_activity(client, ts)
        remember_estimated_app_targets(c, client, domain, item.get("answer") or [], ts, blocked)

        if cutoff and ts <= cutoff:
            continue

        # Fast duplicate protection for this running process.
        key = f"{ts}|{client}|{domain}"
        if key in imported_dns_keys:
            continue

        imported_dns_keys.add(key)

        try:
            run_sql(
                """
                INSERT OR IGNORE INTO dns_querylog
                    (day, ts, client, domain, blocked, category)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (day, ts, client, domain, blocked, category),
            )
            imported += 1
        except Exception as e:
            print(f"DNS querylog insert failed: {e}")

    if imported:
        print(f"AdGuard querylog imported rows: {imported}")


def adguard_querylog_loop():
    """Background loop for AdGuard DNS querylog importing."""
    init_db()

    while True:
        c = cfg()
        interval = positive_int(c.get("adguard_querylog_interval_seconds", 15), 15, 5)

        try:
            refresh_adguard_client_names(c)
            refresh_unifi_clients(c)
            process_ids_email_alerts(c)
            import_adguard_querylog()
            update_one_remote_location()
        except Exception as e:
            print(f"AdGuard querylog loop failed: {e}")

        time.sleep(interval)


if __name__ == "__main__":
    if not acquire_collector_lock():
        raise SystemExit(1)

    atexit.register(remove_nft_counters)
    signal.signal(signal.SIGTERM, shutdown_collector)
    signal.signal(signal.SIGINT, shutdown_collector)

    while True:
        try:
            init_db()
            break
        except Exception as e:
            print(f"Collector startup failed: {e}")
            print("Retrying startup in 10 seconds")
            time.sleep(10)

    # Thread 1: nftables byte counters and traffic totals.
    packet_thread = threading.Thread(target=flush_loop, daemon=True)
    packet_thread.start()

    # Thread 2: AdGuard DNS querylog import.
    dns_thread = threading.Thread(target=adguard_querylog_loop, daemon=True)
    dns_thread.start()

    interface = str(cfg().get("packet_iface") or "br0")

    print(f"NetSpecter nftables collector started for bridge: {interface}")
    print(f"Database: {DB_PATH}")
    print("AdGuard DNS querylog importer started")
    write_heartbeat("OK", "collector started")

    while True:
        time.sleep(3600)
