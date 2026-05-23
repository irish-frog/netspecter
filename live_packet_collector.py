#!/usr/bin/env python3
"""
NetSpecter Live Packet Collector

What this file does:
- Watches live network packets on the selected network interface.
- Works out which LAN device is uploading or downloading.
- Calculates live speed per device.
- Saves live speed into SQLite.
- Saves device details like IP, MAC, vendor and type.
- Saves daily usage totals.
- Restores today's totals after a reboot or service restart.
- Ignores the gateway/router so it does not appear as the top user.
- Imports AdGuard Home DNS querylog into dns_querylog.
- Classifies domains into application categories for Top Applications.

Important:
- Speeds in live_device_speed are stored as BYTES per second.
- live_bps in traffic_samples is stored as BITS per second.
- dns_querylog powers Top Applications and per-device application views.
"""

import json
import os
import sqlite3
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import requests
from scapy.all import sniff, Ether, IP

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
SECRET_KEY_PATH = CONFIG_DIR / "secret.key"
ENCRYPTED_PREFIX = "enc:"
SENSITIVE_CONFIG_KEYS = {"adguard_pass", "ntop_pass"}


# ---------------------------------------------------
# Default settings
# ---------------------------------------------------
# packet_iface:
#   The network interface to sniff.
#   Examples: br0, enp1s0, enp2s0, eth0.
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
    "gateway_ip": "",
    "ignore_ips": [],

    "adguard_url": "http://127.0.0.1",
    "adguard_user": "admin",
    "adguard_pass": "",
    "adguard_querylog_interval_seconds": 15,
}


# ---------------------------------------------------
# Runtime counters
# ---------------------------------------------------

stats = defaultdict(lambda: {"rx": 0, "tx": 0, "mac": ""})
last_stats = defaultdict(lambda: {"rx": 0, "tx": 0})
total_stats = defaultdict(lambda: {"rx": 0, "tx": 0})
imported_dns_keys = set()


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


def vendor_from_mac(mac):
    """Look up vendor name from MAC address."""
    oui = load_json(OUI_PATH, {})
    key = str(mac or "").upper().replace(":", "").replace("-", "")[:6]
    return oui.get(key, "Unknown Vendor")


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

        dt = datetime.fromisoformat(text)
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
      Historical usage samples and daily totals.

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

    con.execute("CREATE INDEX IF NOT EXISTS idx_traffic_day_ip ON traffic_samples(day, ip)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_traffic_ip_ts ON traffic_samples(ip, ts)")
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


def load_today_totals():
    """
    Restore today's totals after a reboot or collector restart.

    Without this, total_stats starts at zero every time the service starts.
    """
    day = datetime.now().strftime("%Y-%m-%d")

    try:
        con = connect_db()
        con.row_factory = sqlite3.Row

        rows = con.execute(
            """
            SELECT ip, downloaded_mb, uploaded_mb
            FROM traffic_samples
            WHERE day = ?
            AND id IN (
                SELECT MAX(id)
                FROM traffic_samples
                WHERE day = ?
                GROUP BY ip
            )
            """,
            (day, day),
        ).fetchall()

        con.close()
    except Exception as e:
        print(f"Could not restore today's totals: {e}")
        return

    for row in rows:
        ip = row["ip"]
        total_stats[ip]["rx"] = float(row["downloaded_mb"] or 0) * 1024 * 1024
        total_stats[ip]["tx"] = float(row["uploaded_mb"] or 0) * 1024 * 1024


def handle_packet(pkt):
    """
    Process each captured packet.

    Upload logic:
    - If source IP is inside the LAN, that device uploaded traffic.

    Download logic:
    - If destination IP is inside the LAN, that device downloaded traffic.
    """
    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(Ether):
            return

        c = cfg()
        lan_prefix = str(c.get("lan_prefix", DEFAULT_CONFIG["lan_prefix"]))
        ignore_ips = ignored_ips(c)

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_mac = pkt[Ether].src.upper()
        dst_mac = pkt[Ether].dst.upper()
        size = len(pkt)

        if src_ip.startswith(lan_prefix) and src_ip not in ignore_ips:
            stats[src_ip]["tx"] += size
            stats[src_ip]["mac"] = src_mac
            total_stats[src_ip]["tx"] += size

        if dst_ip.startswith(lan_prefix) and dst_ip not in ignore_ips:
            stats[dst_ip]["rx"] += size
            stats[dst_ip]["mac"] = dst_mac
            total_stats[dst_ip]["rx"] += size
    except Exception as e:
        print(f"Packet handling failed: {e}")


def flush_loop():
    """
    Packet database update loop.

    Every few seconds it:
    - Calculates live RX/TX speed
    - Updates live_device_speed
    - Updates devices
    - Inserts traffic_samples rows
    """
    init_db()
    load_today_totals()

    while True:
        c = cfg()
        interval = positive_int(c.get("collect_interval_seconds", 2), 2, 1)

        time.sleep(interval)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        day = datetime.now().strftime("%Y-%m-%d")
        write_heartbeat("OK", "flush loop running")

        for ip, cur in list(stats.items()):
            prev = last_stats[ip]

            rx_delta = max(cur["rx"] - prev["rx"], 0)
            tx_delta = max(cur["tx"] - prev["tx"], 0)

            rx_Bps = rx_delta / interval
            tx_Bps = tx_delta / interval
            total_Bps = rx_Bps + tx_Bps

            last_stats[ip] = {
                "rx": cur["rx"],
                "tx": cur["tx"],
            }

            mac = cur.get("mac", "")
            vendor = vendor_from_mac(mac)
            dtype = classify_device(vendor)

            total_rx_mb = total_stats[ip]["rx"] / 1024 / 1024
            total_tx_mb = total_stats[ip]["tx"] / 1024 / 1024
            total_mb = total_rx_mb + total_tx_mb

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
                    mac=excluded.mac,
                    vendor=excluded.vendor,
                    device_type=CASE
                        WHEN devices.device_type IS NULL
                          OR devices.device_type=''
                          OR devices.device_type='Unknown'
                        THEN excluded.device_type
                        ELSE devices.device_type
                    END,
                    last_seen=excluded.last_seen
                """,
                (ip, ip, mac, vendor, dtype, now, now),
            )

            run_sql(
                """
                INSERT INTO traffic_samples
                    (ip, name, mac, downloaded_mb, uploaded_mb, total_mb, live_bps, day, ts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ip,
                    ip,
                    mac,
                    total_rx_mb,
                    total_tx_mb,
                    total_mb,
                    total_Bps * 8,
                    day,
                    now,
                ),
            )


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
            import_adguard_querylog()
        except Exception as e:
            print(f"AdGuard querylog loop failed: {e}")

        time.sleep(interval)


if __name__ == "__main__":
    import threading

    while True:
        try:
            init_db()
            load_today_totals()
            break
        except Exception as e:
            print(f"Collector startup failed: {e}")
            print("Retrying startup in 10 seconds")
            time.sleep(10)

    # Thread 1: packet speed and usage totals.
    packet_thread = threading.Thread(target=flush_loop, daemon=True)
    packet_thread.start()

    # Thread 2: AdGuard DNS querylog import.
    dns_thread = threading.Thread(target=adguard_querylog_loop, daemon=True)
    dns_thread.start()

    interface = str(cfg().get("packet_iface") or "br0")

    print(f"NetSpecter collector started on interface: {interface}")
    print(f"Database: {DB_PATH}")
    print("AdGuard DNS querylog importer started")
    write_heartbeat("OK", "collector started")

    while True:
        try:
            sniff(iface=interface, prn=handle_packet, store=False)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"Packet capture failed on {interface}: {e}")
            write_heartbeat("Capture Retry", f"packet capture failed on {interface}: {e}")
            print("Retrying packet capture in 10 seconds")
            time.sleep(10)
