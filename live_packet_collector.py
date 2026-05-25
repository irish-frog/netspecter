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
- Classifies domains into application categories for Top Applications.

Important:
- Speeds in live_device_speed are stored as BYTES per second.
- live_bps in traffic_intervals is stored as BITS per second.
- dns_querylog powers Top Applications and per-device application views.
"""

import fcntl
import ipaddress
import json
import os
import sqlite3
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

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
SECRET_KEY_PATH = CONFIG_DIR / "secret.key"
COLLECTOR_LOCK_PATH = DATA_DIR / "collector.lock"
ENCRYPTED_PREFIX = "enc:"
SENSITIVE_CONFIG_KEYS = {"adguard_pass"}
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
}


# ---------------------------------------------------
# Kernel counter state
# ---------------------------------------------------

imported_dns_keys = set()
NFT_FAMILY = "bridge"
NFT_TABLE = "netspecter"
NFT_CHAIN = "forward"
nft_config_signature = None
nft_previous_counters = {}
nft_active_ips = set()


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


def nft_signature(config=None):
    c = config or cfg()
    return (
        str(c.get("packet_iface") or "br0"),
        str(lan_network(c)),
        tuple(sorted(ignored_ips(c))),
    )


def install_nft_counters(config=None):
    """Create an isolated bridge counter table; no traffic is blocked or redirected."""
    global nft_config_signature, nft_previous_counters, nft_active_ips
    c = config or cfg()
    interface, network_text, ignored = nft_signature(c)
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
        f"  chain {NFT_CHAIN} {{",
        "    type filter hook forward priority filter; policy accept;",
    ]
    for ip in hosts:
        lines.append(
            f'    ip saddr {ip} ip daddr != {network} counter comment "netspecter:tx:{ip}"'
        )
        lines.append(
            f'    ip daddr {ip} ip saddr != {network} counter comment "netspecter:rx:{ip}"'
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

    nft_config_signature = (interface, network_text, ignored)
    nft_previous_counters = {}
    nft_active_ips = set()
    print(f"nftables traffic counters installed for {network_text} on bridge traffic ({interface})")


def read_nft_counters():
    """Return {(direction, ip): bytes} from the NetSpecter nftables table."""
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
    for item in payload.get("nftables", []):
        rule = item.get("rule") if isinstance(item, dict) else None
        if not rule:
            continue
        comment = str(rule.get("comment") or "")
        if not comment.startswith("netspecter:"):
            continue
        parts = comment.split(":", 2)
        if len(parts) != 3 or parts[1] not in ("rx", "tx"):
            continue
        total_bytes = 0
        for expr in rule.get("expr", []):
            if isinstance(expr, dict) and isinstance(expr.get("counter"), dict):
                total_bytes = int(expr["counter"].get("bytes", 0) or 0)
                break
        counters[(parts[1], parts[2])] = total_bytes
    return counters


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
    global nft_config_signature, nft_previous_counters, nft_active_ips
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

            current_counters = read_nft_counters()
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
                    last_seen=excluded.last_seen
                """,
                (ip, ip, mac, vendor, dtype, now, now),
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
                        ip,
                        mac,
                        interval_rx_mb,
                        interval_tx_mb,
                        interval_total_mb,
                        (rx_delta + tx_delta) / elapsed * 8,
                        day,
                        now,
                    ),
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
            import_adguard_querylog()
        except Exception as e:
            print(f"AdGuard querylog loop failed: {e}")

        time.sleep(interval)


if __name__ == "__main__":
    if not acquire_collector_lock():
        raise SystemExit(1)

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
