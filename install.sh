#!/bin/bash
set -euo pipefail

echo "=== NetSpecter Full Appliance Installer ==="

INSTALL_DIR="/opt/netspecter"
CONFIG_DIR="/etc/netspecter"
DATA_DIR="/var/lib/netspecter"
SERVICE_DIR="/etc/systemd/system"
INSTALL_ADGUARD="${INSTALL_ADGUARD:-1}"
ADGUARD_JUST_INSTALLED=0

if [ "${EUID}" -ne 0 ]; then
  echo "Please run as root." >&2
  exit 1
fi

port_3000_in_use() {
  ss -H -ltn 'sport = :3000' 2>/dev/null | grep -q LISTEN
}

echo "[1/9] Refreshing package metadata and installing setup tools..."
apt update
apt install -y wget curl gnupg ca-certificates lsb-release iproute2

echo "[2/9] Installing AdGuard Home first if requested..."
if [ "$INSTALL_ADGUARD" = "1" ] && ! command -v AdGuardHome >/dev/null 2>&1 && [ ! -x /opt/AdGuardHome/AdGuardHome ]; then
  if port_3000_in_use; then
    echo "Port 3000 is already in use. Free it before installing AdGuard Home." >&2
    ss -ltnp 'sport = :3000' || true
    exit 1
  fi
  wget -O - https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
  ADGUARD_JUST_INSTALLED=1
else
  echo "AdGuard Home install skipped or already present."
fi

if [ "$ADGUARD_JUST_INSTALLED" = "1" ] && port_3000_in_use; then
  echo ""
  echo "=== AdGuard Home setup available ==="
  echo "After installation completes, open: http://SERVER-IP:3000"
  echo "In the AdGuard wizard, set its web/admin port to 80."
  echo "Continuing with NetSpecter installation now."
fi

echo "[3/9] Installing NetSpecter base packages..."
if ! dpkg-query -W -f='${Status}' speedtest 2>/dev/null | grep -q "install ok installed"; then
  curl -fsSL https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash
fi
apt remove -y speedtest-cli >/dev/null 2>&1 || true
apt install -y python3 python3-pip python3-venv sqlite3 bridge-utils nftables tcpdump curl nano git bmon vnstat ieee-data snmp speedtest

echo "[4/9] Creating folders..."
mkdir -p "$INSTALL_DIR/static" "$INSTALL_DIR/scripts" "$INSTALL_DIR/adguard" "$CONFIG_DIR/adguard" "$DATA_DIR"

echo "[5/9] Copying NetSpecter files..."
# A collector started outside systemd, or from an older build without locking,
# can otherwise keep writing stale totals after an upgrade.
systemctl stop netspecter-collector netspecter-live >/dev/null 2>&1 || true
systemctl disable netspecter-live >/dev/null 2>&1 || true
rm -f "$SERVICE_DIR/netspecter-live.service"
systemctl daemon-reload
pkill -f 'live_packet_collector.py' >/dev/null 2>&1 || true
cp app.py "$INSTALL_DIR/app.py"
cp gunicorn_config.py "$INSTALL_DIR/gunicorn_config.py"
cp wsgi.py "$INSTALL_DIR/wsgi.py"
cp live_packet_collector.py "$INSTALL_DIR/live_packet_collector.py"
cp scheduled_speedtest.py "$INSTALL_DIR/scheduled_speedtest.py"
cp collector_watchdog.sh "$INSTALL_DIR/collector_watchdog.sh"
cp -r static/. "$INSTALL_DIR/static/"
cp -r scripts/. "$INSTALL_DIR/scripts/"
cp -r adguard/. "$INSTALL_DIR/adguard/"
if [ ! -f "$CONFIG_DIR/config.json" ]; then
  cp config.example.json "$CONFIG_DIR/config.json"
else
  echo "Existing config preserved: $CONFIG_DIR/config.json"
fi
[ -f cache.json ] && cp cache.json "$DATA_DIR/cache.json" || echo "{}" > "$DATA_DIR/cache.json"
[ -f oui_cache.json ] && cp oui_cache.json "$DATA_DIR/oui_cache.json" || echo "{}" > "$DATA_DIR/oui_cache.json"

echo "[6/9] Creating Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r requirements.txt

echo "[7/9] Preparing database and permissions..."
touch "$DATA_DIR/netspecter.db"
chown -R root:root "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR"
chmod 700 "$CONFIG_DIR" "$CONFIG_DIR/adguard" "$DATA_DIR"
chmod 600 "$CONFIG_DIR/config.json" "$DATA_DIR/netspecter.db" "$DATA_DIR/cache.json" "$DATA_DIR/oui_cache.json"
chmod +x "$INSTALL_DIR/live_packet_collector.py"
chmod +x "$INSTALL_DIR/scheduled_speedtest.py"
chmod +x "$INSTALL_DIR/collector_watchdog.sh"
chmod +x "$INSTALL_DIR/scripts/render-adguard-template.sh"

echo "[8/9] Preparing AdGuard template..."
"$INSTALL_DIR/scripts/render-adguard-template.sh" "$INSTALL_DIR/adguard/AdGuardHome.yaml.example" "$CONFIG_DIR/adguard/AdGuardHome.yaml.generated" || true

echo "[9/9] Installing systemd services..."
cp systemd/netspecter-web.service "$SERVICE_DIR/netspecter-web.service"
cp systemd/netspecter-collector.service "$SERVICE_DIR/netspecter-collector.service"
cp systemd/netspecter-watchdog.service "$SERVICE_DIR/netspecter-watchdog.service"
cp systemd/netspecter-watchdog.timer "$SERVICE_DIR/netspecter-watchdog.timer"
cp systemd/netspecter-speedtest.service "$SERVICE_DIR/netspecter-speedtest.service"
cp systemd/netspecter-speedtest.timer "$SERVICE_DIR/netspecter-speedtest.timer"
systemctl daemon-reload
systemctl enable netspecter-web netspecter-collector netspecter-watchdog.timer netspecter-speedtest.timer
systemctl restart netspecter-web netspecter-collector
systemctl restart netspecter-watchdog.timer
systemctl restart netspecter-speedtest.timer
systemctl enable --now vnstat || true
systemctl enable AdGuardHome || true

echo ""
echo "=== NetSpecter installed ==="
echo "Open: http://SERVER-IP:5050"
echo "AdGuard template: $CONFIG_DIR/adguard/AdGuardHome.yaml.generated"
echo "Check: systemctl status netspecter-web netspecter-collector"
