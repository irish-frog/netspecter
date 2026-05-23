#!/bin/bash
set -euo pipefail

echo "=== NetSpecter Full Appliance Installer ==="

INSTALL_DIR="/opt/netspecter"
CONFIG_DIR="/etc/netspecter"
DATA_DIR="/var/lib/netspecter"
SERVICE_DIR="/etc/systemd/system"
INSTALL_ADGUARD="${INSTALL_ADGUARD:-1}"
APPLY_ADGUARD_TEMPLATE="${APPLY_ADGUARD_TEMPLATE:-0}"

if [ "${EUID}" -ne 0 ]; then
  echo "Please run as root." >&2
  exit 1
fi

echo "[1/9] Installing base packages..."
apt update
apt install -y python3 python3-pip python3-venv sqlite3 bridge-utils tcpdump curl wget nano git iftop bmon vnstat redis-server

echo "[2/9] Installing ntopng repository and ntopng..."
if ! command -v ntopng >/dev/null 2>&1; then
  wget -q https://packages.ntop.org/apt/bookworm/all/apt-ntop.deb -O /tmp/apt-ntop.deb || true
  if [ -s /tmp/apt-ntop.deb ]; then dpkg -i /tmp/apt-ntop.deb || true; apt update; apt install -y ntopng redis-server || true; fi
fi

echo "[3/9] Installing AdGuard Home if requested..."
if [ "$INSTALL_ADGUARD" = "1" ] && ! command -v AdGuardHome >/dev/null 2>&1 && [ ! -x /opt/AdGuardHome/AdGuardHome ]; then
  wget -O - https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v || true
else
  echo "AdGuard Home install skipped or already present."
fi

echo "[4/9] Creating folders..."
mkdir -p "$INSTALL_DIR/static" "$INSTALL_DIR/scripts" "$INSTALL_DIR/adguard" "$CONFIG_DIR/adguard" "$DATA_DIR"

echo "[5/9] Copying NetSpecter files..."
cp app.py "$INSTALL_DIR/app.py"
cp live_packet_collector.py "$INSTALL_DIR/live_packet_collector.py"
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
chmod +x "$INSTALL_DIR/live_packet_collector.py"
chmod +x "$INSTALL_DIR/collector_watchdog.sh"
chmod +x "$INSTALL_DIR/scripts/render-adguard-template.sh"

echo "[8/9] Preparing AdGuard template..."
"$INSTALL_DIR/scripts/render-adguard-template.sh" "$INSTALL_DIR/adguard/AdGuardHome.yaml.example" "$CONFIG_DIR/adguard/AdGuardHome.yaml.generated" || true
if [ "$APPLY_ADGUARD_TEMPLATE" = "1" ]; then
  if [ -f /opt/AdGuardHome/AdGuardHome.yaml ]; then
    echo "Existing AdGuard config preserved: /opt/AdGuardHome/AdGuardHome.yaml"
    echo "Generated template is at: $CONFIG_DIR/adguard/AdGuardHome.yaml.generated"
  else
    cp "$CONFIG_DIR/adguard/AdGuardHome.yaml.generated" /opt/AdGuardHome/AdGuardHome.yaml
    chmod 600 /opt/AdGuardHome/AdGuardHome.yaml
  fi
fi

echo "[9/9] Installing systemd services..."
cp systemd/netspecter-web.service "$SERVICE_DIR/netspecter-web.service"
cp systemd/netspecter-collector.service "$SERVICE_DIR/netspecter-collector.service"
cp systemd/netspecter-watchdog.service "$SERVICE_DIR/netspecter-watchdog.service"
cp systemd/netspecter-watchdog.timer "$SERVICE_DIR/netspecter-watchdog.timer"
systemctl daemon-reload
systemctl enable netspecter-web netspecter-collector netspecter-watchdog.timer
systemctl restart netspecter-web netspecter-collector
systemctl restart netspecter-watchdog.timer
systemctl enable --now vnstat redis-server || true
systemctl enable --now ntopng || true
systemctl enable --now AdGuardHome || true

echo ""
echo "=== NetSpecter installed ==="
echo "Open: http://SERVER-IP:5050"
echo "AdGuard template: $CONFIG_DIR/adguard/AdGuardHome.yaml.generated"
echo "Check: systemctl status netspecter-web netspecter-collector"
