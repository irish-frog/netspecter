#!/bin/bash
set -euo pipefail

echo "=== NetSpecter Full Appliance Installer ==="

INSTALL_DIR="/opt/netspecter"
CONFIG_DIR="/etc/netspecter"
DATA_DIR="/var/lib/netspecter"
SERVICE_DIR="/etc/systemd/system"
INSTALL_ADGUARD="${INSTALL_ADGUARD:-1}"
NTOP_REPO_BACKUP_DIR="/var/backups/netspecter/ntop-repo"
NTOP_KEYRING="/usr/share/keyrings/ntop-archive-keyring.gpg"

if [ "${EUID}" -ne 0 ]; then
  echo "Please run as root." >&2
  exit 1
fi

port_3000_in_use() {
  ss -H -ltn 'sport = :3000' 2>/dev/null | grep -q LISTEN
}

echo "[1/11] Clearing incomplete ntop repository setup..."
mkdir -p "$NTOP_REPO_BACKUP_DIR"
for source in /etc/apt/sources.list.d/*ntop*.list /etc/apt/sources.list.d/*ntop*.sources; do
  [ -f "$source" ] || continue
  cp -a "$source" "$NTOP_REPO_BACKUP_DIR/$(basename "$source").$(date +%Y%m%d%H%M%S)"
done
dpkg --purge apt-ntop apt-ntop-stable >/dev/null 2>&1 || true
rm -f /etc/apt/sources.list.d/*ntop*.list /etc/apt/sources.list.d/*ntop*.sources

echo "[2/11] Updating system and installing setup tools..."
apt update
apt upgrade -y
apt install -y wget gnupg ca-certificates lsb-release iproute2

echo "[3/11] Installing AdGuard Home first if requested..."
if [ "$INSTALL_ADGUARD" = "1" ] && ! command -v AdGuardHome >/dev/null 2>&1 && [ ! -x /opt/AdGuardHome/AdGuardHome ]; then
  if systemctl is-active --quiet ntopng 2>/dev/null; then
    echo "Stopping ntopng temporarily so AdGuard Home can use setup port 3000."
    systemctl stop ntopng
  fi
  if port_3000_in_use; then
    echo "Port 3000 is already in use. Free it before installing AdGuard Home." >&2
    ss -ltnp 'sport = :3000' || true
    exit 1
  fi
  wget -O - https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
else
  echo "AdGuard Home install skipped or already present."
fi

if [ "$INSTALL_ADGUARD" = "1" ] && port_3000_in_use && ! systemctl is-active --quiet ntopng 2>/dev/null; then
  echo ""
  echo "=== AdGuard Home setup required before continuing ==="
  echo "Open: http://SERVER-IP:3000"
  echo "In the AdGuard wizard, set its web/admin port to 80."
  echo "After setup frees port 3000, rerun: ./install.sh"
  echo "The second run installs ntopng and NetSpecter."
  exit 0
fi

echo "[4/11] Installing NetSpecter base packages..."
apt install -y python3 python3-pip python3-venv sqlite3 bridge-utils tcpdump curl nano git iftop bmon vnstat redis-server

echo "[5/11] Installing ntopng with signed stable repositories..."
if [ -f /etc/apt/sources.list.d/debian.sources ]; then
  sed -i '/^Components:/ { /contrib/! s/$/ contrib/; }' /etc/apt/sources.list.d/debian.sources
fi
if [ -f /etc/apt/sources.list ]; then
  sed -i -E '/^deb(-src)? / { /[[:space:]]contrib([[:space:]]|$)/! s/[[:space:]]main([[:space:]]|$)/ main contrib /; }' /etc/apt/sources.list
fi
apt update
wget -q https://packages.ntop.org/apt/ntop.key -O /tmp/ntop.key
gpg --batch --yes --dearmor -o "$NTOP_KEYRING" /tmp/ntop.key
cat > /etc/apt/sources.list.d/ntop.list <<EOF
deb [signed-by=$NTOP_KEYRING] https://packages.ntop.org/apt-stable/bookworm x64/
deb [signed-by=$NTOP_KEYRING] https://packages.ntop.org/apt-stable/bookworm all/
EOF
apt clean
rm -rf /var/lib/apt/lists/*
apt update
apt install -y ntopng redis-server

echo "[6/11] Creating folders..."
mkdir -p "$INSTALL_DIR/static" "$INSTALL_DIR/scripts" "$INSTALL_DIR/adguard" "$CONFIG_DIR/adguard" "$DATA_DIR"

echo "[7/11] Copying NetSpecter files..."
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

echo "[8/11] Creating Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r requirements.txt

echo "[9/11] Preparing database and permissions..."
touch "$DATA_DIR/netspecter.db"
chown -R root:root "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR"
chmod +x "$INSTALL_DIR/live_packet_collector.py"
chmod +x "$INSTALL_DIR/collector_watchdog.sh"
chmod +x "$INSTALL_DIR/scripts/render-adguard-template.sh"

echo "[10/11] Preparing AdGuard template..."
"$INSTALL_DIR/scripts/render-adguard-template.sh" "$INSTALL_DIR/adguard/AdGuardHome.yaml.example" "$CONFIG_DIR/adguard/AdGuardHome.yaml.generated" || true

echo "[11/11] Installing systemd services..."
cp systemd/netspecter-web.service "$SERVICE_DIR/netspecter-web.service"
cp systemd/netspecter-collector.service "$SERVICE_DIR/netspecter-collector.service"
cp systemd/netspecter-watchdog.service "$SERVICE_DIR/netspecter-watchdog.service"
cp systemd/netspecter-watchdog.timer "$SERVICE_DIR/netspecter-watchdog.timer"
systemctl daemon-reload
systemctl enable netspecter-web netspecter-collector netspecter-watchdog.timer
systemctl restart netspecter-web netspecter-collector
systemctl restart netspecter-watchdog.timer
systemctl enable --now vnstat redis-server || true
systemctl enable AdGuardHome || true
systemctl enable --now ntopng

echo ""
echo "=== NetSpecter installed ==="
echo "Open: http://SERVER-IP:5050"
echo "AdGuard template: $CONFIG_DIR/adguard/AdGuardHome.yaml.generated"
echo "Check: systemctl status netspecter-web netspecter-collector"
echo "ntopng: http://SERVER-IP:3000"
