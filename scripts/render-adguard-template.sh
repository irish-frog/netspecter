#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

TEMPLATE="${1:-$REPO_DIR/adguard/AdGuardHome.yaml.example}"
OUTPUT="${2:-/etc/netspecter/adguard/AdGuardHome.yaml.generated}"

SERVER_IP="${NETSPECTER_SERVER_IP:-}"
LAN_CIDR="${NETSPECTER_LAN_CIDR:-}"

if [ -z "$SERVER_IP" ]; then
  SERVER_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="src"){print $(i+1); exit}}}' || true)"
fi

if [ -z "$LAN_CIDR" ] && [ -n "$SERVER_IP" ]; then
  LAN_CIDR="$(ip -4 -o addr show | awk -v ip="$SERVER_IP" '$0 ~ ip {print $4; exit}' || true)"
fi

SERVER_IP="${SERVER_IP:-127.0.0.1}"
LAN_CIDR="${LAN_CIDR:-192.168.1.0/24}"

mkdir -p "$(dirname "$OUTPUT")"

sed \
  -e "s#__SERVER_IP__#${SERVER_IP}#g" \
  -e "s#__LAN_CIDR__#${LAN_CIDR}#g" \
  -e "s#__ADMIN_USER__#admin#g" \
  -e "s#__ADMIN_PASSWORD__##g" \
  "$TEMPLATE" > "$OUTPUT"

chmod 600 "$OUTPUT"

echo "Rendered AdGuard template:"
echo "  $OUTPUT"
echo ""
echo "Review it before applying to /opt/AdGuardHome/AdGuardHome.yaml."
