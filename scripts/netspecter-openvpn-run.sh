#!/bin/bash
set -euo pipefail

PROFILE="/etc/netspecter/vpn/client.ovpn"
AUTH_FILE="/etc/netspecter/vpn/auth.txt"

if [ ! -s "$PROFILE" ]; then
  echo "No OpenVPN client profile uploaded: $PROFILE" >&2
  exit 1
fi

# Keep this first phase from changing the appliance or LAN routes. Selective
# Clients-VLAN routing is added separately once NetSpecter is their gateway.
args=(--config "$PROFILE" --auth-nocache --route-noexec)
if [ -s "$AUTH_FILE" ]; then
  args+=(--auth-user-pass "$AUTH_FILE")
fi

exec /usr/sbin/openvpn "${args[@]}"
