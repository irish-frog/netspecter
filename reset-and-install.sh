#!/bin/bash
set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
  echo "Please run as root." >&2
  exit 1
fi

echo "Stopping and removing old broken services..."
systemctl stop netlifyx-web netlifyx-collector netspecter-web netspecter-collector netspecter-live netspecter-watchdog.timer netspecter-watchdog.service 2>/dev/null || true
systemctl disable netlifyx-web netlifyx-collector netspecter-web netspecter-collector netspecter-live netspecter-watchdog.timer netspecter-watchdog.service 2>/dev/null || true
rm -f /etc/systemd/system/netlifyx-web.service /etc/systemd/system/netlifyx-collector.service
rm -f /etc/systemd/system/netspecter-web.service /etc/systemd/system/netspecter-collector.service /etc/systemd/system/netspecter-live.service
rm -f /etc/systemd/system/netspecter-watchdog.service /etc/systemd/system/netspecter-watchdog.timer
systemctl daemon-reload
systemctl reset-failed || true

echo "Removing old app folders..."
rm -rf /root/netlifyx /root/netspecter /opt/netspecter

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
bash ./install.sh
