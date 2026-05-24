<p align="center">
  <img src="static/netspecter-logo-sidebar.png" width="240">
</p>

<h1 align="center">NetSpecter</h1>

<p align="center">
  Real-time Network Visibility and DNS Analytics Platform
</p>

---

## Overview

NetSpecter is a lightweight network visibility appliance for homelabs, small offices, and advanced home networks.

It combines:

- Real-time device traffic visibility
- DNS analytics from AdGuard Home
- Device discovery and vendor classification
- Historical traffic views
- ntopng integration
- Bridge-mode packet monitoring
- Login-protected dashboard
- CSV exports and service health checks

---

## Recommended Layout

```text
Internet
  |
Gateway / Router
  |
NetSpecter Bridge
  |
Switch / LAN
  |
Client Devices
```

Bridge mode is recommended for best traffic visibility. DNS analytics require clients to use AdGuard Home as DNS.

---

## Supported OS

Recommended:

- Debian 12 Bookworm

Run the installer as `root`.

---

## Quick Install

```bash
apt update && apt install git -y

cd /root
git clone https://github.com/irish-frog/netspecter.git
cd netspecter

chmod +x install.sh
./install.sh
```

The installer:

- Updates Debian and installs initial setup tools
- Installs AdGuard Home first and pauses for its browser setup
- Installs ntopng from signed stable Debian 12 `x64/` and `all/` repositories on the second run
- Installs NetSpecter to `/opt/netspecter`
- Creates config in `/etc/netspecter`
- Stores runtime data in `/var/lib/netspecter`
- Installs systemd services and watchdog timer

---

## First Run

On a new appliance, AdGuard Home first opens its setup wizard on port `3000`. Open:

```text
http://SERVER-IP:3000
```

Set the AdGuard web/admin port to `80`, leaving port `3000` available for ntopng. Once AdGuard setup is complete, rerun the installer:

```bash
cd /root/netspecter
./install.sh
```

The second run installs ntopng and NetSpecter. Then open NetSpecter:

```text
http://SERVER-IP:5050
```

If no admin password exists, NetSpecter redirects to:

```text
/setup-admin
```

After creating the admin login, NetSpecter checks whether deployment settings are complete. If key values are still missing or generic, it redirects to Settings.

Configure:

- Gateway IP
- LAN prefix
- Live traffic interface, usually `br0`
- Fallback traffic interface, usually `br0`
- AdGuard URL/user/password
- ntopng URL/user/password/interface ID

Service passwords are encrypted in `/etc/netspecter/config.json` after saving Settings.

---

## AdGuard Home Template

NetSpecter includes a safe AdGuard Home YAML template:

```text
adguard/AdGuardHome.yaml.example
```

This template contains most useful DNS/querylog/filtering defaults, but does not include private deployment values such as your real LAN IP, user password hash, or persistent clients.

During install, NetSpecter renders:

```text
/etc/netspecter/adguard/AdGuardHome.yaml.generated
```

Review it before applying.

To render manually:

```bash
/opt/netspecter/scripts/render-adguard-template.sh
```

To provide explicit values:

```bash
NETSPECTER_SERVER_IP=192.168.1.10 \
NETSPECTER_LAN_CIDR=192.168.1.0/24 \
/opt/netspecter/scripts/render-adguard-template.sh
```

The installer does not overwrite the configuration created by the AdGuard setup wizard. Use the generated file as a safe reference when adding filtering and query-log options to the live configuration.

The installer will not overwrite an existing:

```text
/opt/AdGuardHome/AdGuardHome.yaml
```

This is intentional. Keep live AdGuard configs private.

---

## Important Files

```text
/opt/netspecter/app.py
/opt/netspecter/live_packet_collector.py
/etc/netspecter/config.json
/etc/netspecter/secret.key
/etc/netspecter/session.key
/var/lib/netspecter/netspecter.db
```

Do not commit runtime files or secrets to GitHub.

The repository includes:

```text
config.example.json
adguard/AdGuardHome.yaml.example
```

The repository ignores:

```text
config.json
netspecter.db
cache.json
session.key
secret.key
AdGuardHome.yaml
venv/
```

---

## Services

```bash
systemctl status netspecter-web
systemctl status netspecter-collector
systemctl status netspecter-watchdog.timer
```

Restart:

```bash
systemctl restart netspecter-web
systemctl restart netspecter-collector
```

Logs:

```bash
journalctl -u netspecter-web -f
journalctl -u netspecter-collector -f
```

Watchdog timer:

```bash
systemctl list-timers | grep netspecter
```

---

## Bridge Setup

Identify interfaces:

```bash
ip -br addr
```

Example `/etc/network/interfaces`:

```ini
auto lo
iface lo inet loopback

auto br0
iface br0 inet static
    address 192.168.1.10/24
    gateway 192.168.1.1
    dns-nameservers 9.9.9.9 1.1.1.1
    bridge_ports enp1s0 enp2s0
    bridge_stp off
    bridge_fd 0
    bridge_maxwait 0

iface enp1s0 inet manual
iface enp2s0 inet manual
```

Then configure NetSpecter Settings:

```text
Live Traffic Interface: br0
Fallback Traffic Interface: br0
Gateway IP: your router IP
LAN Prefix: your LAN prefix
```

---

## Updating

From a cloned repository:

```bash
cd /root/netspecter
git pull
./install.sh
```

The installer preserves existing:

```text
/etc/netspecter/config.json
/opt/AdGuardHome/AdGuardHome.yaml
```

---

## Project Status

Alpha / active development.
