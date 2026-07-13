<p align="center">
  <img src="static/netspecter-logo-sidebar.png" width="240" alt="NetSpecter logo">
</p>

<h1 align="center">NetSpecter</h1>

<p align="center">
  A lightweight inline network visibility and DNS analytics appliance.
</p>

NetSpecter is the original lightweight appliance for home networks, very small networks, and older hardware. It provides live traffic visibility, DNS analytics, device discovery, service health checks, exports, and optional integrations through one web interface.

## Which Version Should You Use?

Use this original NetSpecter when you want a simpler appliance with lower hardware demands.

Use [NetSpecter v2](https://github.com/irish-frog/netspecter-v2) if you have better hardware or want the newer feature set, including expanded monitoring, IDS incident workflows, MaxMind GeoLite2 mapping, backup/restore tooling, telemetry, and broader appliance health views.

## What NetSpecter Does

| Area | Capability |
|---|---|
| Network visibility | Live devices, traffic, bridge counters, and per-device history |
| DNS analytics | AdGuard Home query logs, blocked domains, services, and client names |
| Device discovery | Local device inventory, vendor classification, UniFi imports, and manual labels |
| Traffic history | Historical traffic views when retention is configured |
| Monitoring | Service health checks and stale collector detection |
| Speed tests | Manual and optional scheduled speed-test history |
| IDS review | Suricata log review when Suricata is available |
| Integrations | Optional UniFi, SNMP, MQTT, Gatus, Beszel, and Telegram links |
| Exports | CSV exports for selected views |
| Web access | Login-protected dashboard |

## Network Layout

```text
Internet -> Router -> NetSpecter bridge -> Switch -> Client devices
```

NetSpecter is designed to sit inline between the router and the LAN switch. Bridge mode is recommended for best traffic visibility.

DNS analytics require clients to use AdGuard Home on the NetSpecter appliance as DNS.

## Hardware

| Use case | CPU | RAM | Storage | Network |
|---|---:|---:|---:|---|
| Minimum | 2 cores | 4 GB | 32 GB SSD | 2 Ethernet ports |
| Recommended | 4 cores | 8 GB | 64 GB SSD | 2 reliable Ethernet ports |

Use an SSD rather than a USB flash drive. Two physical Ethernet ports are required for the supported inline bridge deployment.

The original NetSpecter can run on older low-power hardware such as a Celeron J1900 quad-core system with 8 GB RAM and a 32 GB SSD, or similar.

For heavier IDS use, longer retention, more monitors, telemetry, or faster links, use [NetSpecter v2](https://github.com/irish-frog/netspecter-v2).

## Quick Install

Fresh Debian appliance, run as `root`:

```bash
apt update
apt install -y git curl nano
cd /root
git clone https://github.com/irish-frog/netspecter.git
cd netspecter
bash ./install.sh
```

Then open:

```text
http://YOUR-NETSPECTER-IP:5050
```

## Bridge Setup Summary

Warning: bridge changes can disconnect SSH. Configure the bridge from a local keyboard/monitor or out-of-band console when possible.

Identify the two physical NICs:

```bash
ip -br link
ip -br addr
ip route
```

Back up network config:

```bash
cp -a /etc/network/interfaces /etc/network/interfaces.before-netspecter
apt install -y bridge-utils
nano /etc/network/interfaces
```

Example `/etc/network/interfaces`:

```ini
auto lo
iface lo inet loopback

auto br0
iface br0 inet static
    address 192.168.1.10/24
    gateway 192.168.1.1
    dns-nameservers 192.168.1.1
    bridge_ports enp1s0 enp2s0
    bridge_stp off
    bridge_fd 0
    bridge_maxwait 0

iface enp1s0 inet manual
iface enp2s0 inet manual
```

Change these before saving:

- `192.168.1.10/24` to the NetSpecter management IP
- `192.168.1.1` to the router IP
- `enp1s0 enp2s0` to the real bridge NICs

The management IP belongs on `br0`. Do not put IP addresses on the physical bridge ports.

Reboot and verify:

```bash
reboot
ip -br addr show br0
bridge link
ip route
ping -c 3 1.1.1.1
```

## AdGuard DNS

For DNS analytics, clients must use NetSpecter/AdGuard Home as DNS.

In router DHCP/LAN settings:

```text
Router DHCP DNS: YOUR-NETSPECTER-IP
```

Test from a LAN client:

```bash
nslookup google.com YOUR-NETSPECTER-IP
```

Expected result:

- AdGuard Home shows query log activity.
- NetSpecter shows DNS and application activity.

## Optional Integrations

| Integration | Purpose |
|---|---|
| UniFi | Import client names, MAC addresses, and device details |
| SNMP | Poll supported network devices |
| MQTT | Subscribe to telemetry topics |
| Gatus | Companion service-monitor links |
| Beszel | Companion metrics links |
| Telegram | Optional alert delivery where configured |
| Suricata | IDS alert review when logs are available |

## Updates

Run as `root` from the installed appliance path:

```bash
cd /opt/netspecter
git fetch origin
git checkout main
git pull --ff-only origin main
systemctl restart netspecter-web
systemctl restart netspecter-collector
```

## Important Notes

- NetSpecter is a visibility appliance; it does not replace the router or firewall.
- DNS blocking is a soft control and can be bypassed by cached DNS, direct IP connections, VPNs, or DNS-over-HTTPS.
- Bridge deployment requires two physical Ethernet ports.
- UniFi, SNMP, MQTT, Gatus, Beszel, Telegram, and Suricata are optional.
- For the fuller current feature set, use [NetSpecter v2](https://github.com/irish-frog/netspecter-v2).

## Project Status

This repository contains the original NetSpecter appliance. It remains useful for simpler deployments, older hardware, and very small networks. NetSpecter v2 is the newer feature-rich appliance line.
