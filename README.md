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

* Real-time device traffic visibility
* DNS analytics from AdGuard Home
* Device discovery, AdGuard client names, UniFi client imports, and vendor classification
* Historical traffic views up to 90 days when retention is configured
* Bridge-mode kernel traffic accounting
* Speed test history with optional scheduled tests
* IDS alert review from Suricata logs when the engine is available, with exclusions, bans, and SMTP alerting
* Optional SNMP polling and MQTT subscriptions for device telemetry
* Login-protected dashboard
* CSV exports, service health checks, and one-click collector restart when stale

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

Need to know why the appliance is bridged? See the [FAQ: Why Does NetSpecter Need To Be Bridged?](FAQ.md).

---

## Before Installation: Network Interfaces And Bridge

NetSpecter is designed to sit inline between the router and the LAN switch. A transparent bridge requires two physical Ethernet interfaces:

```text
Router / Gateway ---- NetSpecter port 1 | br0 | NetSpecter port 2 ---- LAN Switch
```

Do the bridge change from a local keyboard/monitor or out-of-band console. Changing the interface carrying an SSH session can disconnect you.

### Find Your Network Interface Names

Debian interface names vary by hardware. Identify them before creating `br0`:

```bash
ip -br link
ip -br addr
ip route
```

Example output may show:

```text
lo               UNKNOWN        127.0.0.1/8
enp1s0           UP
enp2s0           UP
```

Determine which cable is router-facing and which is switch-facing. One simple method is to unplug one cable briefly and rerun:

```bash
ip -br link
```

The interface that changes to `DOWN` is the disconnected port. Write down both names before continuing.

For example, if your two connected interfaces are:

```text
enp4s0    router-facing port
enp5s0    switch-facing port
```

then use those exact names in the bridge configuration:

```ini
    bridge_ports enp4s0 enp5s0

iface enp4s0 inet manual
iface enp5s0 inet manual
```

### Create The Bridge

Back up the Debian network configuration:

```bash
cp -a /etc/network/interfaces /etc/network/interfaces.before-netspecter
apt install -y bridge-utils
nano /etc/network/interfaces
```

The following is file content to paste into `/etc/network/interfaces`; it is not a list of commands to run at the Bash prompt.

This configuration matches a working NetSpecter bridge layout, using an example appliance address of `192.168.1.10`, a gateway at `192.168.1.1`, and physical interfaces `enp1s0` and `enp2s0`:

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

Replace the IPs and physical interface names for your network:

* Replace `enp1s0` with your router-facing NIC name.
* Replace `enp2s0` with your switch-facing NIC name.
* Replace those names in both `bridge_ports` and the `iface ... inet manual` lines.
* Leave the appliance IP address on `br0` only; do not give either physical bridge port its own IP address.

### Keep Bridge Ports Active On Reboot

The bridge configuration above is sufficient for the two NICs inside the bridge:

```ini
auto br0
    bridge_ports enp1s0 enp2s0
```

When Debian brings up `br0` during boot, it also brings `enp1s0` and `enp2s0` into the bridge. On a working NetSpecter system, verification should show:

```text
enp1s0  UP ... master br0 state forwarding
enp2s0  UP ... master br0 state forwarding
br0     UP ... 192.168.1.10/24
```

Do not give `enp1s0` or `enp2s0` their own IP addresses. The address belongs on `br0`.

If the appliance has an extra unused NIC that you intentionally want raised at boot, for example `enp4s0`, add it separately without placing it in the bridge:

```ini
auto enp4s0
iface enp4s0 inet manual
    up ip link set dev enp4s0 up
    down ip link set dev enp4s0 down
```

Only add that block for a NIC you need active. It is not required for the two bridge ports and it does not make `enp4s0` part of monitored bridge traffic.

Reboot to apply the network configuration:

```bash
reboot
```

After reboot, verify the bridge:

```bash
ip -br addr show br0
bridge link
ip route
ping -c 3 1.1.1.1
```

Expected results:

* `br0` has the NetSpecter appliance IP address.
* Both physical ports appear as bridge members.
* Both physical bridge ports show `state forwarding` after reboot.
* The default route points to your gateway through `br0`.
* LAN devices continue to access the router through the appliance.

---

## Supported OS

Recommended:

* Debian 12 Bookworm

Run the installer as `root`.

---

## FAQ

* [Why does NetSpecter need to be bridged?](FAQ.md#why-does-netspecter-need-to-be-bridged)
* [Can it run as DNS-only without a bridge?](FAQ.md#can-i-run-netspecter-without-a-bridge)
* [Does bridge mode slow the internet connection?](FAQ.md#does-bridge-mode-slow-my-internet-connection)

---

## Quick Install

```bash
apt update && apt install git -y

cd /root
git clone https://github.com/irish-frog/netspecter.git
cd netspecter

bash ./install.sh
```

The installer:

* Updates Debian and installs initial setup tools
* Installs AdGuard Home and continues while its browser setup remains available
* Installs `suricata-update` for IDS rule management and installs Suricata when the package is available
* Installs bridge, packet capture, nftables, SNMP, speed test, and Python runtime dependencies
* Installs NetSpecter to `/opt/netspecter`
* Creates config in `/etc/netspecter`
* Stores runtime data in `/var/lib/netspecter`
* Installs systemd services, watchdog timer, and scheduled speed test timer

---

## First Run

On a new appliance, AdGuard Home first opens its setup wizard on port `3000`. Open:

```text
http://SERVER-IP:3000
```

The installer continues and installs NetSpecter in the same run. Follow the step-by-step [AdGuard Home Setup Guide](ADGUARD-SETUP.md), setting the AdGuard web/admin port to `80` as recommended.

Open NetSpecter at:

```text
http://SERVER-IP:5050
```

To use local names, add AdGuard DNS rewrites and keep the service port in the URL. For example, `netspecter -> SERVER-IP` opens as `http://netspecter:5050`.

UniFi device-name lookup uses the local gateway only. Enter a URL like `https://192.168.99.1/proxy/network/integration`, use a local UniFi username and password, and enable self-signed certificates if your gateway uses its built-in HTTPS cert.

If no admin password exists, NetSpecter redirects to:

```text
/setup-admin
```

After creating the admin login, NetSpecter checks whether deployment settings are complete. If key values are still missing or generic, it redirects to Settings.

Configure:

* Gateway IP
* LAN prefix
* Live traffic interface, usually `br0`
* AdGuard URL/user/password
* Traffic retention days, use `90` to keep the full 90-day traffic view
* DNS/App retention days, use `90` to keep the full 90-day application history
* Optional UniFi, SNMP, MQTT, speed test, and IDS/email integrations

Service passwords are encrypted in `/etc/netspecter/config.json` after saving Settings.

Existing appliances keep their saved retention values during upgrades. To use the 60-day and 90-day range buttons on upgraded installs, open Settings and raise both retention values to `90`.

---

## Optional Integrations

### UniFi Device Discovery

If you own a UniFi console, NetSpecter can import client names, IP addresses, and MAC addresses from the UniFi Network API connector. This helps Devices show friendly names even when a client's traffic does not cross the NetSpecter bridge.

Configure it from Integrations:

* Enable UniFi Device Discovery
* Enter the connector URL for your local gateway, such as `https://192.168.99.1/proxy/network/integration`
* Enter the local UniFi username and password
* Use Find Site Automatically, or enter the site ID manually
* Enable the self-signed certificate option only for local UniFi gateways that need it

The local UniFi password is encrypted in NetSpecter's local config and is never committed to GitHub.

### SNMP And MQTT Telemetry

NetSpecter can pull telemetry from existing devices using SNMP and subscribe to an existing MQTT broker. It does not act as an SNMP server or MQTT broker.

Use Settings to configure SNMP targets and MQTT topics, then open Telemetry to see the latest readings. See the [SNMP and MQTT Telemetry wiki page](wiki/SNMP-MQTT-Telemetry.md) for setup notes and troubleshooting.

### Speed Tests

Manual speed tests are stored automatically. Optional scheduled speed tests can run up to five times per day and are shown in Speed Tests history. Scheduled tests consume internet data, so they are disabled by default.

### IDS Alerts

If Suricata is installed on the appliance and writing `/var/log/suricata/fast.log`, NetSpecter can show recent IDS alerts, summarize noisy signatures, ignore expected source IPs, show only unknown source IPs, add IPs to a local nftables ban list, and send SMTP email notifications.

---

## Updates

When NetSpecter detects a newer GitHub version, Dashboard shows an update button near the range controls. The System page can also run the same update flow.

The update action performs a fast-forward Git pull and reruns the installer while preserving `/etc/netspecter/config.json`.

### Destination Map Privacy Note

The Network Map plots approximate destinations for monitored application delivery traffic only. To locate remote endpoints, the collector sends a remote destination IP address, never a LAN client IP address, to `https://ipwho.is/`. Location results are cached locally and refreshed no more than once per hour per destination.

### Point Your Router DNS To NetSpecter

For AdGuard and NetSpecter DNS analytics to work, devices on your LAN must use the NetSpecter appliance as their DNS server.

Open your router's DHCP or LAN DNS settings and set the DNS server given to client devices to the IP address assigned to NetSpecter `br0`.

Example:

```text
NetSpecter br0 IP: 192.168.1.10
Router DHCP DNS:   192.168.1.10
```

Use your own NetSpecter IP address, not the example above. After saving the router change, reconnect devices or renew their DHCP leases so they start using AdGuard DNS.

You can confirm DNS is reaching NetSpecter from a LAN computer:

```bash
nslookup google.com YOUR-NETSPECTER-IP
```

Requests should then appear in the AdGuard Query Log and in NetSpecter DNS/application views.

For friendly local names, add AdGuard DNS rewrites such as `netspecter -> YOUR-NETSPECTER-IP`. DNS cannot include `:5050`, so keep the port in the browser URL: `http://netspecter:5050`.

---

## Project Status

Alpha / active development.
