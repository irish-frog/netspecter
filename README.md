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

- Replace `enp1s0` with your router-facing NIC name.
- Replace `enp2s0` with your switch-facing NIC name.
- Replace those names in both `bridge_ports` and the `iface ... inet manual` lines.
- Leave the appliance IP address on `br0` only; do not give either physical bridge port its own IP address.

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

- `br0` has the NetSpecter appliance IP address.
- Both physical ports appear as bridge members.
- Both physical bridge ports show `state forwarding` after reboot.
- The default route points to your gateway through `br0`.
- LAN devices continue to access the router through the appliance.

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

Follow the step-by-step [AdGuard Home Setup Guide](ADGUARD-SETUP.md) during this stage.

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

## Updating

To update NetSpecter after it has already been installed:

```bash
cd /root/netspecter
git pull
./install.sh
```

Rerunning the installer updates application files and services while preserving your live configuration:

```text
/etc/netspecter/config.json
/opt/AdGuardHome/AdGuardHome.yaml
```

---

## Project Status

Alpha / active development.
