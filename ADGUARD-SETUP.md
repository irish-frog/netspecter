# AdGuard Home Setup Guide For NetSpecter

This guide uses the AdGuard Home web interface. Do not copy a YAML file over your live AdGuard configuration.

The example network used below is:

```text
NetSpecter / AdGuard IP: 192.168.1.10
Gateway / router IP:     192.168.1.1
LAN network:             192.168.1.0/24
AdGuard web page:        http://192.168.1.10
ntopng web page:         http://192.168.1.10:3000
NetSpecter web page:     http://192.168.1.10:5050
```

Replace `192.168.1.10` with the IP address assigned to `br0` on your NetSpecter appliance.

## 1. Start The AdGuard Installer Stage

From the cloned NetSpecter repository, run:

```bash
cd /root/netspecter
./install.sh
```

On a new installation the script installs AdGuard Home first, then pauses before installing ntopng. This matters because AdGuard uses port `3000` for its setup wizard, and ntopng uses port `3000` after setup is finished.

## 2. Open The AdGuard Setup Wizard

From a browser on your LAN, open:

```text
http://192.168.1.10:3000
```

On the first configuration page, set:

| Setting | Recommended value |
| --- | --- |
| Admin Web Interface | All interfaces / `0.0.0.0` |
| Admin Web Port | `80` |
| DNS Server Interface | All interfaces / `0.0.0.0` |
| DNS Server Port | `53` |

Port `80` is important because it releases port `3000` for ntopng.

Create your AdGuard administrator username and password when prompted. Keep that password private; you will enter it in NetSpecter Settings later.

When the wizard finishes, check that this opens:

```text
http://192.168.1.10
```

## 3. Finish The NetSpecter Install

Return to the Debian terminal and run the installer a second time:

```bash
cd /root/netspecter
./install.sh
```

The second run installs ntopng, Redis, NetSpecter and its systemd services.

## 4. Recommended DNS Settings

In AdGuard Home, open **Settings > DNS settings**.

### Upstream DNS servers

Set these upstream servers:

```text
https://dns.quad9.net/dns-query
https://cloudflare-dns.com/dns-query
```

### Bootstrap DNS servers

Set:

```text
9.9.9.9
1.1.1.1
```

### Other DNS Settings

Use these recommended settings:

| Setting | Recommended value |
| --- | --- |
| DNS cache | Enabled |
| Optimistic caching | Enabled |
| Rate limit | `20` |
| DNSSEC | Off initially |
| Blocking mode | Default |

Keep DNSSEC off initially so that basic DNS and dashboard collection can be confirmed first. You can enable it later after the appliance is stable.

Click **Save**.

## 5. Recommended Query Log And Statistics

NetSpecter reads AdGuard activity to show domains, applications and blocked queries.

Open the AdGuard general or query-log settings page and set:

| Setting | Recommended value |
| --- | --- |
| Query log | Enabled |
| Query log retention | `72 hours` / `3 days` |
| Statistics | Enabled |
| Statistics retention | `168 hours` / `7 days` |
| Anonymize client IP | Disabled |

Do not anonymize client IP addresses if you want NetSpecter to associate DNS use with individual devices.

## 6. Recommended Filter Lists

Open **Filters > DNS blocklists** and ensure these lists are enabled:

| Filter list | URL |
| --- | --- |
| AdGuard DNS filter | `https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt` |
| AdAway Default Blocklist | `https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt` |

Click **Check for updates** after adding them.

## 7. Recommended Allow Rules

Open **Filters > Custom filtering rules** and add:

```text
@@||dns.msftncsi.com^
@@||connectivitycheck.gstatic.com^
```

These rules allow common internet-connectivity checks so devices do not incorrectly report that the internet is offline.

## 8. Make Devices Use AdGuard DNS

AdGuard can only report client DNS activity when your devices actually use it for DNS.

Recommended method: set the DNS server handed out by your router's DHCP service to:

```text
192.168.1.10
```

Then reconnect client devices or renew their DHCP leases.

To test DNS from another LAN device:

```bash
nslookup google.com 192.168.1.10
```

Queries should begin appearing in the AdGuard query log.

## 9. Configure NetSpecter To Read AdGuard

Open NetSpecter:

```text
http://192.168.1.10:5050
```

After creating the NetSpecter administrator login, open **Settings** and set:

| Setting | Recommended value |
| --- | --- |
| Gateway IP | `192.168.1.1` |
| LAN Prefix | `192.168.1.` |
| Live Traffic Interface | `br0` |
| Fallback Traffic Interface | `br0` |
| AdGuard URL | `http://127.0.0.1` |
| AdGuard User | Your AdGuard administrator username |
| AdGuard Password | Your AdGuard administrator password |
| ntopng URL | `http://127.0.0.1:3000` |

`127.0.0.1` is recommended for AdGuard and ntopng here because all three services run on the same appliance.

## 10. Confirm Everything Works

On Debian, check the services:

```bash
systemctl status AdGuardHome ntopng netspecter-web netspecter-collector --no-pager
```

Open:

```text
AdGuard:    http://192.168.1.10
ntopng:     http://192.168.1.10:3000
NetSpecter: http://192.168.1.10:5050
```

Confirm:

- AdGuard shows queries from LAN devices.
- NetSpecter displays DNS queries and applications after activity occurs.
- NetSpecter shows traffic collected on `br0`.

## Keeping Your Configuration Private

AdGuard stores your live administrator details and site-specific configuration in:

```text
/opt/AdGuardHome/AdGuardHome.yaml
```

Do not upload this file to GitHub. The repository YAML file is only a safe reference template and is not required for setup.
