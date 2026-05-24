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
| Admin Web Interface | NetSpecter bridge address / `192.168.1.10` |
| Admin Web Port | `80` |
| DNS Server Interface | All interfaces / `0.0.0.0` |
| DNS Server Port | `53` |

Port `80` is important because it releases port `3000` for ntopng.

Create your AdGuard administrator username and password when prompted. Keep that password private; you will enter it in NetSpecter Settings later.

When the wizard finishes, check that this opens:

```text
http://192.168.1.10
```

In the AdGuard appearance/general settings, select the **Dark** theme if you want the interface to match the working NetSpecter appliance.

## 3. Finish The NetSpecter Install

Return to the Debian terminal and run the installer a second time:

```bash
cd /root/netspecter
./install.sh
```

The second run installs ntopng, Redis, NetSpecter and its systemd services.

## 4. Set The DNS Servers

Log into AdGuard:

```text
http://192.168.1.10
```

Go to **Settings > DNS settings**.

### Upstream DNS Servers

Find **Upstream DNS servers**. Remove what is in the box and paste these two lines:

```text
https://1.1.1.1/dns-query
https://9.9.9.9/dns-query
```

Set **Upstream mode** to:

```text
Parallel requests
```

### Fallback And Bootstrap Servers

Find **Fallback DNS servers** and paste:

```text
9.9.9.9
1.1.1.1
```

Find **Bootstrap DNS servers** and paste:

```text
1.1.1.1
9.9.9.9
```

### Local Device Names

Find the option for **Private reverse DNS servers** or **Private PTR resolvers**.

Enable the option to use private reverse DNS resolvers, then enter the address of your router:

```text
192.168.1.1
```

Use your own gateway address if it is different. This helps AdGuard show local device names when your router knows them.

Click **Save**.

## 5. Set DNS Safety And Cache Options

Still on **Settings > DNS settings**, set these options:

| Option | Set To |
| --- | --- |
| Rate limit | `20` |
| Enable DNS cache | On |
| Cache size | `8388608` bytes / `8 MB` |
| Optimistic caching | On |
| Enable DNSSEC | On |
| Disable resolution of IPv6 addresses / AAAA | On |
| Blocking mode | Default |

Click **Save** after changing the options.

The working NetSpecter appliance blocks AAAA answers. Leave this on only if you do not use IPv6 on your LAN.

## 6. Set Query Log And Statistics History

NetSpecter needs the AdGuard query log so it can show device DNS usage, domains and applications.

Go to **Settings > General settings** and set:

| Option | Set To |
| --- | --- |
| Enable query log | On |
| Query log retention | `90 days` |
| Enable statistics | On |
| Statistics retention | `1 day` |
| Anonymize client IP addresses | Off |

Click **Save**.

Leave **Anonymize client IP addresses** off. If it is enabled, NetSpecter cannot reliably show which device made a DNS request.

## 7. Add The Blocklists

Go to **Filters > DNS blocklists**.

The **AdGuard DNS filter** may already be present. If it is not shown, add it first. Then choose **Add blocklist > Add a custom list** and add the remaining lists one at a time.

Use these five enabled lists:

| Name | URL |
| --- | --- |
| AdGuard DNS filter | `https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt` |
| Phishing URL Blocklist (PhishTank and OpenPhish) | `https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt` |
| Dandelion Sprout's Anti-Malware List | `https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt` |
| ShadowWhisperer's Malware List | `https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt` |
| Malicious URL Blocklist (URLHaus) | `https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt` |

For each list:

1. Select **Add blocklist**.
2. Choose **Add a custom list** if it is not available in the built-in list.
3. Paste the URL.
4. Enter the matching name.
5. Ensure the list is enabled.

When all five are shown and enabled, click **Check for updates**.

## 8. Set Filtering Options

Go to **Settings > General settings** or the filtering settings screen, depending on the AdGuard version.

Set:

| Option | Set To |
| --- | --- |
| Protection / DNS filtering | On |
| Filter update interval | `24 hours` |
| Safe Browsing | Off |
| Parental Control | Off |
| Safe Search | Off |
| Blocked services | None |

Go to **Filters > Custom filtering rules**. Leave this page empty for the same setup as the working appliance.

## 9. Leave DHCP On The Router

Go to **Settings > DHCP settings**.

Leave **DHCP server** disabled in AdGuard. In this setup:

```text
Router:  gives devices IP addresses
AdGuard: provides DNS filtering and query history
```

Now open your router configuration and change the DNS server handed out by DHCP to the NetSpecter/AdGuard address:

```text
192.168.1.10
```

Replace that with your NetSpecter `br0` address.

Reconnect client devices, or renew their DHCP lease, so they receive the new DNS server.

## 10. Check That AdGuard Is Receiving Queries

From a computer on the LAN, test a DNS lookup through AdGuard:

```bash
nslookup google.com 192.168.1.10
```

In AdGuard, open **Query Log**. You should see the request and the IP address of the client device that made it.

If no requests appear, confirm the client or router is actually using `192.168.1.10` as its DNS server.

## 11. Connect AdGuard To NetSpecter

Open NetSpecter:

```text
http://192.168.1.10:5050
```

Create the NetSpecter admin login when prompted, then open **Settings**.

Enter:

| NetSpecter Setting | Value |
| --- | --- |
| Gateway IP | `192.168.1.1` |
| LAN Prefix | `192.168.1.` |
| Live Traffic Interface | `br0` |
| Fallback Traffic Interface | `br0` |
| AdGuard URL | `http://127.0.0.1` |
| AdGuard User | The AdGuard admin username you created |
| AdGuard Password | The AdGuard admin password you created |
| ntopng URL | `http://127.0.0.1:3000` |

Use your own LAN values in place of the example IP addresses. `127.0.0.1` is correct for AdGuard and ntopng when they are installed on the same NetSpecter appliance.

Click **Save Settings**.

## 12. Final Checks

On the NetSpecter Debian terminal, run:

```bash
systemctl status AdGuardHome ntopng netspecter-web netspecter-collector --no-pager
```

Open each page:

```text
AdGuard:    http://192.168.1.10
ntopng:     http://192.168.1.10:3000
NetSpecter: http://192.168.1.10:5050
```

The installation is working when:

- AdGuard Query Log shows client requests.
- NetSpecter displays DNS queries and applications after devices browse the internet.
- NetSpecter displays traffic collected from `br0`.

## Keep The Live AdGuard File Private

AdGuard stores its administrator account and site-specific values in:

```text
/opt/AdGuardHome/AdGuardHome.yaml
```

Do not upload that live file to GitHub. The YAML example in this repository is only a reference for the settings documented above.
