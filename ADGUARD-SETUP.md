# AdGuard Home Setup Guide For NetSpecter

This guide uses the AdGuard Home web interface. Do not copy a YAML file over your live AdGuard configuration.

## Fill In Your Network Details First

Before following the guide, write down the values for your own network:

| Item | Your Value | Example Used In This Guide |
| --- | --- | --- |
| NetSpecter `br0` IP address | `________________` | `192.168.1.10` |
| Gateway / router IP address | `________________` | `192.168.1.1` |
| LAN network range | `________________` | `192.168.1.0/24` |
| LAN prefix for NetSpecter Settings | `________________` | `192.168.1.` |

You can see the NetSpecter bridge address and gateway on Debian with:

```bash
ip -br addr show br0
ip route
```

Example output:

```text
br0  UP  192.168.1.10/24
default via 192.168.1.1 dev br0
```

The example network used below is:

```text
NetSpecter / AdGuard IP: 192.168.1.10
Gateway / router IP:     192.168.1.1
LAN network:             192.168.1.0/24
AdGuard web page:        http://192.168.1.10
NetSpecter web page:     http://192.168.1.10:5050
```

Throughout this guide:

- Replace `192.168.1.10` with **your NetSpecter `br0` IP address**.
- Replace `192.168.1.1` with **your gateway/router IP address**.
- Replace `192.168.1.0/24` or `192.168.1.` with **your own LAN range/prefix**.

## 1. Complete The AdGuard Setup Wizard

From a browser on your LAN, open:

```text
http://YOUR-NETSPECTER-IP:3000
```

On the first configuration page, set:

| Setting | Recommended value |
| --- | --- |
| Admin Web Interface | Your NetSpecter bridge address, for example `192.168.1.10` |
| Admin Web Port | `80` |
| DNS Server Interface | All interfaces / `0.0.0.0` |
| DNS Server Port | `53` |

Port `80` is recommended so AdGuard has a simple, predictable management address on the appliance.

Create your AdGuard administrator username and password when prompted. Keep that password private; you will enter it in NetSpecter Settings later.

When the wizard finishes, check that this opens:

```text
http://YOUR-NETSPECTER-IP
```

In the AdGuard appearance/general settings, select the **Dark** theme if you want the interface to match the working NetSpecter appliance.

## 2. Set The DNS Servers

Log into AdGuard:

```text
http://YOUR-NETSPECTER-IP
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
YOUR-GATEWAY-IP
```

For example, on the example network this is `192.168.1.1`. This helps AdGuard show local device names when your router knows them.

Click **Save**.

## 3. Set DNS Safety And Cache Options

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

## 4. Set Query Log And Statistics History

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

## 5. Add The Blocklists

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

## 6. Set Filtering Options

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

## 7. Leave DHCP On The Router

Go to **Settings > DHCP settings**.

Leave **DHCP server** disabled in AdGuard. In this setup:

```text
Router:  gives devices IP addresses
AdGuard: provides DNS filtering and query history
```

Now open your router configuration and change the DNS server handed out by DHCP to the NetSpecter/AdGuard address:

```text
YOUR-NETSPECTER-IP
```

For example, on the example network this is `192.168.1.10`.

Reconnect client devices, or renew their DHCP lease, so they receive the new DNS server.

## 8. Check That AdGuard Is Receiving Queries

From a computer on the LAN, test a DNS lookup through AdGuard:

```bash
nslookup google.com YOUR-NETSPECTER-IP
```

In AdGuard, open **Query Log**. You should see the request and the IP address of the client device that made it.

If no requests appear, confirm the client or router is actually using your NetSpecter IP as its DNS server.

## 9. Return To NetSpecter

AdGuard setup is complete when its **Query Log** shows requests from LAN devices.

NetSpecter was installed during the same installer run. Return to the main installation guide to finish configuration:

[Return to the NetSpecter README](README.md#first-run)
