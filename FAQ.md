# NetSpecter FAQ

## Why Does NetSpecter Need To Be Bridged?

Traffic totals and live device usage come from lightweight `nftables` counters managed by the NetSpecter collector.

Those counters can only measure packets that cross the appliance. For full traffic visibility, NetSpecter must remain inline as a transparent bridge:

```text
Internet / Router <-> NetSpecter bridge (br0) <-> Switch or Access Point <-> Devices
```

When a phone, TV or computer sends traffic through `br0`, NetSpecter can measure download and upload bytes for that device without running a heavy traffic-analysis platform.

Bridge mode enables:

* Per-device download and upload totals
* Live throughput
* Historical traffic usage
* Estimated monitored-app data usage
* Monitored app destination map volumes

## Can I Run NetSpecter Without A Bridge?

Yes, but only as a DNS analytics appliance. If client devices use AdGuard Home on the NetSpecter box as their DNS server, NetSpecter can still show:

* DNS/application activity
* Blocked services and blocked queries
* DNS client IP addresses
* Domains queried by each client

It cannot accurately show per-device data usage or live traffic if internet packets go directly between the router and clients without crossing `br0`.

| Deployment | DNS/App Views | Blocked Views | Per-Device Traffic Totals | Live Throughput | Destination Traffic Map |
| --- | --- | --- | --- | --- | --- |
| Bridged inline appliance | Yes | Yes | Yes | Yes | Yes |
| DNS-only appliance | Yes | Yes | No | No | No |

## Does Bridge Mode Slow My Internet Connection?

Bridge mode is required for measurement, but the NetSpecter collector is designed to be lightweight. It reads kernel `nftables` counters instead of capturing and deeply processing every packet in a separate analytics engine.

Actual throughput still depends on the appliance hardware, network adapters, cabling, and bridge configuration. A useful check is to run the manual Speed Test from the NetSpecter dashboard or the official Ookla client on the appliance after installation.

## Does The Bridge Replace My Router?

No. The existing router still handles routing, internet connectivity and normally DHCP. NetSpecter is a transparent inline bridge and AdGuard DNS analytics/filtering appliance.

## Does AdGuard Home Need Bridge Mode?

No. AdGuard Home requires devices to use it as their DNS server. Bridge mode is required by NetSpecter's traffic-measurement features, not by DNS filtering itself.

## What Should I Configure?

For the full dashboard:

1. Place the two-port NetSpecter appliance inline between the router and LAN switch or access point.
2. Configure both Ethernet ports as members of `br0`.
3. Give the appliance address to `br0`, not the physical bridge ports.
4. Set LAN devices, usually through router DHCP DNS settings, to use AdGuard Home on the NetSpecter address.
5. Set NetSpecter's Live Traffic Interface to `br0`.

For bridge creation and verification commands, return to the [README bridge installation section](README.md#before-installation-network-interfaces-and-bridge).
