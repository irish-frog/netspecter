# SNMP And MQTT Telemetry

NetSpecter can collect extra device telemetry in two client-side ways:

* SNMP polling: NetSpecter polls devices that already expose SNMP.
* MQTT subscription: NetSpecter subscribes to topics on an existing MQTT broker.

NetSpecter is not an SNMP agent, SNMP trap receiver, MQTT server, or MQTT broker.

## Where To Configure It

Open NetSpecter, go to Settings, and configure the SNMP and MQTT fields.

Sensitive values such as the SNMP community and MQTT password are encrypted in NetSpecter's local config and are not written to GitHub.

## SNMP Polling

Use SNMP when you want NetSpecter to pull basic information from switches, routers, access points, UPS units, printers, or other network devices.

The current collector pass supports SNMP v2c polling.

Required on the target device:

* SNMP enabled
* A read-only community string
* UDP port `161` reachable from the NetSpecter appliance

NetSpecter settings:

* SNMP Enabled: turn polling on
* SNMP Targets: comma-separated IPs or hostnames
* SNMP Version: use `2c`
* SNMP Port: usually `161`
* SNMP Community: read-only community string
* SNMP Poll Seconds: polling interval

The first implementation stores:

* `sys_name`
* `sys_descr`
* `sys_uptime`

You can test a target from the NetSpecter box:

```bash
snmpget -v2c -c COMMUNITY TARGET 1.3.6.1.2.1.1.5.0
```

Replace `COMMUNITY` and `TARGET` with your real values.

## MQTT Subscription

Use MQTT when another system already publishes device, sensor, or network telemetry to a broker.

Required:

* An existing MQTT broker
* Topics that NetSpecter should subscribe to
* Credentials if the broker requires authentication

NetSpecter settings:

* MQTT Enabled: turn subscription on
* MQTT Broker Host: broker IP or hostname
* MQTT Broker Port: usually `1883`, or `8883` for TLS
* MQTT TLS Enabled: enable when your broker requires TLS
* MQTT Username and Password: optional broker credentials
* MQTT Client ID: default is `netspecter`
* MQTT Subscribe Topics: comma-separated topics, for example `sensors/#,home/+/status`

Each received MQTT message is stored as a telemetry reading with source `mqtt`, target set to the topic, and metric `payload`.

## Viewing Readings

Open Telemetry in the NetSpecter menu. It shows the latest SNMP and MQTT readings stored by the collector.

## Troubleshooting

If no readings appear:

* Confirm the collector is running.
* If Health shows the collector as stale, click the collector card to restart it.
* Check the collector logs:

```bash
journalctl -u netspecter-collector -n 100 --no-pager
```

For SNMP:

* Confirm the target allows polling from the NetSpecter IP.
* Confirm the community is read-only and correct.
* Confirm UDP `161` is not blocked.

For MQTT:

* Confirm the broker host and port are reachable from NetSpecter.
* Confirm the topic list matches what the broker publishes.
* Confirm TLS and credentials match the broker configuration.

## Current Limits

SNMP currently stores core identity and uptime values only. MQTT stores raw payloads as received. Future versions can map selected telemetry into device cards, graphs, and alert rules.
