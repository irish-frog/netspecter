# Reverse Proxy And Local Names

NetSpecter can manage a Caddy reverse proxy block from the web UI.

Use it when you want clean LAN URLs such as:

```text
http://netspecter
http://kuma
```

instead of:

```text
http://192.168.99.6:5050
http://192.168.99.6:3001
```

## How It Works

AdGuard Home handles DNS:

```text
netspecter -> 192.168.99.6
kuma       -> 192.168.99.6
```

Caddy handles the port mapping:

```text
netspecter -> 127.0.0.1:5050
kuma       -> 127.0.0.1:3001
```

DNS cannot store the port. The reverse proxy is the part that knows about `5050` and `3001`.

## In NetSpecter

Open:

```text
Reverse Proxy
```

From there you can:

- Add a hostname and target port.
- Remove a hostname.
- Enable or disable the generated Caddy block.
- See the exact Caddy config NetSpecter will write.

NetSpecter manages only the marked block between:

```text
# BEGIN NETSPECTER REVERSE PROXY
# END NETSPECTER REVERSE PROXY
```

in:

```text
/etc/caddy/Caddyfile
```

## Important Port Note

Only one service can use port `80` on the same IP address.

If AdGuard Home already uses port `80`, Caddy cannot also use port `80`. Choose one:

- Keep AdGuard on `80` and keep using `http://netspecter:5050`.
- Move AdGuard's web UI to another port, then use Caddy on `80`.
- Run Caddy on another machine.

## Uptime Kuma

Uptime Kuma usually listens on port `3001`.

Add this reverse proxy host:

```text
Hostname: kuma
Target:   127.0.0.1
Port:     3001
```

Then add an AdGuard DNS rewrite:

```text
kuma -> 192.168.99.6
```

Replace `192.168.99.6` with your NetSpecter appliance IP.
