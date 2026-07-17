# macOS Remote Smoke Testing

This project can test a local macOS client against a public Linux server.

## No-TUN NAT smoke

This does not require root and does not change local routes:

```bash
scripts/mac-remote-smoke.sh
```

Success means both diagnostics report:

```json
"state": "direct"
"active_path": "direct"
```

## Real macOS TUN smoke

This creates a macOS `utunN` interface and installs a temporary route for
`10.20.0.0/16`, so it requires root:

```bash
sudo -E scripts/mac-remote-smoke.sh --tun
```

Success means:

- The macOS peer reaches the Linux peer VIP with `ping`.
- The Linux peer reaches the macOS peer VIP with `ping`.
- Both directions report `0% packet loss`.

The script cleans up the local daemon, the remote daemon, the remote route, and
the local `10.20.0.0/16` route on exit. If interrupted hard, clean manually:

```bash
sudo route -n delete -net 10.20.0.0 -netmask 255.255.0.0 2>/dev/null || true
ssh -i ~/.ssh/ali.pem root@47.109.40.237 \
  'for p in $(pgrep -f "^/tmp/p2wlan-remote-test/" || true); do kill -9 $p; done; ip route del 10.20.0.0/16 2>/dev/null || true; ip link del p2wmali 2>/dev/null || true'
```

Useful overrides:

```bash
ALI_HOST=47.109.40.237 \
ALI_KEY=~/.ssh/ali.pem \
STUN_SERVER=74.125.250.129:19302 \
scripts/mac-remote-smoke.sh
```
