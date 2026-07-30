# p2wlan-tray

Tiny native tray controller for P2WLAN.

The tray process is intentionally separate from both the Flutter UI and the
network daemon:

- `p2wlan-daemon` owns TUN/utun/Wintun, routes, crypto, NAT traversal, relay,
  control-plane registration, diagnostics, and shutdown.
- `p2wlan-tray` owns the desktop menu bar / system tray presence.
- Flutter owns the full dashboard and settings UI and can be opened on demand.

This keeps the normal idle path small: users can close the Flutter frontend
while the daemon keeps the tunnel up, with only this lightweight native tray
process left for quick status and controls.

## Run

```bash
cargo build -p p2wlan-tray
target/debug/p2wlan-tray
```

Menu actions:

- `Refresh Status`: polls `http://127.0.0.1:39277/health` and `/status`.
- `Start Daemon`: launches `p2wlan-daemon` with the default config path.
  On macOS this uses the system administrator prompt.
- `Stop Daemon`: sends `POST /shutdown`.
- `Open P2WLAN`: opens the Flutter frontend when deeper settings or
  diagnostics are needed.
- `Quit Tray`: exits only the tray process; it does not stop the daemon.

## Scope

This is a minimal tray first. It deliberately does not duplicate the Flutter
configuration UI. Start/stop/status live here; rich diagnostics and account
flows stay in Flutter.
