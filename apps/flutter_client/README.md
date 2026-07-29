# P2WLAN Flutter Client

Read-only P1 Flutter prototype for the P2WLAN local daemon diagnostics API.

This app follows `docs/adr/0002-flutter-rust-client-migration.md`:

- Reads `GET /health`.
- Reads `GET /status`.
- Does not call `POST /shutdown`.
- Does not start, stop, elevate, or configure the daemon.
- Does not modify routes, TUN, Wintun, utun, Android VpnService, or iOS Network Extension.

## Run

```bash
cd apps/flutter_client
flutter run -d macos
```

To point the UI at a manually started daemon, open Settings and set the
diagnostics URL. The default is:

```text
http://127.0.0.1:39277/status
```

## Real Daemon Smoke

This P1 prototype never starts, stops, elevates, or shuts down the daemon. Run
the daemon yourself in a separate terminal, then use this Flutter app as a
read-only viewer.

Before opening Flutter, confirm the daemon endpoint manually:

```bash
curl -fsS http://127.0.0.1:39277/health
curl -fsS http://127.0.0.1:39277/status
```

If the existing Tauri client started the daemon on another local diagnostics
port, use that URL in Flutter Settings instead. The Flutter app is only a
consumer of `GET /health` and `GET /status`.

One no-TUN smoke option is:

```bash
# Terminal 1, from the repository root.
cargo build -p p2pnet-daemon
P2WLAN_DISABLE_TUN=1 \
  target/debug/p2pnet-daemon \
  --manual \
  --config /tmp/p2wlan-flutter-smoke-config.json \
  --diagnostics-bind 127.0.0.1:39277
```

Then open the Flutter client:

```bash
# Terminal 2.
cd apps/flutter_client
flutter run -d macos
```

Expected smoke result:

- Dashboard changes from Offline to Online.
- Dashboard shows node ID, virtual IP, network ID, daemon health, UDP local addr,
  relay status, and peer count from `GET /status`.
- Diagnostics shows summary fields and raw JSON from `GET /status`.
- Settings can change only the local diagnostics URL used by the Flutter app.
- The Flutter app does not call `POST /shutdown`; stop the manually started
  daemon from Terminal 1 when the smoke is complete.

## Memory Baseline

Memory comparisons must include both UI and daemon RSS. A lower UI RSS alone is
not enough if the total `UI + p2pnet-daemon` RSS regresses.

macOS read-only snapshot:

```bash
# Start the Tauri client manually, if measuring the existing route.
# Start the Flutter client manually, if measuring the P1 route.
# Start or reuse p2pnet-daemon manually before taking connected samples.

apps/flutter_client/scripts/memory_baseline_macos.sh
```

The script reads `ps` output only. It does not start, stop, elevate, terminate, or
configure any process, and it intentionally does not print daemon command-line
arguments because they can contain tokens.

Recommended samples:

```bash
SAMPLES=3 INTERVAL_SEC=10 apps/flutter_client/scripts/memory_baseline_macos.sh
```

Record these fields for each scenario:

- Tauri UI RSS.
- Flutter UI RSS.
- `p2pnet-daemon` RSS.
- Tauri UI + daemon total RSS.
- Flutter UI + daemon total RSS.

Suggested scenarios:

- Offline UI idle: UI open, daemon not running.
- Daemon reachable: manually started daemon, Dashboard visible.
- Diagnostics view: Diagnostics page open after three refreshes.
- Long idle: repeat after 30 minutes without restarting either UI or daemon.

Windows/Linux TODO:

- Windows: use PowerShell `Get-Process` for `p2wlan`, `p2wlan_flutter_client`,
  and `p2pnet-daemon`, then compare `WorkingSet64`.
- Linux: use `ps -o pid,rss,comm,args -C p2wlan -C p2wlan_flutter_client -C
  p2pnet-daemon` or `/proc/<pid>/status` `VmRSS`.

## Validate

```bash
cd apps/flutter_client
flutter analyze
flutter test
flutter build macos --debug
```

## P1 Acceptance Checklist

- [ ] `flutter analyze` passes.
- [ ] `flutter test` passes.
- [ ] Offline daemon state renders without crashing.
- [ ] Manually started daemon is visible through `GET /health` and `GET /status`.
- [ ] Fixture parsing covers node ID, virtual IP, network ID, UDP local addr,
      relay status, peer path, and peer connection type.
- [ ] No code calls `POST /shutdown`.
- [ ] No code starts, stops, elevates, or configures `p2pnet-daemon`.
- [ ] No code modifies routes, TUN, Wintun, utun, Android VpnService, or iOS
      Network Extension.
- [ ] Real daemon smoke documents manual daemon startup and Flutter read-only
      verification.
- [ ] Memory baseline records Tauri UI RSS, Flutter UI RSS, daemon RSS, and both
      UI + daemon totals.
- [ ] Git diff does not include `src/`, `src-tauri/`, `client/daemon`,
      `client/cli`, or `server` behavior changes.
