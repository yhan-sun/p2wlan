# P2WLAN Flutter Client

Flutter frontend for the Rust P2WLAN client. This app is intended to replace the
legacy Tauri/WebView desktop shell while keeping the Rust networking core.

The split is:

- Flutter: desktop/mobile UI, settings, status, peer views, and lifecycle
  controls. It exits normally when its window is closed in the default desktop
  flow.
- Rust `p2wlan-tray`: tiny native tray process for idle status, opening the
  Flutter UI on demand, and quick daemon controls without keeping WebView or
  Flutter UI memory resident.
- Rust `p2wlan-daemon`: virtual adapter, routes, crypto, NAT traversal, relay,
  control-plane session, diagnostics, and shutdown.

## Run

```bash
# Build the daemon binary used by the Flutter desktop client.
cargo build -p p2wlan-daemon

# Run the lightweight menu bar / tray controller.
cargo build -p p2wlan-tray
target/debug/p2wlan-tray

# Run Flutter.
cd apps/flutter_client
flutter run -d macos
```

For debugging only, set `P2WLAN_ENABLE_FLUTTER_TRAY=1` before launching Flutter
to use its in-process tray. The normal low-idle-memory path keeps tray and
Flutter as separate processes.

The client looks for `p2wlan-daemon` in this order:

1. `P2WLAN_DAEMON_BIN`
2. Side-by-side with the app executable
3. macOS `.app/Contents/Resources/p2wlan-daemon`
4. Workspace `target/debug` or `target/release`
5. `PATH`

On macOS, starting P2WLAN from the app requests administrator authorization so
`p2wlan-daemon` can create `utun` and install routes. Stop first tries
`POST /shutdown`, then falls back to a verified PID marker.

## macOS Bundle

The macOS Runner has a build phase that runs:

```bash
apps/flutter_client/scripts/bundle_daemon_macos.sh
```

It builds `p2wlan-daemon` for Debug/Release when missing and copies it into the
app bundle Resources directory.

## Diagnostics

The default diagnostics URL is:

```text
http://127.0.0.1:39277/status
```

The app uses:

- `GET /health` for lightweight reachability checks
- `GET /status` for runtime snapshots
- `POST /shutdown` for graceful daemon stop

## Memory Snapshot

Measure the Flutter UI separately from the Rust daemon:

```bash
apps/flutter_client/scripts/memory_baseline_macos.sh
```

Use `CORE_PATTERN` only when you explicitly want a combined UI + daemon number.

For the intended low-idle-memory desktop flow, run `p2wlan-tray` and close the
Flutter window when the dashboard is not needed:

```bash
cargo build -p p2wlan-tray
target/debug/p2wlan-tray
```

## Validate

```bash
cd apps/flutter_client
flutter analyze
flutter test
flutter build macos --release

cd ../..
cargo check -p p2wlan-daemon
```

## Acceptance Checklist

- [x] Flutter exposes `p2wlan-daemon` start from Dashboard.
- [x] Flutter exposes daemon stop through `/shutdown` with PID fallback.
- [x] Dashboard, Diagnostics, and Nodes update from `/status`.
- [x] Flutter in-process tray remains available behind
  `P2WLAN_ENABLE_FLUTTER_TRAY=1` for debugging.
- [x] Rust `p2wlan-tray` builds as a lightweight idle tray companion.
- [ ] macOS release app bundles `p2wlan-daemon` in Resources and passes local
  notarization/signing smoke.
- [ ] Windows UAC, Linux elevation, and packaged tray behavior pass live smoke.
- [ ] Flutter UI RSS is measured separately from daemon RSS.
- [ ] Tauri/WebView is no longer required for the primary desktop client path.
