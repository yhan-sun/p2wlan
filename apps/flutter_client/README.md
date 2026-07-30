# P2WLAN Flutter Client

Read-only P1/P1.5 Flutter prototype for the P2WLAN local daemon diagnostics API.

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

The app performs one read-only refresh on startup. Auto refresh is off by
default in P1.5 so the prototype does not keep polling an offline local port in
the background. Users can turn on the Dashboard auto refresh switch for a low
frequency 30 second poll; auto refresh only issues `GET /health` and
`GET /status`.

To point the UI at a manually started daemon, open Settings and set the
diagnostics URL. The default is:

```text
http://127.0.0.1:39277/status
```

Settings are saved only to the Flutter client's local settings JSON. They do not
write daemon configuration.

## P1.5 Smoke

Offline smoke, with no daemon started by this app:

```bash
cd apps/flutter_client
flutter run -d macos
```

Expected offline result:

- Dashboard shows `Offline`, a failed `GET /health`, skipped `GET /status`, last
  refresh time, and request duration.
- Diagnostics shows health/status summary plus a readable offline/error JSON
  block instead of crashing.
- Nodes shows peer count `0` and no peer cards.
- Settings rejects invalid URLs, can restore the default URL, and states that the
  URL is saved only in Flutter local settings.
- The app does not start, stop, elevate, or shut down the daemon.

Manual refresh smoke after starting an existing daemon yourself:

- Click Dashboard `Refresh now`; health and status should update separately.
- Confirm Dashboard shows `Healthy`, `Degraded`, or `Unhealthy` based on
  `/status.health.status`, not only socket reachability.
- Confirm Diagnostics raw JSON matches `GET /status` and the Copy button copies
  the visible JSON using Flutter's built-in Clipboard API.
- Confirm Nodes shows peer count, peer ID/name, virtual IP, path, connection
  type, and Direct/Relay route; missing fields display `—`.
- Optional: turn on Auto refresh and verify the UI refreshes every 30 seconds,
  then turn it back off.

## Platform Notes

The Flutter client keeps the same read-only diagnostics behavior on every
platform. It does not manage daemon lifecycle on Android, Windows, Linux, or
macOS.

Common local builds:

```bash
cd apps/flutter_client
flutter analyze
flutter test
flutter build apk --release --target-platform android-arm64
flutter build macos --release
flutter build linux --release      # run on Linux with GTK dev packages
flutter build windows --release    # run on Windows with Visual Studio tooling
```

Android notes:

- Release/debug Android builds include `INTERNET` because the app reads the
  diagnostics HTTP endpoint.
- Cleartext HTTP is allowed because the diagnostics URL is user-configurable and
  local/LAN endpoints are expected in P1/P1.5.
- Android emulators usually reach a host daemon through `http://10.0.2.2:<port>`
  rather than `127.0.0.1`. Physical devices need a reachable LAN address.

Desktop notes:

- macOS, Linux, and Windows use the visible app/window title
  `P2WLAN Diagnostics`.
- Desktop windows use an 860x560 minimum size so diagnostics tables and controls
  remain usable while still supporting compact laptop windows.

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

- Dashboard changes from Offline to Healthy/Degraded/Unhealthy based on the
  daemon health reported by `GET /status`.
- Dashboard shows separate `GET /health` and `GET /status` states, node ID,
  virtual IP, network ID, daemon health, UDP local addr, relay status, peer
  count, last refresh time, and request duration.
- Diagnostics shows summary fields and raw JSON from `GET /status`; Copy uses
  Flutter's built-in Clipboard API.
- Nodes shows peer count and clearer peer ID/name, virtual IP, path, connection
  type, and Direct/Relay route fields.
- Settings can change only the local diagnostics URL used by the Flutter app and
  can restore the default URL.
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
flutter build macos --release
```

GitHub Actions:

- `.github/workflows/flutter-client.yml` runs analyze/test plus Android, Linux,
  macOS, and Windows release app builds.
- Android uploads only an arm64 release APK.
- `.github/workflows/release.yml` is the publish workflow for tag releases.
- Release publishes Android arm64 APK, unsigned iOS arm64 IPA, macOS arm64/x64
  DMGs, Windows x64 setup installer, Linux x64 Flutter bundle, and Linux
  x64/arm64 CLI/daemon tarballs.
- Windows and Linux Flutter ARM64 desktop packages are not enabled until the
  GitHub Action can resolve stable Flutter ARM64 SDKs on those runners.
- Release builds use `--split-debug-info` to keep Dart symbols out of the
  downloadable app packages.
- The Flutter client workflow is intentionally UI-only; the tag release workflow
  publishes Linux CLI/daemon tarballs separately.

## P1/P1.5 Acceptance Checklist

- [ ] `flutter analyze` passes.
- [ ] `flutter test` passes.
- [ ] Offline daemon state renders without crashing.
- [ ] Manual refresh works against a manually started daemon through `GET /health` and `GET /status`.
- [ ] Auto refresh defaults off and, when enabled, only polls `GET /health` and `GET /status`.
- [ ] Dashboard shows last refresh time and request duration.
- [ ] Diagnostics shows raw JSON, readable offline/error JSON, and Copy support.
- [ ] Settings validates diagnostics URLs and stores them only in Flutter local settings.
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
