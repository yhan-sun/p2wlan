# Diagnostics and speed-test reliability repair

Base: `c1f8fb0d6ead1b1e759e16038aa95823847453ce`; implementation and evidence are tracked in PR #69. This change does not publish a release or change the speed-test command protocol. Flutter remains the GUI.

## Behavior and bounds

- Every speed-test run has its own increasing run ID, monotonic stopwatch, counters and chart scale. Late samples, cancelled responses and disposed owners cannot modify another run. Closing a running test cancels its request. The UI only offers tests for an active confirmed Direct path, matching the daemon contract.
- The speed-test listener allows eight connections globally and two per source IP. Commands have a three-second deadline, transfers use their sample duration with a two-second upload drain margin, acknowledgements have a three-second deadline, and each complete operation is bounded. Partial writes are counted. Missing, malformed and inflated upload acknowledgements fail instead of falling back to locally sent bytes. Accepted child tasks are cancelled and drained on shutdown.
- Diagnostics HTTP headers are assembled before authentication with a 16 KiB size limit and three-second total deadline. Duplicate authentication/framing fields and unsupported bodies are rejected. Existing native-client, loopback and session-secret boundaries remain in place. Caller disconnection and daemon shutdown cancel in-flight speed-test work.
- Initial health failure no longer ends the startup-settling window. Startup progress and terminal errors are displayed separately. Health failure categories remain inspectable; unrelated HTTP services cannot satisfy the health check. Automatic transient misses mark cached snapshots stale before discarding them, without claiming cached data is live. Explicit manual refresh remains immediate.
- Control shutdown uses an independent notification and bounded supervisor to cancel ordinary HTTP work and drain critical tasks before best-effort presence release. Current server lease expiry remains the fallback for release failure, abnormal exit or an already-accepted stale server request. An old deployment may not support `/offline`; server compatibility must be verified on the deployed build. Hiding to the tray is not stopping the daemon.
- Human-readable daemon and Android logs use local RFC3339 timestamps with explicit offsets. The UI converts old UTC logs to the viewer's timezone, preserves unknown lines, and offers level/search filtering and consecutive duplicate folding after redaction. Routine roster polls move to DEBUG; timeline fields are not repeated in generic event prose. Raw support exports retain original timestamps.
- File logs use a 512-record queue, a 16 KiB per-record bound, a 10 MiB active file and four backups. Queue overflow and write failures are reported. Shutdown drain is bounded. Unix private modes and original ownership survive rotation. Existing oversized logs are trimmed with bounded tail reads. The dual-machine and NAT log parsers accept old and new timestamps/field formats.

## Regression validation

The existing Rust and Flutter gates run the added timeout, admission, ACK, cancellation, repeated chart, counter reset, stale completion, startup, HTTP fragmentation, shutdown and log tests. No existing acceptance check is disabled. The temporary recovery workflow is removed from the final tree.

Additional parser checks:

```sh
python3 scripts/dual-end/test-log-format-compatibility.py
python3 scripts/dual-end/test-production-availability-parser.py
```

## Runtime verification boundary

CI only proves the test and packaging scenarios it actually executes. Live two-device verification must identify client, daemon and deployed server commits and package hashes. For offline propagation, compare the server roster, receiving daemon `/status`, and UI independently. Slow elevation, real routing, actual Direct/Relay paths and old-server compatibility still require packaged runtime evidence. This document is not a record of a live server upgrade or a Windows/macOS dual-machine test.
