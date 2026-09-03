# Mobile lifecycle identity inventory

This document records the ownership boundaries for Issue #24. Each layer
advances only the identity it owns. Flutter and Android provide lifecycle input
and attachment fences; the Rust daemon remains the authority for network
generation, candidate publication, peer path state, and Relay/Direct commits.
The canonical wire vocabulary and required evidence scenarios are in
[`contracts/mobile_lifecycle.json`](../contracts/mobile_lifecycle.json).

The Android permission implementation retains the existing
`startActivityForResult` callback because the app already owns a stable
`MethodChannel` API. A `PendingPermission` stores the request, Activity, and
FlutterEngine incarnations. Recreation, revoke, duplicate requests, and late
results are resolved by the production `MobileLifecycleCoordinator`; a pending
callback is completed with an explicit cancellation/stale error instead of
being left suspended.

| Identity | Authoritative owner | Representation and advance trigger | Persisted across process death? | Consumers and stale fence | Deterministic proof |
| --- | --- | --- | --- | --- | --- |
| Flutter app epoch | Flutter `MobileLifecycleCoordinator` | `appEpoch`; background/resume transition | No | `StatusStore._refreshAfterResume` and event loop require the captured epoch | Dart coordinator lifecycle test |
| Flutter diagnostics event-loop generation | Flutter `StatusStore` plus coordinator | `eventLoopGeneration`; background, resume, settings, bridge, and dispose invalidation | No | Long-poll completion checks epoch and generation before applying | `status_store_test.dart`, lifecycle coordinator test |
| Observed daemon process/revision | Daemon diagnostics, adopted by Flutter | `processId` and monotonic `revision`; replacement process is accepted even with a lower revision | No | `observeDaemon` rejects lower same-process revisions; snapshot replacement rejects rollback | `status_store_test.dart`, ML-03 manifest |
| VPN permission request | Android Activity coordinator | Monotonic `permissionRequestId`; each pending request has one owner | No | Pending result checks request, Activity, and Engine; revoke clears it | `MobileLifecycleCoordinatorTest.permissionRevokeInvalidatesPendingRequestAndRegrantGetsNewId` |
| Activity / FlutterEngine incarnation | Android host | Monotonic Activity and Engine counters on recreation/attachment | No | Old permission result and old channel owner are rejected | `stalePermissionResultIsRejectedAfterActivityAndEngineRecreation` |
| VPN desired-running state | Android VpnService plus persisted start request | `SharedPreferences` stores the desired start JSON; runtime handles are not persisted | Yes, as desired intent only | Explicit stop/revoke clears persisted intent and cancels restart callbacks | Service `stopVpn`, `onRevoke`, and restart owner checks |
| VpnService incarnation | Android VpnService | Monotonic `serviceIncarnation` allocated in `onCreate` | No | Monitor, health-reset, restart, and cleanup callbacks require the current service owner | `serviceRecreationAllocatesNewIncarnationAndOldMonitorIsRejected` |
| Automatic-restart generation | Android VpnService coordinator | `automaticRestartGeneration`; assigned when a restart is scheduled | No | Runnable must match service and restart generations and desired-running state | `oldDelayedRestartIsRejectedAfterExplicitOwnerChange` |
| Native monitor generation | Android VpnService | Transient `monitorGeneration` incremented when monitoring stops/starts | No | Main-thread monitor completion checks monitor and service incarnations | `startNativeMonitor`, owner checks in `P2wlanVpnService.kt` |
| Physical network identity / hint generation | Android `PhysicalNetworkIdentityReducer` for input; Rust for dataplane authority | Network handle, transport set, validation/captive bits, interface identity; reducer debounces callbacks | No | Retired handles and replacement state reject old available/lost callbacks; only a changed identity hints Rust | `wifiCellularAndHotspotHandoffsAdvanceExactlyOnceAndDebounceCallbacks` |
| JNI / native bridge incarnation | Rust Android bridge, surfaced by `nativeIncarnation()` | Non-reused `OwnerId` allocated for each native runtime | No | Kotlin attaches the returned owner; old service/bridge cleanup cannot stop a replacement | Android bridge tests and `client/android-native/src/lifecycle.rs` |
| Android socket protector ownership | Rust Android bridge | `OwnerId` stored beside the socket protector | No | compare-and-clear is owner-scoped; replacement install and old cleanup are serialized | `old_runtime_cannot_clear_new_socket_protector` |
| Rust Android runtime handle | Rust `RUNTIME` slot | `OwnerId` attached to the runtime handle | No | `nativeStop` and final runtime cleanup compare the expected owner | Android-native host tests |
| Rust network generation | Rust `PeerManager` / `network_epoch_gate` | Monotonic daemon-owned network epoch from physical/socket changes | No | Candidate, socket, path, and Direct validation commits require the current epoch | Existing path-state, UDP, candidate, and transport tests; ML-14–17 |
| Peer-session generation | Rust peer lifecycle | Per-peer session identity advanced on peer replacement/left | No | Late ACK/business events must match the current peer session | Existing PeerLeft and path-state tests |
| Remote-candidate epoch | Rust candidate refresh/runtime | Candidate refresh epoch attached to every result | No | A result from an older network/candidate epoch is rejected before apply | Existing candidate refresh generation tests; ML-14 |
| UDP socket/publication generation | Rust UDP publication | Publication identity paired with network epoch | No | Old socket publication cannot replace the current publication | Existing UDP replacement tests; ML-15 |
| Control WebSocket connection generation | Rust control WebSocket task | Mutex-serialized connection generation per connect attempt | No | Old task teardown cannot clear the connected bit for a newer owner | `new_control_connection_survives_old_task_teardown` |
| Relay transport / connection ID | Rust Relay transport and peer path state | Connection ID identifies the currently usable Relay transport | No | Direct probing never clears a confirmed Relay; transport replacement is explicit | Existing relay retention tests; ML-16 |
| Direct validation owner | Rust path commit / validation probe | Probe owner token paired with current network and peer session | No | Only an encrypted, current-generation confirmation commits Direct | Existing Direct ACK/path commit tests; ML-17 |
| Diagnostics source process identity | Rust diagnostics, consumed by Flutter | Daemon process ID and revision in every status/event response | No | Flutter resets cursor on process replacement and does not apply stale responses | `StatusStore._refreshOnce` and ML-03 |

## Boundary rules

- Kotlin network callbacks do not mutate the Rust Path State Machine directly;
  they are a deterministic input adapter. Rust `PeerManager` remains the one
  network/path authority.
- Flutter does not infer Direct or Relay from UI lifecycle state. It consumes
  daemon diagnostics and refreshes after a bridge/process boundary.
- A confirmed Relay stays usable while Direct discovery is probing and after a
  bounded Direct retry timeout. It is replaced only after current-generation,
  encrypted Direct confirmation.
- Evidence records are schema 2 and bind both `source_head_sha` and
  `workflow_sha`. The required aggregate accepts only `applied`, `duplicate`,
  or `stale_rejected` decisions prescribed by the canonical scenario; manual
  device work is deliberately outside that aggregate.
