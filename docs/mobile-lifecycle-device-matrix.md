# Mobile lifecycle device matrix

This is the follow-up device/lab matrix for Issue #24. Every row is currently
`not_run`; the rows are non-blocking and not executed by the pull-request
workflow. The deterministic PR gate uses Flutter, Android JVM, and Rust host
tests only, so it does not require a device, emulator, VPN permission dialog,
or a physical cellular network.

The supported baseline is Android API 24+ and iOS 15+ as documented by the
Flutter client. Device and OEM columns remain intentionally open until a lab
run is scheduled.

| Platform | OS/version | Device/OEM | Scenario | Expected result | Evidence required | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Android | API 24+ | Lab handset / OEM recorded at execution | Foreground → background → resume | Late callbacks are fenced; resume refreshes status before the event stream | Timestamped log plus source/revision transition | not_run | non-blocking; not executed |
| Android | API 24+ | Lab handset / OEM recorded at execution | Doze / screen-off interval | Desired VPN state is retained; stale monitor/restart work cannot take ownership | Doze configuration and lifecycle trace | not_run | non-blocking; not executed |
| Android | API 24+ | OEM battery manager recorded at execution | Aggressive OEM background restriction | Service behavior and user-visible stopped/permission state are explicit | OEM policy setting and service trace | not_run | non-blocking; not executed |
| Android | API 24+ | Cellular-capable handset | Wi-Fi → cellular | One physical identity change advances one network generation and reattaches paths | Network callback trace and daemon generation | not_run | non-blocking; not executed |
| Android | API 24+ | Two phones, hotspot provider recorded | Cellular → Wi-Fi / phone hotspot | New Wi-Fi network identity is adopted without guessing hotspot provenance | Network handle/transport trace and daemon generation | not_run | non-blocking; not executed |
| Android | API 24+ | Lab handset / OEM recorded at execution | VPN permission revoke → regrant | Current attempt stops; old result cannot start; regrant creates a new request | Permission request IDs and service status | not_run | non-blocking; not executed |
| Android | API 24+ | Lab handset / OEM recorded at execution | Service process kill and recreation | Persisted desired intent is separated from transient runtime; new service incarnation adopts safely | Service/bridge incarnation trace | not_run | non-blocking; not executed |
| Android | API 24+ | Lab handset / OEM recorded at execution | App upgrade with active desired VPN state | Upgrade does not reuse an old runtime handle; restart is explicit and bounded | Before/after package identity and service trace | not_run | non-blocking; not executed |
| iOS | 15+ | iPhone model recorded at execution | Foreground → background → resume | Client refreshes after suspension and does not apply pre-suspend callbacks | OS lifecycle trace and diagnostics revision | not_run | non-blocking; not executed |
| iOS | 15+ | iPhone model recorded at execution | Wi-Fi → cellular handoff | Daemon-owned network generation converges and a current path is selected | Network transition trace and daemon evidence | not_run | non-blocking; not executed |
| Android / iOS | Supported baseline | Captive portal lab network | Captive portal / validation loss | Captive identity is observable; old validated path is not resurrected | Connectivity capabilities and path diagnostics | not_run | non-blocking; not executed |
| Android / iOS | Supported baseline | IPv4/IPv6-capable lab network | IPv4 ↔ IPv6 network replacement | Address-family replacement is treated as a new identity; stale sockets/candidates are fenced | Address-family and socket publication evidence | not_run | non-blocking; not executed |

No row in this document contributes to `Mobile Lifecycle Required` or to the
schema-2 component artifacts. A future lab run must attach its raw device logs
separately and must not rewrite an unexecuted row as deterministic PR evidence.
