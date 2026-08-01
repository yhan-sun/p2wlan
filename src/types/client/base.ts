export type ConnectionState =
  | "idle"
  | "connecting"
  | "hole_punching"
  | "direct"
  | "fallback_to_relay"
  | "relay"
  | "failed"
  | "closed";

export type NetworkPath = "direct" | "relay";
export type PeerPath = NetworkPath | "direct_trial" | "connecting" | "offline";
export type DirectPathType =
  | "lan"
  | "public_udp"
  | "overlay"
  | "relay"
  | "probing"
  | "unknown";
export type ConnectionType =
  | "lan_direct"
  | "public_direct"
  | "overlay_direct"
  | "direct"
  | "direct_trial"
  | "connecting"
  | "relay"
  | "offline"
  | "unknown";

export type CandidatePairSource =
  | "signaled"
  | "host"
  | "stun_observed"
  | "upnp"
  | "pcp"
  | "nat_pmp"
  | "predicted"
  | "birthday"
  | "learned"
  | "peer_reflexive";

export type CandidatePairState =
  | "frozen"
  | "waiting"
  | "probing"
  | "succeeded"
  | "selected"
  | "failed"
  | "degraded";

export type HealthStatus = "healthy" | "degraded" | "unhealthy" | "shutting_down";

export type DaemonLifecycle = "running" | "stopped" | "unknown" | "error";

export type DaemonOperationPhase =
  | "stopped"
  | "authorizing"
  | "launching"
  | "waiting_for_daemon"
  | "running"
  | "stopping"
  | "error";

export type RelayPolicy = "auto" | "direct-first" | "relay-only";

export type CloseBehavior = "keep-running" | "stop-and-quit";

export type DiagnosticCheckStatus = "pass" | "warn" | "fail" | "unknown" | "skipped";

export type DataSource = "live" | "fallback" | "cached";
