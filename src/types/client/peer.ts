import type {
  CandidatePairSource,
  CandidatePairState,
  ConnectionState,
  DirectPathType,
  NetworkPath,
} from "./base";

export interface PathHealthDiagnostics {
  last_success_age_ms: number | null;
  last_failure_age_ms: number | null;
  consecutive_failures: number;
  last_error: string | null;
  last_error_code?: string | null;
  latency_ms: number | null;
  rtt_ewma_ms?: number | null;
  jitter_ms?: number | null;
  success_count?: number;
  failure_count?: number;
}

export interface CandidatePairDiagnostics {
  local_endpoint: string | null;
  remote_endpoint: string;
  local_candidate_type: CandidatePairSource | null;
  remote_candidate_type: CandidatePairSource;
  local_interface: string | null;
  local_source: string | null;
  remote_source: CandidatePairSource;
  source: CandidatePairSource;
  local_generation: number;
  state: CandidatePairState;
  pair_state: CandidatePairState;
  nominated: boolean;
  selected: boolean;
  nominated_age_ms: number | null;
  selected_age_ms: number | null;
  last_probe_age_ms: number | null;
  probe_count: number;
  probe_due: boolean;
  probe_retry_after_ms: number | null;
  probe_retry_remaining_ms: number | null;
  first_success_age_ms: number | null;
  last_success_age_ms: number | null;
  last_failure_age_ms: number | null;
  consecutive_failures: number;
  last_error: string | null;
  last_error_code: string | null;
  rtt_ms: number | null;
  rtt_ewma_ms: number | null;
  jitter_ms: number | null;
  success_count: number;
  failure_count: number;
  direct_type: DirectPathType;
  is_public_udp_direct: boolean;
  is_overlay_direct: boolean;
  is_relay: boolean;
  warning: string | null;
}

export interface CandidatePairSourceStats {
  source: CandidatePairSource;
  pair_count: number;
  current_pair_count: number;
  selected_count: number;
  succeeded_count: number;
  probing_count: number;
  failed_count: number;
  degraded_count: number;
  success_count: number;
  failure_count: number;
  success_rate_per_mille: number | null;
  last_success_age_ms: number | null;
  last_failure_age_ms: number | null;
  history_success_count: number | null;
  history_failure_count: number | null;
  history_consecutive_failures: number | null;
  history_success_rate_per_mille: number | null;
  history_cooldown_remaining_ms: number | null;
  source_quality_rank: number | null;
  probe_budget_per_cycle: number | null;
  probe_budget_reason: string | null;
}

export interface PeerDiagnostics {
  node_id: string;
  device_name?: string;
  virtual_ip: string;
  endpoint: string | null;
  nat_type: string;
  online?: boolean;
  last_seen?: number;
  state: ConnectionState;
  active_path: NetworkPath | null;
  direct_type: DirectPathType;
  probe_session_id?: string | null;
  probe_key_type?: string;
  selected_pair: CandidatePairDiagnostics | null;
  current_direct_pair: CandidatePairDiagnostics | null;
  consent_endpoint: string | null;
  is_public_udp_direct: boolean;
  is_overlay_direct: boolean;
  is_relay: boolean;
  warning: string | null;
  connected_for_ms: number | null;
  bytes_sent: number;
  bytes_received: number;
  relay_server: string | null;
  candidates: string[];
  direct: PathHealthDiagnostics;
  relay: PathHealthDiagnostics;
  candidate_pair_stats?: CandidatePairSourceStats[];
  candidate_pairs?: CandidatePairDiagnostics[];
  current_path_selection?: PathSelectionDiagnostics | null;
  last_path_selection?: PathSelectionDiagnostics | null;
}

export interface PathScoreDiagnostics {
  path: NetworkPath;
  score: number;
  reachable: boolean;
  reachability_score: number;
  preference_score: number;
  latency_score: number;
  stability_score: number;
  penalty_score: number;
  reason: string;
}

export interface PathSelectionDiagnostics {
  path: NetworkPath | null;
  direct_endpoint: string | null;
  reason_code: string;
  reason: string;
  direct_confirmed: boolean;
  relay_hedged: boolean;
  direct_score?: PathScoreDiagnostics | null;
  relay_score?: PathScoreDiagnostics | null;
}

export interface PeerManagerStats {
  total_peers: number;
  direct_connections: number;
  relay_connections: number;
  total_bytes_sent: number;
  total_bytes_received: number;
}
