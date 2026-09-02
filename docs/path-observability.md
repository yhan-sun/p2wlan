# Path observability contract

`Path Observability` is the bounded diagnostic contract for Direct/Relay path
selection. It observes the generation-aware Path State Machine; it does not
make path decisions, alter health, enqueue network work, or block the data
plane.

## Ownership and non-blocking rule

The authoritative recorder is called only from
`PeerConnection::commit_path_transition`, after the pure reducer commits and
before compatibility side effects are published. The recorder:

- uses only fields already protected by the current `PeerConnection` writer;
- performs no `await`, socket operation, file operation or metric export;
- allocates no dynamic metric labels;
- retains at most 32 transition records per peer;
- reports evictions in `dropped_transition_events`;
- preserves rejected and duplicate transitions as typed evidence.

The `/status` serializer reads this already-committed state. Telemetry cannot
write path state and cannot become a lock owner in the Direct/Relay dataplane.

## Wire schema

The additive object `peers[].path_observability` has
`schema_version = 1`. Older clients can ignore it. The Flutter parser treats a
missing object as schema version `0`, so an older daemon remains readable.

A snapshot includes:

- the exact network generation, peer-session generation and remote-candidate
  epoch;
- lifecycle, current and previous active path, transition reason and path age;
- typed Direct, Relay and recovery states;
- Direct and Relay health snapshots;
- the latest handshake and Direct-validation timing summary;
- bounded candidate/punch counts without endpoint labels;
- the selected Direct overlay budget and UDP datagram size, or the conservative
  Relay MTU of 1380;
- a bounded typed transition ring;
- fixed-field counters and one fixed-bucket Direct time-to-connect histogram.

Example:

```json
{
  "schema_version": 1,
  "network_epoch": {
    "network_generation": 7,
    "peer_session_generation": 3,
    "remote_candidate_epoch": 11
  },
  "lifecycle": "online",
  "current_path": "direct",
  "previous_path": "relay",
  "transition_reason": "direct_committed",
  "path_age_ms": 42,
  "path_state_revision": 19,
  "direct_state": "committed",
  "relay_state": "usable",
  "recovery_state": "stable",
  "selected_path_mtu": 1360,
  "selected_udp_datagram_size": 1392
}
```

## Metric table

Metrics are serialized under `stats.path_observability` and mirrored inside
each peer snapshot. They are JSON fields, not Prometheus-style dynamic label
sets. Consequently peer IDs, endpoints, IP addresses, session IDs and arbitrary
error text cannot increase cardinality.

| Field | Type | Meaning |
|---|---:|---|
| `accepted_transitions` | counter | State-changing reducer commits. |
| `accepted_observations` | counter | Typed observations that execute once without changing the state enum. |
| `duplicate_events` | counter | Exact idempotent event replays. |
| `rejected_transitions` | counter | Stale/illegal/revision-fenced events. |
| `path_changes` | counter | Authoritative active-path changes. |
| `direct_attempts` | counter | New Direct probe attempts. |
| `direct_retries` | counter | Typed Direct retry schedules. |
| `direct_validations` | counter | Encrypted Direct validations started. |
| `direct_successes` | counter | Direct commit events. |
| `direct_failures` | counter | Direct probe/path/cancellation failures. |
| `validation_failures` | counter | Direct validation lifecycle failures. |
| `relay_confirmations` | counter | Encrypted Relay peer confirmations. |
| `relay_fallbacks` | counter | Active-path transitions to Relay. |
| `relay_failures` | counter | Relay transport/path failure events. |
| `candidate_refreshes` | counter | Remote candidate epoch advances. |
| `control_reconnects` | counter | Control registrations after the initial registration; held outside the bounded event ring so timeline eviction cannot erase reconnect evidence. |
| `network_generation_changes` | counter | Local network generation advances. |
| `lifecycle_resets` | counter | Peer-left or identity reset events. |
| `dplpmtud_changes` | gauge/counter snapshot | Current bounded DPLPMTUD revision for the exact path. |
| `active_tasks` | gauge | Running supervised daemon tasks. |
| `active_sockets` | gauge | Live Direct UDP socket publications. |
| `dropped_transition_events` | counter | Oldest transition-ring entries evicted at the 32-entry bound. |
| `direct_time_to_connect_ms` | histogram | Attempt-to-Direct-commit latency. |

The histogram bounds are fixed at
`50, 100, 250, 500, 1000, 3000, 10000, 30000` milliseconds and have one final
overflow bucket. Bucket boundaries cannot be supplied by peers or runtime
errors.

## Transition reason codes

Reason codes are a closed set derived from typed `PathEvent` variants, such as
`direct_probe_started`, `direct_committed`, `relay_peer_confirmed`,
`network_generation_advanced` and `remote_candidate_epoch_advanced`. Reducer
decisions are also closed labels (`applied`, `duplicate`,
`rejected_network_generation`, and so on). Arbitrary error strings remain in
ordinary human diagnostics and never become metric dimensions.

## Operator output

`p2wlan doctor` prints a compact aggregate including transition count, path
changes, Direct successes/attempts, Relay fallbacks, rejections, active tasks,
active sockets and Direct-connect sample count. Full per-peer timelines remain
available through authenticated `/status` and support logs.

## Test mapping

- `path_observability_metrics_are_bounded`: transition-ring and histogram
  bounds, plus absence of peer/endpoint data in the serialized object.
- `path_observability_tests_direct_to_relay_to_direct_timeline`: typed recovery
  history.
- `rejected_and_duplicate_events_are_observable_without_side_effect_labels`:
  stale/duplicate visibility and fixed metric names.
- `connection_timeline::tests::control_reconnect_counter_survives_timeline_eviction`:
  reconnect count remains correct after the bounded process timeline evicts the
  initial registration.
- Rust and Flutter shared contract fixtures: additive schema compatibility.
- `scripts/path-observability-evidence.py`: repository policy, metric table,
  forbidden-label and workflow-name verification.

The stable aggregate check is named exactly `Path Observability Required`.
