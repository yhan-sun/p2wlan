#!/usr/bin/env bash
# Deterministic dual-NAT cold-start verification: two independent NATs
# (address/port-dependent mapping, configurable strict filtering / direct
# blackhole, step/consumption/loss/reordering), 4+ independent STUN observers,
# relay safety net, two daemons with P2WLAN_DISABLE_TUN=1 behind the NATs.
#
# Modes:
# - direct (default): every round is a completely cold start; a round PASSES
#   only when BOTH sides reach Direct *and* complete a bidirectional encrypted
#   overlay loopback that targets confirmed Direct paths only. Host candidates
#   are never advertised, so the Direct path must traverse the simulated NATs.
# - relay-only: the NAT simulators run --block-direct so Direct can NEVER
#   establish (a deterministic CGNAT bidirectional UDP blackhole); both daemons
#   run --validate-overlay --overlay-any-path and a round PASSES when BOTH
#   sides complete the bidirectional encrypted overlay loopback over Relay.
#   Direct results are reported separately as informational and must be 0.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/diagnostics-auth.sh"

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# The standalone local control DB provisions only `default`; the real dual-end
# harness uses NETWORK_ID explicitly and requires a provisioned test network.
NETWORK_ID=${NETWORK_ID:-default}
MODE=${MODE:-direct}
# Keep the local regression logs at the same diagnostic granularity as the
# dual-end harness: per-packet counter/order and transport handoff boundaries
# are DEBUG, while the rest remains INFO. Override this for a quieter run.
  NAT_SIM_RUST_LOG=${NAT_SIM_RUST_LOG:-info,p2pnet_daemon::transport=debug,p2pnet_daemon::network_outbound=debug,p2pnet_daemon::relay=debug,p2pnet_daemon::relay_runtime=debug,p2pnet_daemon::connection_timeline=debug,p2pnet_daemon::direct_validation=debug,p2pnet_daemon::peer::connection=debug,p2pnet_daemon::peer::connection::events=debug,p2pnet_daemon::peer::manager::relay=debug,p2pnet_relay::client=debug}
ROUNDS=${ROUNDS:-5}
NAT_SEED_BASE=${NAT_SEED_BASE:-20260806}
 # Avoid collisions between locally parallel/recent smoke invocations.  The
 # caller may still pin PORT/RELAY_PORT/RELAY_METRICS_PORT explicitly.
PORT=${PORT:-$((38080 + ($$ % 1000) * 10))}
RELAY_PORT=${RELAY_PORT:-$((PORT + 1))}
RELAY_METRICS_PORT=${RELAY_METRICS_PORT:-$((PORT + 1001))}
DIAG_A_PORT=${DIAG_A_PORT:-$((PORT + 301))}
DIAG_B_PORT=${DIAG_B_PORT:-$((PORT + 302))}
STEP_A=${STEP_A:-1}
STEP_B=${STEP_B:-1}
CONSUME_A=${CONSUME_A:-0}
CONSUME_B=${CONSUME_B:-0}
LOSS=${LOSS:-0.0}
REORDER=${REORDER:-0}
STRICT_FILTERING=${STRICT_FILTERING:-0}
FRESH_MAPPING_PUNCH=${FRESH_MAPPING_PUNCH:-1}
PREDICTED_CANDIDATES=${PREDICTED_CANDIDATES:-1}
BIRTHDAY_PROBING=${BIRTHDAY_PROBING:-1}
SOCKET_POOL=${SOCKET_POOL:-}
BASE_A=${BASE_A:-36000}
BASE_B=${BASE_B:-46000}
DIRECT_TIMEOUT_S=${DIRECT_TIMEOUT_S:-60}
OVERLAY_TIMEOUT_S=${OVERLAY_TIMEOUT_S:-30}
NAT_SIM_ARTIFACT_DIR=${NAT_SIM_ARTIFACT_DIR:-}
# Give every local daemon timeline an explicit, bounded correlation namespace.
# The dual-end harness already supplies P2WLAN_TEST_RUN_ID; NAT-sim used to
# leave it unset, which made the logs harder to join even though each daemon
# still had a correlation_id.  This value is diagnostic-only and never carries
# credentials or control-plane material.
NAT_SIM_RUN_ID=${NAT_SIM_RUN_ID:-nat-sim-${MODE}-${NAT_SEED_BASE}}
# Post-first-usable burst verification: fire this many business payloads per
# peer right after first-usable evidence and require EVERY echo (zero loss /
# duplicate / replay).  Relay-only rounds default to a 256-packet burst.
OVERLAY_BURST=${OVERLAY_BURST:-0}
# Relay-only rounds verify a full 256-packet burst by default (the acceptance
# requirement: 100 continuous + 256 burst with zero loss).
if [[ "$OVERLAY_BURST" -eq 0 && "$MODE" == "relay-only" ]]; then
  OVERLAY_BURST=256
fi
# Artificial per-frame relay forwarding delay in ms (slow-relay diagnostics;
# the relay observes the full one-way delay).  Informational: a delayed relay
# cannot meet the 3000ms SLO, so no PASS/FAIL claim is made for it.
RELAY_DELAY_MS=${RELAY_DELAY_MS:-0}
# Kill and restart the relay mid-round and require the overlay to recover
# (relay disconnect/reconnect verification).
RELAY_KILL_RESTART=${RELAY_KILL_RESTART:-0}
# Number of relay candidates offered in the catalog.  With RELAY_FAILOVER=1,
# the ACTIVE relay is killed after the round's first confirmation and the
# daemon must fail over to another candidate and re-confirm.
RELAY_COUNT=${RELAY_COUNT:-1}
RELAY_FAILOVER=${RELAY_FAILOVER:-0}
# Failure-injection hooks exercise the harness' own observability gate.  They
# deliberately make a required endpoint unavailable or malformed; the smoke
# run must FAIL with a reason code instead of manufacturing an empty JSON
# object or a zero delta.
STATUS_FAILURE_INJECTION=${STATUS_FAILURE_INJECTION:-0}
METRICS_FAILURE_INJECTION=${METRICS_FAILURE_INJECTION:-0}
STATUS_SCHEMA_INJECTION=${STATUS_SCHEMA_INJECTION:-0}

if ! [[ "$NAT_SEED_BASE" =~ ^[0-9]+$ ]]; then
  echo "[nat-sim] NAT_SEED_BASE must be a non-negative integer" >&2
  exit 2
fi
if ! [[ "$NAT_SIM_RUN_ID" =~ ^[A-Za-z0-9_.-]{1,80}$ ]]; then
  echo "[nat-sim] NAT_SIM_RUN_ID must contain only letters, digits, '.', '_' or '-' and be <= 80 characters" >&2
  exit 2
fi

if [[ -n "$NAT_SIM_ARTIFACT_DIR" ]]; then
  case "$NAT_SIM_ARTIFACT_DIR" in
    /*) ;;
    *)
      echo "[nat-sim] NAT_SIM_ARTIFACT_DIR must be an absolute path" >&2
      exit 2
      ;;
  esac
  if [[ -e "$NAT_SIM_ARTIFACT_DIR" ]]; then
    echo "[nat-sim] NAT_SIM_ARTIFACT_DIR already exists: $NAT_SIM_ARTIFACT_DIR" >&2
    exit 2
  fi
  BASE_DIR="$NAT_SIM_ARTIFACT_DIR"
  mkdir -p "$BASE_DIR"
else
  BASE_DIR=$(mktemp -d /tmp/p2wlan-natsim.XXXXXX)
fi
PIDS=()
# Per-round sum of the two ends' relay-ready -> usable deltas (monotonic, ms).
DELTA_SUMS=()
# Per-round failure reason codes (first relay_unavailable_or_first_packet_expired
# reason_code seen on either node, if any).
FAILURE_CODES=()

# Strip ANSI color codes from a log line so structured fields match cleanly.
strip_ansi() {
  sed $'s/\x1b\\[[0-9;]*m//g'
}

# Extract the first t_ms (monotonic, ms since daemon start) of a timeline event
# from one node's log.  Each daemon computes its OWN delta; the harness only
# SUMS the two ends' deltas, never subtracts wall clocks across machines.
node_event_tms() {
  local log="$1" ev="$2"
  # The same event is intentionally logged twice: a subsystem DEBUG line and
  # a structured ConnectionTimeline INFO line.  The DEBUG line has no t_ms.
  # Do not use grep -m1 before extracting t_ms, or a perfectly valid timeline
  # event is reported as missing (this made Direct rounds fail closed with
  # first_usable_delta_missing even though both timestamps were present).
  strip_ansi < "$log" \
    | grep "event=\"${ev}\"" \
    | grep -oE 't_ms=[0-9]+' \
    | head -1 \
    | cut -d= -f2 || true
}

# Extract the real ingress path of the first production business evidence
# (relay:<endpoint> or direct), from first_real_business_ingress (never
# inferred from active_path or the stronger harness-only echo event).
node_first_usable_ingress() {
  local log="$1"
  local line
  line=$(strip_ansi < "$log" | grep -m1 'event="first_real_business_ingress"' || true)
  if [[ -n "$line" ]]; then
    local path
    path=$(printf '%s\n' "$line" | grep -oE 'path="[^"]+"' | tail -1 | cut -d= -f2 | tr -d '"' || true)
    if [[ "$path" == "relay" ]]; then
      local relay_id
      relay_id=$(printf '%s\n' "$line" | grep -oE 'relay_id=[^ ]+' | head -1 | cut -d= -f2 | sed -E 's/[",)]+$//' || true)
      printf 'relay:%s\n' "${relay_id:-unknown}"
    elif [[ "$path" == "direct" ]]; then
      printf 'direct\n'
    fi
    return 0
  fi
  # Backward-compatible fallback for a harness-only log that predates the
  # production timeline event. It is still never inferred from active_path.
  strip_ansi < "$log" | grep -m1 'event="first_usable_confirmed"' | grep -oE 'ingress=[^ ]+' | head -1 | cut -d= -f2 || true
}

# Extract the per-daemon monotonic relay-ready -> first production business
# delta. The subtraction is performed only on one daemon's own t_ms values;
# a missing baseline/evidence remains missing and is never converted to zero.
node_first_usable_delta_ms() {
  local log="$1"
  local first_ready first_business
  first_ready=$(node_event_tms "$log" relay_transport_ready_peer)
  first_business=$(node_event_tms "$log" first_real_business_ingress)
  if [[ "$first_ready" =~ ^[0-9]+$ && "$first_business" =~ ^[0-9]+$ ]]; then
    echo $((first_business - first_ready))
    return 0
  fi
  # Backward-compatible fallback for older harness logs.
  strip_ansi < "$log" | grep -m1 'event="first_usable_confirmed"' | grep -oE 'relay_ready_to_usable_ms=Some\([0-9]+\)' | head -1 | grep -oE '[0-9]+' || true
}

# First stable drop/cancel reason_code seen on a node's timeline (if any).
node_failure_code() {
  local log="$1"
  strip_ansi < "$log" | grep "relay_unavailable_or_first_packet_expired" | grep -oE 'reason_code=Some\("[A-Za-z0-9_]+"\)' | head -1 | sed -E 's/.*reason_code=Some\("([A-Za-z0-9_]+)"\).*/\1/' || true
}

# A structured timeline event and its human-readable log line are both
# emitted for each confirmation.  Never count log lines as confirmations:
# failover evidence must be based on unique relay endpoints, otherwise the
# diagnostic itself can report a false second confirmation.
node_relay_confirmed_endpoints() {
  local log="$1"
  strip_ansi < "$log" \
    | grep 'event="relay_peer_confirmed"' \
    | grep -oE 'relay_endpoint=[^ ]+' \
    | cut -d= -f2 \
    | sed -E 's/[",)]+$//' \
    | sort -u || true
}

node_relay_confirmed_count() {
  local log="$1"
  node_relay_confirmed_endpoints "$log" | awk 'NF { count++ } END { print count + 0 }'
}

node_replacement_relay_endpoint() {
  local log="$1" active_endpoint="$2"
  node_relay_confirmed_endpoints "$log" \
    | grep -Fvx "$active_endpoint" \
    | head -1 || true
}

# Only inspect business-ingress evidence written after the failover action.
# The old endpoint's traffic before the kill is not recovery evidence.
node_post_failover_relay_ingress() {
  local log="$1" start_line="$2" active_endpoint="$3"
  tail -n +"$start_line" "$log" 2>/dev/null \
    | strip_ansi \
    | grep 'overlay_payload_verified' \
    | grep -oE 'ingress=relay:[^ ]+' \
    | cut -d= -f2 \
    | grep -Fvx "relay:${active_endpoint}" \
    | head -1 || true
}

# Fetch a required JSON endpoint.  A failed request, an empty document, or an
# incomplete schema is an acceptance failure.  In particular, this function
# never writes `{}` as a substitute for missing status/metrics evidence.
fetch_required_json() {
  local url="$1" output="$2" kind="$3" token_file="${4:-}"
  if [[ "$kind" == "status" && "$STATUS_FAILURE_INJECTION" == "1" ]]; then
    echo "[nat-sim] FAIL reason_code=status_http_500_injected url=$url" >&2
    return 1
  fi
  if [[ "$kind" == "metrics" && "$METRICS_FAILURE_INJECTION" == "1" ]]; then
    echo "[nat-sim] FAIL reason_code=metrics_http_500_injected url=$url" >&2
    return 1
  fi
  local curl_status=0
  if [[ "$kind" == "status" ]]; then
    if [[ -z "$token_file" || ! -s "$token_file" ]]; then
      echo "[nat-sim] FAIL reason_code=status_auth_token_missing path=${token_file:-missing}" >&2
      return 1
    fi
    DIAGNOSTICS_AUTH_TOKEN_FILE="$token_file" \
      p2wlan_diagnostics_curl -fsS --max-time 5 "$url" -o "$output" || curl_status=$?
  else
    curl -fsS --max-time 5 "$url" -o "$output" || curl_status=$?
  fi
  if [[ "$curl_status" -ne 0 ]]; then
    echo "[nat-sim] FAIL reason_code=${kind}_unavailable url=$url" >&2
    return 1
  fi
  if ! python3 - "$output" "$kind" "$STATUS_SCHEMA_INJECTION" <<'PY'
import json
import sys

path, kind, schema_injection = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
except Exception as exc:
    raise SystemExit(f"{kind}_invalid_json: {exc}")
if not isinstance(value, dict) or not value:
    raise SystemExit(f"{kind}_empty_or_non_object")
if kind == "status":
    if schema_injection == "1":
        raise SystemExit("status_schema_injected")
    stats = value.get("stats")
    timeline = value.get("connection_timeline")
    if not isinstance(stats, dict) or not isinstance(timeline, dict):
        raise SystemExit("status_schema_incomplete")
    if not isinstance(stats.get("outbound_drops"), dict):
        raise SystemExit("status_schema_missing_outbound_drops")
    if not isinstance(stats.get("outbound_loss_events"), list):
        raise SystemExit("status_schema_missing_outbound_loss_events")
    if not isinstance(timeline.get("correlation_id"), str) or not timeline["correlation_id"]:
        raise SystemExit("status_schema_missing_correlation_id")
    if not isinstance(timeline.get("events"), list):
        raise SystemExit("status_schema_missing_timeline_events")
elif kind == "metrics":
    required = (
        "active_connections",
        "registered_peers",
        "forwarded_frames_total",
        "forward_errors_total",
    )
    for field in required:
        if not isinstance(value.get(field), (int, float)) or isinstance(value.get(field), bool):
            raise SystemExit(f"metrics_schema_missing_{field}")
    # Metrics are intentionally aggregate-only; source identifiers do not
    # belong on this unauthenticated diagnostic endpoint.
    if "auth_failure_sources" in value:
        raise SystemExit("metrics_schema_contains_source_identifiers")
PY
  then
    echo "[nat-sim] FAIL reason_code=${kind}_schema_invalid file=$output" >&2
    return 1
  fi
}

# Sample the authenticated status endpoint without writing credentials or a
# response body. `000` means no HTTP response; callers tolerate it only before
# the daemon's first 200 during startup. Once the endpoint is live, every
# sample through the Relay burst must remain 200.
status_http_code() {
  local url="$1" token_file="$2" code
  code=$(DIAGNOSTICS_AUTH_TOKEN_FILE="$token_file" \
    p2wlan_diagnostics_curl \
      -sS --connect-timeout 0.2 --max-time 2 \
      -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)
  if ! [[ "$code" =~ ^[0-9]{3}$ ]]; then
    code=000
  fi
  printf '%s\n' "$code"
}

record_relay_status_code() {
  local side="$1" code="$2"
  printf 'side=%s code=%s at_ms=%s\n' \
    "$side" "$code" "$(python3 -c 'import time; print(int(time.time()*1000))')" \
    >>"$ROUND_DIR/status-http-samples.log"
  case "$side" in
    a)
      A_STATUS_SAMPLE_COUNT=$((A_STATUS_SAMPLE_COUNT + 1))
      if [[ "$code" == 200 ]]; then
        A_STATUS_SEEN_200=1
        A_STATUS_200_COUNT=$((A_STATUS_200_COUNT + 1))
      elif [[ "$code" != 000 || "$A_STATUS_SEEN_200" -eq 1 ]]; then
        A_STATUS_ALWAYS_200=0
      fi
      ;;
    b)
      B_STATUS_SAMPLE_COUNT=$((B_STATUS_SAMPLE_COUNT + 1))
      if [[ "$code" == 200 ]]; then
        B_STATUS_SEEN_200=1
        B_STATUS_200_COUNT=$((B_STATUS_200_COUNT + 1))
      elif [[ "$code" != 000 || "$B_STATUS_SEEN_200" -eq 1 ]]; then
        B_STATUS_ALWAYS_200=0
      fi
      ;;
  esac
}

# Sample both daemons concurrently so observability cannot lengthen the
# topology deadline by one client timeout per endpoint. Hidden scratch files
# carry the two subshell results back to this shell; only the final bounded
# code/timestamp stream is retained as acceptance evidence.
sample_relay_status_pair() {
  local a_url="$1" a_token_file="$2" b_url="$3" b_token_file="$4"
  local a_code_file="$ROUND_DIR/.status-a-code"
  local b_code_file="$ROUND_DIR/.status-b-code"
  local a_pid b_pid a_code b_code

  status_http_code "$a_url" "$a_token_file" >"$a_code_file" &
  a_pid=$!
  status_http_code "$b_url" "$b_token_file" >"$b_code_file" &
  b_pid=$!
  wait "$a_pid"
  wait "$b_pid"
  IFS= read -r a_code <"$a_code_file" || a_code=000
  IFS= read -r b_code <"$b_code_file" || b_code=000
  rm -f "$a_code_file" "$b_code_file"

  record_relay_status_code a "${a_code:-000}"
  record_relay_status_code b "${b_code:-000}"
}

# A topology run introduces no one-shot Relay owner tasks. Every supervised
# critical task present in the final status must still be running, unfinished,
# and error-free; this turns a silent task exit into a Relay acceptance failure.
node_task_health_ok() {
  python3 - "$1" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        status = json.load(handle)
    health = status["health"]
    tasks = health["critical_tasks"]
    critical = [task for task in tasks if task.get("critical") is True]
    ok = bool(critical) and all(
        task.get("running") is True
        and task.get("finished") is False
        and task.get("error") is None
        for task in critical
    )
except Exception:
    ok = False
print(1 if ok else 0)
PY
}

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${PIDS[@]:-}"; do
    wait "$pid" 2>/dev/null || true
  done
  echo "[nat-sim] artifacts retained: $BASE_DIR" >&2
}
trap cleanup EXIT

echo "[nat-sim] mode=$MODE isolated network id: $NETWORK_ID"
echo "[nat-sim] exact_head_sha=${NAT_TOPOLOGY_HEAD_SHA:-unknown} replica=${NAT_TOPOLOGY_REPLICA:-1}"
echo "[nat-sim] traversal flags: strict_filtering=$STRICT_FILTERING fresh_mapping=$FRESH_MAPPING_PUNCH predicted_candidates=$PREDICTED_CANDIDATES birthday=$BIRTHDAY_PROBING socket_pool=${SOCKET_POOL:-default}"
echo "[nat-sim] building control server, relay and daemon..."
(
  cd "$ROOT_DIR/server"
  go build -o "$BASE_DIR/control-server" .
  go build -o "$BASE_DIR/relay-server" ./relay
)
cargo build -p p2wlan-daemon --manifest-path "$ROOT_DIR/client/daemon/Cargo.toml" >/dev/null

# One relay keypair for the whole run (tickets are per-device). The helper
# uses only Go's standard library, so the harness does not depend on Python
# cryptography packages being installed on the test host.
read -r RELAY_SEED RELAY_PUB < <(go run "$ROOT_DIR/scripts/relay_keygen.go")

overall=0
round_num=0
for round in $(seq 1 "$ROUNDS"); do
  round_num=$round
  ROUND_DIR="$BASE_DIR/round-$round"
  NODE_A_RUNTIME="$ROUND_DIR/node-a-runtime"
  NODE_B_RUNTIME="$ROUND_DIR/node-b-runtime"
  mkdir -p "$ROUND_DIR" "$NODE_A_RUNTIME" "$NODE_B_RUNTIME"
  NAT_SEED=$((NAT_SEED_BASE + round))
  ROUND_RUN_ID="${NAT_SIM_RUN_ID}-round-${round}"

  echo "[nat-sim] round $round: starting NAT simulator (mode=$MODE step_a=$STEP_A step_b=$STEP_B consume_a=$CONSUME_A consume_b=$CONSUME_B loss=$LOSS reorder=$REORDER strict_filtering=$STRICT_FILTERING seed=$NAT_SEED)"
  REORDER_FLAG=""
  if [[ "$REORDER" == "1" ]]; then REORDER_FLAG="--reorder"; fi
  STRICT_FILTERING_FLAG=""
  if [[ "$STRICT_FILTERING" == "1" ]]; then STRICT_FILTERING_FLAG="--strict-filtering"; fi
  MODE_FLAGS=""
  if [[ "$MODE" == "relay-only" ]]; then
    # Deterministic Direct impossibility: a bidirectional UDP blackhole that
    # keeps STUN observers working.  Direct can never establish; only Relay can
    # carry the encrypted overlay loopback.
    MODE_FLAGS="--block-direct"
  fi
  python3 "$ROOT_DIR/scripts/nat-sim/nat_sim.py" \
    --step-a "$STEP_A" --step-b "$STEP_B" \
    --consume-a "$CONSUME_A" --consume-b "$CONSUME_B" \
    --loss "$LOSS" $REORDER_FLAG $STRICT_FILTERING_FLAG $MODE_FLAGS \
    --seed "$NAT_SEED" --base-a "$BASE_A" --base-b "$BASE_B" \
    --trace-file "$ROUND_DIR/nat-trace.jsonl" \
    >"$ROUND_DIR/nat-sim.out" 2>&1 &
  NAT_PID=$!
  PIDS+=($NAT_PID)
  for _ in {1..40}; do
    grep -q 'STUN_A=' "$ROUND_DIR/nat-sim.out" 2>/dev/null && break
    sleep 0.25
  done
  STUN_A=$(sed -n 's/^STUN_A=//p' "$ROUND_DIR/nat-sim.out")
  STUN_B=$(sed -n 's/^STUN_B=//p' "$ROUND_DIR/nat-sim.out")
  if [[ -z "$STUN_A" || -z "$STUN_B" ]]; then
    echo "[nat-sim] round $round: NAT simulator failed to start" >&2
    exit 1
  fi

  # Relay(s) (safety net; TCP, bypasses the NATs).  Multiple relays offer a
  # catalog with several candidates; the daemon selects one and fails over to
  # another when the active one dies (RELAY_FAILOVER).
  KEYRING_JSON="{\"relay-sim\":\"$RELAY_PUB\"}"
  RELAY_PIDS=()
  RELAY_ENDPOINTS=""
  if [[ "$RELAY_COUNT" -lt 1 ]]; then RELAY_COUNT=1; fi
  for relay_idx in $(seq 1 "$RELAY_COUNT"); do
    R_PORT=$((RELAY_PORT + relay_idx - 1))
    R_METRICS=$((RELAY_METRICS_PORT + relay_idx - 1))
    R_AUDIENCE="relay-sim"
    R_REGION="local"
    if [[ "$relay_idx" -gt 1 ]]; then
      R_AUDIENCE="relay-sim-$relay_idx"
    fi
    RELAY_AUDIENCE="$R_AUDIENCE" RELAY_REGION="$R_REGION" "$BASE_DIR/relay-server" \
      -bind "127.0.0.1:$R_PORT" \
      -ticket-keyring "$KEYRING_JSON" -require-auth -allow-insecure-plaintext \
      -metrics-bind "127.0.0.1:$R_METRICS" \
      -forward-delay "${RELAY_DELAY_MS}ms" \
      >"$ROUND_DIR/relay-$relay_idx.log" 2>&1 &
    RELAY_PIDS+=($!)
    PIDS+=($!)
    if [[ -n "$RELAY_ENDPOINTS" ]]; then RELAY_ENDPOINTS="$RELAY_ENDPOINTS,"; fi
    RELAY_ENDPOINTS="${RELAY_ENDPOINTS}{\"region\":\"$R_REGION\",\"audience\":\"$R_AUDIENCE\",\"endpoint\":\"tcp://127.0.0.1:$R_PORT\"}"
  done
  RELAY_PID="${RELAY_PIDS[0]}"

  if [[ "$RELAY_COUNT" -ge 2 && "$RELAY_ENDPOINTS" != *'"region":"local"'* ]]; then
    echo "[nat-sim] relay failover catalog must contain the primary local region" >&2
    exit 2
  fi

  # Control server with the relay catalog (no UDP observer in the catalog:
  # every STUN flow must traverse the simulated NATs).
  export PORT DB_PATH="$ROUND_DIR/control.db" JWT_SECRET=smoke \
    RELAY_TICKET_SIGNER_JSON="{\"active\":{\"kid\":\"relay-sim\",\"private_key\":\"$RELAY_SEED\"}}" \
    RELAY_CATALOG_JSON="[$RELAY_ENDPOINTS]"
  "$BASE_DIR/control-server" >"$ROUND_DIR/server.log" 2>&1 &
  SERVER_PID=$!
  PIDS+=($SERVER_PID)

  for _ in {1..40}; do
    curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break
    sleep 0.25
  done
  curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null

  REGISTER_JSON=""
  for _ in {1..20}; do
    REGISTER_JSON=$(curl -fsS -X POST "http://127.0.0.1:$PORT/api/v1/register" \
      -H 'Content-Type: application/json' \
      -d '{"email":"smoke@example.com","password":"passw0rd"}' 2>/dev/null) && break
    sleep 0.5
  done
  TOKEN=$(printf '%s' "$REGISTER_JSON" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  if [[ -z "$TOKEN" ]]; then
    echo "[nat-sim] round $round: failed to parse auth token" >&2
    exit 1
  fi

  START_MS=$(python3 -c 'import time; print(int(time.time()*1000))')

  # In direct mode the validation loop targets confirmed Direct peers only;
  # in relay-only mode it may use Relay so that profile tests availability.
  OVERLAY_FLAGS="--validate-overlay"
  if [[ "$MODE" == "relay-only" ]]; then
    # Availability mode: drive the real encrypted overlay loopback through the
    # production dataplane over whatever path is usable (Relay here), and let
    # the outbound selector ride Relay since Direct is blackholed.
    OVERLAY_FLAGS="$OVERLAY_FLAGS --overlay-any-path"
  fi
  if [[ "$OVERLAY_BURST" -gt 0 ]]; then
    OVERLAY_FLAGS="$OVERLAY_FLAGS --overlay-burst $OVERLAY_BURST"
  fi

  TRAVERSAL_FLAGS=""
  if [[ "$RELAY_COUNT" -ge 2 ]]; then
    # Both daemons must converge on the PRIMARY relay first for the failover
    # scenario to be deterministic.  Equal-region selection uses catalog
    # order as the tie-break, while the selector still connects candidates in
    # parallel and bounds the preference window.
    TRAVERSAL_FLAGS="$TRAVERSAL_FLAGS --relay-regions local"
  fi
  if [[ "$FRESH_MAPPING_PUNCH" == "0" ]]; then TRAVERSAL_FLAGS="$TRAVERSAL_FLAGS --disable-fresh-mapping-punch"; fi
  if [[ "$PREDICTED_CANDIDATES" == "0" ]]; then TRAVERSAL_FLAGS="$TRAVERSAL_FLAGS --disable-predicted-candidates"; fi
  if [[ "$BIRTHDAY_PROBING" == "0" ]]; then TRAVERSAL_FLAGS="$TRAVERSAL_FLAGS --disable-birthday-probing"; fi
  if [[ -n "$SOCKET_POOL" ]]; then TRAVERSAL_FLAGS="$TRAVERSAL_FLAGS --socket-pool $SOCKET_POOL"; fi
  if [[ "${PREFER_RELAY:-0}" == "1" ]]; then TRAVERSAL_FLAGS="$TRAVERSAL_FLAGS --relay-only"; fi

  printf '%s\n' "$TOKEN" | P2WLAN_DISABLE_TUN=1 P2WLAN_TEST_RUN_ID="$ROUND_RUN_ID" RUST_LOG="$NAT_SIM_RUST_LOG" "$ROOT_DIR/target/debug/p2wlan-daemon" \
    --config "$NODE_A_RUNTIME/config.json" \
    --control "http://127.0.0.1:$PORT" \
    --network "$NETWORK_ID" \
    --token-stdin \
    --device-name node-a \
    --udp-bind 127.0.0.1:0 \
    --stun "$STUN_A" \
    --fresh-mapping-harness-loopback \
    --no-host-candidates \
    --diagnostics-bind 127.0.0.1:$DIAG_A_PORT \
    --heartbeat-interval 5 \
    $TRAVERSAL_FLAGS \
    $OVERLAY_FLAGS \
    >"$ROUND_DIR/node-a.log" 2>&1 &
  NODE_A_PID=$!
  PIDS+=($NODE_A_PID)

  for _ in {1..40}; do
    grep -q 'Control plane registration confirmed' "$ROUND_DIR/node-a.log" 2>/dev/null && break
    sleep 0.25
  done

  printf '%s\n' "$TOKEN" | P2WLAN_DISABLE_TUN=1 P2WLAN_TEST_RUN_ID="$ROUND_RUN_ID" RUST_LOG="$NAT_SIM_RUST_LOG" "$ROOT_DIR/target/debug/p2wlan-daemon" \
    --config "$NODE_B_RUNTIME/config.json" \
    --control "http://127.0.0.1:$PORT" \
    --network "$NETWORK_ID" \
    --token-stdin \
    --device-name node-b \
    --udp-bind 127.0.0.1:0 \
    --stun "$STUN_B" \
    --fresh-mapping-harness-loopback \
    --no-host-candidates \
    --diagnostics-bind 127.0.0.1:$DIAG_B_PORT \
    --heartbeat-interval 5 \
    $TRAVERSAL_FLAGS \
    $OVERLAY_FLAGS \
    >"$ROUND_DIR/node-b.log" 2>&1 &
  NODE_B_PID=$!
  PIDS+=($NODE_B_PID)

  if [[ "$MODE" == "relay-only" ]]; then
    # Availability pass condition: BOTH sides complete a bidirectional
    # encrypted overlay loopback (overlay_payload_verified), which here rides
    # Relay.  Direct must not establish (informational, not a failure signal).
    # When OVERLAY_BURST is set, the round additionally waits for the burst to
    # complete on both sides.
    overlay_ok=0
    A_STATUS_SEEN_200=0
    B_STATUS_SEEN_200=0
    A_STATUS_ALWAYS_200=1
    B_STATUS_ALWAYS_200=1
    A_STATUS_SAMPLE_COUNT=0
    B_STATUS_SAMPLE_COUNT=0
    A_STATUS_200_COUNT=0
    B_STATUS_200_COUNT=0
    OVERLAY_DEADLINE=$((SECONDS + OVERLAY_TIMEOUT_S))
    while [[ "$SECONDS" -lt "$OVERLAY_DEADLINE" ]]; do
      sample_relay_status_pair \
        "http://127.0.0.1:$DIAG_A_PORT/status" \
        "$NODE_A_RUNTIME/p2wlan-daemon.diag-auth" \
        "http://127.0.0.1:$DIAG_B_PORT/status" \
        "$NODE_B_RUNTIME/p2wlan-daemon.diag-auth"
      A_OVERLAY=$(grep -c 'overlay_payload_verified' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
      B_OVERLAY=$(grep -c 'overlay_payload_verified' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
      A_BURST=$(grep -c 'overlay_burst_complete' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
      B_BURST=$(grep -c 'overlay_burst_complete' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
      if [[ "$A_OVERLAY" -gt 0 && "$B_OVERLAY" -gt 0 ]]; then
        if [[ "$OVERLAY_BURST" -gt 0 ]]; then
          if [[ "$A_BURST" -ge 1 && "$B_BURST" -ge 1 ]]; then
            overlay_ok=1
            break
          fi
        else
          overlay_ok=1
          break
        fi
      fi
      sleep 0.5
    done
    A_DIRECT=$(grep -c '→ direct' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
    B_DIRECT=$(grep -c '→ direct' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
    direct_ok=0
  else
    # Direct mode proves make-before-break without asking the Direct-only
    # overlay generator to manufacture Relay business traffic. Each side must
    # confirm Relay with an encrypted probe ACK before its first Direct
    # business ingress, then promote Direct via the owned encrypted request/ACK
    # flow and complete a real bidirectional business overlay whose
    # authenticated ingress is Direct. Direct promotion itself may precede the
    # Relay confirmation: an authenticated Direct ACK is authoritative and
    # must not be hidden behind relay catalog publication.
    # Field checks are order-independent because tracing may render fields in
    # either order on the same structured log record.
    direct_ok=0
    for _ in $(seq 1 $((DIRECT_TIMEOUT_S * 2))); do
      if grep -q 'event="relay_peer_confirmed"' "$ROUND_DIR/node-a.log" 2>/dev/null && \
         grep -q 'event="relay_peer_confirmed"' "$ROUND_DIR/node-b.log" 2>/dev/null && \
         grep -q 'event="direct_promoted"' "$ROUND_DIR/node-a.log" 2>/dev/null && \
         grep -q 'event="direct_promoted"' "$ROUND_DIR/node-b.log" 2>/dev/null && \
         awk 'index($0, "overlay_payload_verified") && index($0, "ingress=direct") { found=1; exit } END { exit(found ? 0 : 1) }' "$ROUND_DIR/node-a.log" && \
         awk 'index($0, "overlay_payload_verified") && index($0, "ingress=direct") { found=1; exit } END { exit(found ? 0 : 1) }' "$ROUND_DIR/node-b.log"; then
        direct_ok=1
        break
      fi
      sleep 0.5
    done
    overlay_ok=0
    A_OVERLAY=$(grep -c 'overlay_payload_verified' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
    B_OVERLAY=$(grep -c 'overlay_payload_verified' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
    A_DIRECT=$(grep -c '→ direct' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
    B_DIRECT=$(grep -c '→ direct' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
  fi
  END_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
  ELAPSED_MS=$((END_MS - START_MS))
  STATUS_SCHEMA_OK=1
  fetch_required_json \
    "http://127.0.0.1:$DIAG_A_PORT/status" \
    "$ROUND_DIR/node-a.status.json" \
    status \
    "$NODE_A_RUNTIME/p2wlan-daemon.diag-auth" || STATUS_SCHEMA_OK=0
  fetch_required_json \
    "http://127.0.0.1:$DIAG_B_PORT/status" \
    "$ROUND_DIR/node-b.status.json" \
    status \
    "$NODE_B_RUNTIME/p2wlan-daemon.diag-auth" || STATUS_SCHEMA_OK=0
  METRICS_SCHEMA_OK=1
  fetch_required_json "http://127.0.0.1:$((RELAY_METRICS_PORT))/metrics" "$ROUND_DIR/relay.metrics.json" metrics || METRICS_SCHEMA_OK=0

  # Record the evidence stream for this round.
  {
    echo "== STUN observer allocations (fresh_mapping_observer) =="
    grep -h 'fresh_mapping_observer' "$ROUND_DIR"/node-*.log 2>/dev/null | head -8
    echo "== fresh mapping model =="
    grep -h 'fresh_mapping_model' "$ROUND_DIR"/node-*.log 2>/dev/null | head -2
    echo "== prediction signaled (top-1 + window) =="
    grep -h 'fresh_mapping_prediction_signaled' "$ROUND_DIR"/node-*.log 2>/dev/null | head -2
    echo "== peer-reflexive ports observed =="
    grep -h 'peer_reflexive' "$ROUND_DIR"/node-*.log 2>/dev/null | head -4
    echo "== matched punch ACKs =="
    grep -h 'received authenticated UDP punch ACK\|received UDP punch ACK' "$ROUND_DIR"/node-*.log 2>/dev/null | head -2
    echo "== direct validation request/ack =="
    grep -h -E 'direct_validation_(queued|started|waiting_for_session|session_ready|request_sent|request_received|request_dropped|ack_sent|ack_received|ack_wait_timeout|ack_unmatched|ack_not_promoted|ack_send_failed|emit_lock_timeout|timed_out|failed|cancelled|completed|promoted|suppressed)|direct_path_promoted' "$ROUND_DIR"/node-*.log 2>/dev/null | head -120
    echo "== direct traversal plan lifecycle =="
    grep -h -E 'direct_punch_(started|completed|failed|cancelled)|direct_fast_probe_(started|sent|failed|confirmed)|direct_probe_(ack_timeout|budget_exhausted)|direct_candidates_ready|candidate_pair_probe_succeeded|retry_(punch_started|probes_sent|ack_timeout|probe_succeeded|send_error)|direct_reclaim_(punch_started|probes_sent|ack_timeout|probe_succeeded|send_error)|fresh_mapping_(generation_started|generation_completed|generation_failed|prediction_signaled)' "$ROUND_DIR"/node-*.log 2>/dev/null | head -160
    echo "== promotion times =="
    grep -h 'direct_path_promoted\|candidate_pair_selected' "$ROUND_DIR"/node-*.log 2>/dev/null | head -2
    echo "== relay hedge =="
    grep -h 'relay' "$ROUND_DIR"/node-*.log 2>/dev/null | grep -i 'selected\|fallback' | head -2
    echo "== connection timeline (first usable / relay / direct milestones) =="
    grep -hE 'relay_selection_started|relay_transport_connected|relay_transport_ready_peer|relay_probe_sent|relay_probe_ack_consumed|relay_peer_confirmed|first_direct_probe_sent|direct_promoted|outbound_first_packet_wait_started|outbound_first_packet_flushed|first_usable_path|first_usable_bidirectional_overlay_ms|relay_unavailable_or_first_packet_expired' "$ROUND_DIR"/node-*.log 2>/dev/null | head -16
    echo "== per-packet dataplane boundaries (counter -> handoff -> peer decrypt) =="
    grep -hE 'wireguard_outbound_counter_allocated|outbound_business_emit_lock_acquired|outbound_counter_allocation_rejected|outbound_transport_handoff_started|control_transport_handoff_started|control_transport_handoff_completed|relay_writer_queue_accepted|relay_writer_queue_rejected|relay_writer_completion_received|relay_writer_completion_missing|relay_write_started|relay_write_completed|relay_write_failed|relay_data_send_started|relay_data_write_started|relay_data_write_completed|relay_data_send_failed|relay_outbound_write_started|relay_outbound_write_completed|relay_outbound_write_failed|relay_inbound_frame_accepted|direct_data_send_started|direct_data_handoff_accepted|direct_data_send_failed|wireguard_inbound_decrypt_succeeded|hedge_duplicate_replay|outbound_send_timeout|outbound_terminal_drop' "$ROUND_DIR"/node-*.log 2>/dev/null | head -220
    echo "== overlay loopback evidence =="
    grep -h 'overlay_payload_verified\|overlay_payload_sent\|overlay_payload_echo\|first_usable_confirmed' "$ROUND_DIR"/node-*.log 2>/dev/null | head -6
  } >"$ROUND_DIR/evidence.log" 2>&1 || true

  # Per-daemon monotonic relay-ready -> first production business delta: the
  # harness computes each delta from that daemon's own t_ms values and only
  # reports their sum as a convenience; it never subtracts wall clocks across
  # machines.
  A_DELTA=$(node_first_usable_delta_ms "$ROUND_DIR/node-a.log")
  B_DELTA=$(node_first_usable_delta_ms "$ROUND_DIR/node-b.log")
  DELTA_OK=1
  if [[ -z "$A_DELTA" || -z "$B_DELTA" ]]; then
    if [[ "$MODE" == "relay-only" ]]; then
      echo "[nat-sim] ROUND $round: FAIL reason_code=first_usable_delta_missing a_delta=${A_DELTA:-missing} b_delta=${B_DELTA:-missing}" >&2
      DELTA_OK=0
      overall=1
      A_DELTA=-1
      B_DELTA=-1
      SUM_DELTA=-1
    else
      echo "[nat-sim] ROUND $round: FAIL reason_code=first_usable_delta_missing a_delta=${A_DELTA:-missing} b_delta=${B_DELTA:-missing}" >&2
      DELTA_OK=0
      overall=1
      A_DELTA=-1
      B_DELTA=-1
      SUM_DELTA=-1
    fi
  else
    SUM_DELTA=$((A_DELTA + B_DELTA))
    DELTA_SUMS+=("$SUM_DELTA")
  fi

  if [[ "$MODE" == "relay-only" && "$RELAY_DELAY_MS" -gt 0 ]]; then
    if [[ "$DELTA_OK" -ne 1 || "$A_DELTA" -gt 3000 || "$B_DELTA" -gt 3000 ]]; then
      echo "[nat-sim] ROUND $round: FAIL reason_code=relay_first_slo_exceeded slow_relay_delay_ms=$RELAY_DELAY_MS a_delta_ms=$A_DELTA b_delta_ms=$B_DELTA slo_ms=3000" >&2
      overall=1
    else
      echo "[nat-sim] ROUND $round: FAIL reason_code=slow_relay_test_not_exercised delay_ms=$RELAY_DELAY_MS" >&2
      overall=1
    fi
  fi
  A_INGRESS=$(node_first_usable_ingress "$ROUND_DIR/node-a.log")
  B_INGRESS=$(node_first_usable_ingress "$ROUND_DIR/node-b.log")
  A_RELAY_CONFIRMED=$(node_relay_confirmed_count "$ROUND_DIR/node-a.log")
  B_RELAY_CONFIRMED=$(node_relay_confirmed_count "$ROUND_DIR/node-b.log")
  # First failure reason_code seen on either node this round (drop/cancel reason).
  FAIL_CODE=$(node_failure_code "$ROUND_DIR/node-a.log")
  [[ -z "$FAIL_CODE" ]] && FAIL_CODE=$(node_failure_code "$ROUND_DIR/node-b.log")
  [[ -n "$FAIL_CODE" ]] && FAILURE_CODES+=("$FAIL_CODE")

  if [[ "$MODE" == "relay-only" ]]; then
    # Availability: the relay-first evidence gate is STRICT.  A round PASSES
    # only when EVERY one of these holds:
    #   - the encrypted overlay loopback completed on BOTH sides;
    #   - Direct never established (blackholed) on either side;
    #   - BOTH sides emitted RelayPeerConfirmed (forced-probe ACK, real relay
    #     ingress);
    #   - BOTH sides' first usable path had real relay ingress (ingress=relay:),
    #     which by construction required a locally-sent, matching-nonce echo;
    #   - each daemon's OWN monotonic relay-ready -> usable delta <= 3000ms;
    #   - zero structured outbound drops, zero WireGuard replay rejects and
    #     zero overlay duplicate/invalid on BOTH sides;
    #   - when OVERLAY_BURST is set: the full burst completed on BOTH sides.
    a_relay_first=0
    b_relay_first=0
    [[ "$A_INGRESS" == relay:* ]] && a_relay_first=1
    [[ "$B_INGRESS" == relay:* ]] && b_relay_first=1
    read -r A_DROPS A_DROP_BYTES < <(python3 -c "
import json,sys
try:
    d=json.load(open('$ROUND_DIR/node-a.status.json'))
    s=d.get('stats',{})
    drops=s['outbound_drops']
    if not isinstance(drops, dict): raise ValueError('outbound_drops schema')
    packets=sum(int(v['packets']) for v in drops.values())
    bytes_=sum(int(v['bytes']) for v in drops.values())
    print(packets, bytes_)
except Exception:
    print('-1 -1')")
    read -r B_DROPS B_DROP_BYTES < <(python3 -c "
import json,sys
try:
    d=json.load(open('$ROUND_DIR/node-b.status.json'))
    s=d.get('stats',{})
    drops=s['outbound_drops']
    if not isinstance(drops, dict): raise ValueError('outbound_drops schema')
    packets=sum(int(v['packets']) for v in drops.values())
    bytes_=sum(int(v['bytes']) for v in drops.values())
    print(packets, bytes_)
except Exception:
    print('-1 -1')")
    A_REPLAY=$(grep -c 'replay detected' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
    B_REPLAY=$(grep -c 'replay detected' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
    A_INVALID=$(grep -c 'overlay_payload_invalid' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
    B_INVALID=$(grep -c 'overlay_payload_invalid' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
    A_BURST=$(grep -c 'overlay_burst_complete' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
    B_BURST=$(grep -c 'overlay_burst_complete' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
    A_BURST_BAD=$(grep -c 'overlay_burst_incomplete' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
    B_BURST_BAD=$(grep -c 'overlay_burst_incomplete' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
    A_TASKS_OK=$(node_task_health_ok "$ROUND_DIR/node-a.status.json")
    B_TASKS_OK=$(node_task_health_ok "$ROUND_DIR/node-b.status.json")
    BURST_OK=1
    if [[ "$OVERLAY_BURST" -gt 0 ]]; then
      [[ "$A_BURST" -ge 1 && "$B_BURST" -ge 1 && "$A_BURST_BAD" -eq 0 && "$B_BURST_BAD" -eq 0 ]] || BURST_OK=0
    fi
    if [[ "$STATUS_SCHEMA_OK" -eq 1 && "$METRICS_SCHEMA_OK" -eq 1 && "$DELTA_OK" -eq 1 \
          && "$overlay_ok" -eq 1 && "$A_DIRECT" -eq 0 && "$B_DIRECT" -eq 0 \
          && "$A_RELAY_CONFIRMED" -ge 1 && "$B_RELAY_CONFIRMED" -ge 1 \
          && "$a_relay_first" -eq 1 && "$b_relay_first" -eq 1 \
          && "$A_DELTA" -ge 0 && "$A_DELTA" -le 3000 \
          && "$B_DELTA" -ge 0 && "$B_DELTA" -le 3000 \
          && "$A_DROPS" -eq 0 && "$B_DROPS" -eq 0 \
          && "$A_REPLAY" -eq 0 && "$B_REPLAY" -eq 0 \
          && "$A_INVALID" -eq 0 && "$B_INVALID" -eq 0 \
          && "$A_STATUS_SEEN_200" -eq 1 && "$B_STATUS_SEEN_200" -eq 1 \
          && "$A_STATUS_ALWAYS_200" -eq 1 && "$B_STATUS_ALWAYS_200" -eq 1 \
          && "$A_TASKS_OK" -eq 1 && "$B_TASKS_OK" -eq 1 \
          && "$BURST_OK" -eq 1 ]]; then
      echo "[nat-sim] ROUND $round: PASS relay_first_evidence overlay_ok=1 a_direct=$A_DIRECT b_direct=$B_DIRECT a_overlay=$A_OVERLAY b_overlay=$B_OVERLAY a_relay_confirmed=$A_RELAY_CONFIRMED b_relay_confirmed=$B_RELAY_CONFIRMED a_ingress=${A_INGRESS:-none} b_ingress=${B_INGRESS:-none} a_delta_ms=$A_DELTA b_delta_ms=$B_DELTA sum_delta_ms=$SUM_DELTA drops_a=$A_DROPS drops_b=$B_DROPS replay_a=$A_REPLAY replay_b=$B_REPLAY invalid_a=$A_INVALID invalid_b=$B_INVALID burst_a=$A_BURST burst_b=$B_BURST status_http_200_a=$A_STATUS_200_COUNT/$A_STATUS_SAMPLE_COUNT status_http_200_b=$B_STATUS_200_COUNT/$B_STATUS_SAMPLE_COUNT task_leak_a=$((1 - A_TASKS_OK)) task_leak_b=$((1 - B_TASKS_OK)) elapsed_ms=$ELAPSED_MS failure_reason=${FAIL_CODE:-none} evidence=$ROUND_DIR/evidence.log"
    else
      echo "[nat-sim] ROUND $round: FAIL relay_first_evidence overlay_ok=$overlay_ok a_direct=$A_DIRECT b_direct=$B_DIRECT a_overlay=$A_OVERLAY b_overlay=$B_OVERLAY a_relay_confirmed=$A_RELAY_CONFIRMED b_relay_confirmed=$B_RELAY_CONFIRMED a_ingress=${A_INGRESS:-none} b_ingress=${B_INGRESS:-none} a_delta_ms=$A_DELTA b_delta_ms=$B_DELTA sum_delta_ms=$SUM_DELTA drops_a=$A_DROPS drops_b=$B_DROPS replay_a=$A_REPLAY replay_b=$B_REPLAY invalid_a=$A_INVALID invalid_b=$B_INVALID burst_a=$A_BURST burst_b=$B_BURST burst_bad_a=$A_BURST_BAD burst_bad_b=$B_BURST_BAD status_http_200_a=$A_STATUS_200_COUNT/$A_STATUS_SAMPLE_COUNT status_http_200_b=$B_STATUS_200_COUNT/$B_STATUS_SAMPLE_COUNT status_always_200_a=$A_STATUS_ALWAYS_200 status_always_200_b=$B_STATUS_ALWAYS_200 task_health_a=$A_TASKS_OK task_health_b=$B_TASKS_OK elapsed_ms=$ELAPSED_MS failure_reason=${FAIL_CODE:-none} (strict relay-first evidence required: both RelayPeerConfirmed, ingress=relay:*, per-daemon delta <= 3000ms, zero drops/replay/invalid, burst complete, status always HTTP 200, no supervised task exit)"
      overall=1
    fi
  else
    # A single-sided Direct, Relay confirmation after the first Direct business
    # ingress, unverified Direct business ingress, loss/replay/invalid packets,
    # or a missing/slow relay-ready-to-business delta is a failure. The
    # Direct-only overlay generator intentionally does not create Relay
    # business traffic.
    read -r A_DROPS A_DROP_BYTES < <(python3 -c "
import json,sys
try:
    d=json.load(open('$ROUND_DIR/node-a.status.json'))
    drops=d.get('stats',{})['outbound_drops']
    print(sum(int(v['packets']) for v in drops.values()), sum(int(v['bytes']) for v in drops.values()))
except Exception:
    print('-1 -1')")
    read -r B_DROPS B_DROP_BYTES < <(python3 -c "
import json,sys
try:
    d=json.load(open('$ROUND_DIR/node-b.status.json'))
    drops=d.get('stats',{})['outbound_drops']
    print(sum(int(v['packets']) for v in drops.values()), sum(int(v['bytes']) for v in drops.values()))
except Exception:
    print('-1 -1')")
    A_REPLAY=$(grep -c 'replay detected' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
    B_REPLAY=$(grep -c 'replay detected' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
    A_INVALID=$(grep -c 'overlay_payload_invalid' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
    B_INVALID=$(grep -c 'overlay_payload_invalid' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
    A_RELAY_CONFIRMED_TMS=$(node_event_tms "$ROUND_DIR/node-a.log" relay_peer_confirmed)
    B_RELAY_CONFIRMED_TMS=$(node_event_tms "$ROUND_DIR/node-b.log" relay_peer_confirmed)
    A_DIRECT_PROMOTED_TMS=$(node_event_tms "$ROUND_DIR/node-a.log" direct_promoted)
    B_DIRECT_PROMOTED_TMS=$(node_event_tms "$ROUND_DIR/node-b.log" direct_promoted)
    A_DIRECT_BUSINESS_TMS=$(node_event_tms "$ROUND_DIR/node-a.log" first_real_business_ingress)
    B_DIRECT_BUSINESS_TMS=$(node_event_tms "$ROUND_DIR/node-b.log" first_real_business_ingress)
    relay_before_direct_business_ok=1
    if [[ ! "$A_RELAY_CONFIRMED_TMS" =~ ^[0-9]+$ || ! "$B_RELAY_CONFIRMED_TMS" =~ ^[0-9]+$ \
          || ! "$A_DIRECT_PROMOTED_TMS" =~ ^[0-9]+$ || ! "$B_DIRECT_PROMOTED_TMS" =~ ^[0-9]+$ \
          || ! "$A_DIRECT_BUSINESS_TMS" =~ ^[0-9]+$ || ! "$B_DIRECT_BUSINESS_TMS" =~ ^[0-9]+$ ]]; then
      relay_before_direct_business_ok=0
    elif (( A_RELAY_CONFIRMED_TMS > A_DIRECT_BUSINESS_TMS \
            || B_RELAY_CONFIRMED_TMS > B_DIRECT_BUSINESS_TMS )); then
      relay_before_direct_business_ok=0
    fi
    a_direct_business=0
    b_direct_business=0
    [[ "$A_INGRESS" == "direct" ]] && a_direct_business=1
    [[ "$B_INGRESS" == "direct" ]] && b_direct_business=1
    if [[ "$direct_ok" -eq 1 && "$STATUS_SCHEMA_OK" -eq 1 && "$METRICS_SCHEMA_OK" -eq 1 \
          && "$DELTA_OK" -eq 1 && "$A_DELTA" -ge 0 && "$A_DELTA" -le 3000 \
          && "$B_DELTA" -ge 0 && "$B_DELTA" -le 3000 \
          && "$A_RELAY_CONFIRMED" -ge 1 && "$B_RELAY_CONFIRMED" -ge 1 \
          && "$relay_before_direct_business_ok" -eq 1 \
          && "$a_direct_business" -eq 1 && "$b_direct_business" -eq 1 \
          && "$A_DROPS" -eq 0 && "$B_DROPS" -eq 0 \
          && "$A_REPLAY" -eq 0 && "$B_REPLAY" -eq 0 \
          && "$A_INVALID" -eq 0 && "$B_INVALID" -eq 0 ]]; then
      echo "[nat-sim] ROUND $round: PASS both_direct relay_before_direct_business=1 a_relay_confirmed_t_ms=$A_RELAY_CONFIRMED_TMS b_relay_confirmed_t_ms=$B_RELAY_CONFIRMED_TMS a_direct_promoted_t_ms=$A_DIRECT_PROMOTED_TMS b_direct_promoted_t_ms=$B_DIRECT_PROMOTED_TMS a_direct_business_t_ms=$A_DIRECT_BUSINESS_TMS b_direct_business_t_ms=$B_DIRECT_BUSINESS_TMS a_delta_ms=$A_DELTA b_delta_ms=$B_DELTA sum_delta_ms=$SUM_DELTA a_ingress=${A_INGRESS:-none} b_ingress=${B_INGRESS:-none} elapsed_ms=$ELAPSED_MS failure_reason=${FAIL_CODE:-none} (a_direct=$A_DIRECT b_direct=$B_DIRECT) a_overlay=$A_OVERLAY b_overlay=$B_OVERLAY evidence=$ROUND_DIR/evidence.log"
    else
      if [[ "$direct_ok" -ne 1 ]]; then
        DIRECT_REASON="direct_overlay_unverified"
      elif [[ "$DELTA_OK" -ne 1 || "$A_DELTA" -lt 0 || "$B_DELTA" -lt 0 ]]; then
        DIRECT_REASON="first_usable_delta_missing"
      elif [[ "$A_DELTA" -gt 3000 || "$B_DELTA" -gt 3000 ]]; then
        DIRECT_REASON="relay_first_slo_exceeded"
      elif [[ "$A_RELAY_CONFIRMED" -lt 1 || "$B_RELAY_CONFIRMED" -lt 1 ]]; then
        DIRECT_REASON="relay_confirmation_missing"
      elif [[ "$relay_before_direct_business_ok" -ne 1 ]]; then
        DIRECT_REASON="relay_not_confirmed_before_direct_business"
      elif [[ "$a_direct_business" -ne 1 || "$b_direct_business" -ne 1 ]]; then
        DIRECT_REASON="direct_business_ingress_missing"
      elif [[ "$A_DROPS" -ne 0 || "$B_DROPS" -ne 0 ]]; then
        DIRECT_REASON="outbound_drop"
      elif [[ "$A_REPLAY" -ne 0 || "$B_REPLAY" -ne 0 ]]; then
        DIRECT_REASON="replay_detected"
      elif [[ "$A_INVALID" -ne 0 || "$B_INVALID" -ne 0 ]]; then
        DIRECT_REASON="overlay_invalid"
      elif [[ "$STATUS_SCHEMA_OK" -ne 1 ]]; then
        DIRECT_REASON="status_schema_invalid"
      else
        DIRECT_REASON="metrics_schema_invalid"
      fi
      echo "[nat-sim] ROUND $round: FAIL reason_code=$DIRECT_REASON a_direct=$A_DIRECT b_direct=$B_DIRECT a_overlay=$A_OVERLAY b_overlay=$B_OVERLAY a_relay_confirmed=$A_RELAY_CONFIRMED b_relay_confirmed=$B_RELAY_CONFIRMED a_ingress=${A_INGRESS:-none} b_ingress=${B_INGRESS:-none} a_delta_ms=$A_DELTA b_delta_ms=$B_DELTA sum_delta_ms=$SUM_DELTA drops_a=$A_DROPS drops_b=$B_DROPS replay_a=$A_REPLAY replay_b=$B_REPLAY invalid_a=$A_INVALID invalid_b=$B_INVALID elapsed_ms=$ELAPSED_MS failure_reason=${FAIL_CODE:-none} evidence=$ROUND_DIR/evidence.log"
      overall=1
    fi
  fi

  # Relay resilience scenarios (diagnostic; only run in relay-only mode where
  # the relay is the only data path).
  if [[ "$MODE" == "relay-only" && "$RELAY_KILL_RESTART" == "1" ]]; then
    # Kill the active relay and restart it on the same port: the daemon must
    # reconnect and the encrypted overlay must recover (verified round trips
    # continue growing) within the window.
    A_BEFORE=$(grep -c 'overlay_payload_verified' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
    B_BEFORE=$(grep -c 'overlay_payload_verified' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
    kill "${RELAY_PIDS[0]}" 2>/dev/null || true
    wait "${RELAY_PIDS[0]}" 2>/dev/null || true
    sleep 1
    KEYRING_JSON="{\"relay-sim\":\"$RELAY_PUB\"}"
    RELAY_AUDIENCE="relay-sim" RELAY_REGION="local" "$BASE_DIR/relay-server" \
      -bind "127.0.0.1:$RELAY_PORT" \
      -ticket-keyring "$KEYRING_JSON" -require-auth -allow-insecure-plaintext \
      -metrics-bind "127.0.0.1:$RELAY_METRICS_PORT" \
      -forward-delay "${RELAY_DELAY_MS}ms" \
      >"$ROUND_DIR/relay-restarted.log" 2>&1 &
    RELAY_PIDS[0]=$!
    PIDS+=($!)
    recovered=0
    for _ in $(seq 1 $((OVERLAY_TIMEOUT_S * 4))); do
      A_AFTER=$(grep -c 'overlay_payload_verified' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
      B_AFTER=$(grep -c 'overlay_payload_verified' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
      if [[ "$A_AFTER" -gt "$A_BEFORE" && "$B_AFTER" -gt "$B_BEFORE" ]]; then
        recovered=1
        break
      fi
      sleep 0.5
    done
    if [[ "$recovered" -eq 1 ]]; then
      echo "[nat-sim] ROUND $round: PASS relay_kill_restart_recovery overlay_before=$A_BEFORE after_a=$A_AFTER"
    else
      echo "[nat-sim] ROUND $round: FAIL relay_kill_restart_recovery (overlay did not recover after relay restart)"
      overall=1
    fi
  fi

  if [[ "$MODE" == "relay-only" && "$RELAY_FAILOVER" == "1" && "$RELAY_COUNT" -ge 2 ]]; then
    # Kill the ACTIVE relay (the one the daemons confirmed on); with another
    # candidate in the catalog the daemon must fail over, re-probe and
    # re-confirm on the replacement relay, and the overlay must keep running.
    # Capture line offsets before the kill so old business traffic cannot be
    # mistaken for post-failover recovery.
    A_FAILOVER_START_LINE=$(($(wc -l < "$ROUND_DIR/node-a.log") + 1))
    B_FAILOVER_START_LINE=$(($(wc -l < "$ROUND_DIR/node-b.log") + 1))
    ACTIVE_ENDPOINT=$(node_relay_confirmed_endpoints "$ROUND_DIR/node-a.log" | head -1 || true)
    if [[ -z "$ACTIVE_ENDPOINT" ]]; then
      echo "[nat-sim] ROUND $round: FAIL relay_failover (could not determine the active relay endpoint)"
      overall=1
    else
      ACTIVE_PORT=$(printf '%s' "$ACTIVE_ENDPOINT" | grep -oE '[0-9]+$')
      killed=0
      for idx in $(seq 1 "$RELAY_COUNT"); do
        R_PORT=$((RELAY_PORT + idx - 1))
        if [[ "$R_PORT" == "$ACTIVE_PORT" ]]; then
          kill "${RELAY_PIDS[$((idx - 1))]}" 2>/dev/null || true
          wait "${RELAY_PIDS[$((idx - 1))]}" 2>/dev/null || true
          killed=1
          break
        fi
      done
      if [[ "$killed" -eq 0 ]]; then
        echo "[nat-sim] ROUND $round: FAIL relay_failover (active relay $ACTIVE_ENDPOINT not among the started relays)"
        overall=1
      else
        re_confirmed=0
        for _ in $(seq 1 $((OVERLAY_TIMEOUT_S * 4))); do
          A_REPLACEMENT=$(node_replacement_relay_endpoint "$ROUND_DIR/node-a.log" "$ACTIVE_ENDPOINT")
          B_REPLACEMENT=$(node_replacement_relay_endpoint "$ROUND_DIR/node-b.log" "$ACTIVE_ENDPOINT")
          A_POST_INGRESS=$(node_post_failover_relay_ingress "$ROUND_DIR/node-a.log" "$A_FAILOVER_START_LINE" "$ACTIVE_ENDPOINT")
          B_POST_INGRESS=$(node_post_failover_relay_ingress "$ROUND_DIR/node-b.log" "$B_FAILOVER_START_LINE" "$ACTIVE_ENDPOINT")
          if [[ -n "$A_REPLACEMENT" && "$A_REPLACEMENT" == "$B_REPLACEMENT" \
                && -n "$A_POST_INGRESS" && -n "$B_POST_INGRESS" ]]; then
            re_confirmed=1
            break
          fi
          sleep 0.5
        done
        if [[ "$re_confirmed" -eq 1 ]]; then
          echo "[nat-sim] ROUND $round: PASS relay_failover_reconfirmed active=$ACTIVE_ENDPOINT replacement=$A_REPLACEMENT post_ingress_a=$A_POST_INGRESS post_ingress_b=$B_POST_INGRESS"
        else
          echo "[nat-sim] ROUND $round: FAIL reason_code=relay_failover_no_replacement_business active=$ACTIVE_ENDPOINT replacement_a=${A_REPLACEMENT:-none} replacement_b=${B_REPLACEMENT:-none} post_ingress_a=${A_POST_INGRESS:-none} post_ingress_b=${B_POST_INGRESS:-none}"
          overall=1
        fi
      fi
    fi
  fi

  # Also check for daemon crashes / socket leaks before tearing down.
  if ! kill -0 "$NODE_A_PID" 2>/dev/null || ! kill -0 "$NODE_B_PID" 2>/dev/null; then
    echo "[nat-sim] ROUND $round: FAIL (daemon exited unexpectedly)"
    overall=1
  fi

  kill "$NODE_A_PID" "$NODE_B_PID" "$SERVER_PID" "$NAT_PID" 2>/dev/null || true
  for relay_pid in "${RELAY_PIDS[@]:-}"; do
    kill "$relay_pid" 2>/dev/null || true
  done
  wait "$NODE_A_PID" "$NODE_B_PID" "$SERVER_PID" "$NAT_PID" 2>/dev/null || true
  for relay_pid in "${RELAY_PIDS[@]:-}"; do
    wait "$relay_pid" 2>/dev/null || true
  done
  PIDS=()
  sleep 0.5
done

echo "[nat-sim] base dir: $BASE_DIR"
# p95 of the per-round summed relay-ready -> usable deltas (monotonic, ms).
if [[ "${#DELTA_SUMS[@]}" -gt 0 ]]; then
  DELTA_P95=$(printf '%s\n' "${DELTA_SUMS[@]}" | sort -n | python3 -c 'import sys,math; vals=[int(x) for x in sys.stdin]; n=len(vals); idx=max(0, min(n-1, math.ceil(0.95*n)-1)); print(vals[idx])')
  DELTA_MEAN=$(printf '%s\n' "${DELTA_SUMS[@]}" | awk '{s+=$1; n++} END {print (n>0 ? int(s/n) : 0)}')
  echo "[nat-sim] delta_sum_ms rounds=${#DELTA_SUMS[@]} mean=$DELTA_MEAN p95=$DELTA_P95 values=${DELTA_SUMS[*]}"
fi
if [[ "${#FAILURE_CODES[@]}" -gt 0 ]]; then
  echo "[nat-sim] failure reason_codes seen: ${FAILURE_CODES[*]}"
fi
echo "[nat-sim] RESULT: $([ "$overall" -eq 0 ] && echo PASS || echo FAIL)"
exit $overall
