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

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# The standalone local control DB provisions only `default`; the real dual-end
# harness uses NETWORK_ID explicitly and requires a provisioned test network.
NETWORK_ID=${NETWORK_ID:-default}
MODE=${MODE:-direct}
NAT_SIM_RUST_LOG=${NAT_SIM_RUST_LOG:-info}
ROUNDS=${ROUNDS:-5}
NAT_SEED_BASE=${NAT_SEED_BASE:-20260806}
PORT=${PORT:-38080}
RELAY_PORT=${RELAY_PORT:-38081}
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
BIRTHDAY_PROBING=${BIRTHDAY_PROBING:-1}
SOCKET_POOL=${SOCKET_POOL:-}
BASE_A=${BASE_A:-36000}
BASE_B=${BASE_B:-46000}
DIRECT_TIMEOUT_S=${DIRECT_TIMEOUT_S:-60}
OVERLAY_TIMEOUT_S=${OVERLAY_TIMEOUT_S:-30}
NAT_SIM_ARTIFACT_DIR=${NAT_SIM_ARTIFACT_DIR:-}

if ! [[ "$NAT_SEED_BASE" =~ ^[0-9]+$ ]]; then
  echo "[nat-sim] NAT_SEED_BASE must be a non-negative integer" >&2
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
  strip_ansi < "$log" | grep -m1 "event=\"${ev}\"" | grep -oE 't_ms=[0-9]+' | head -1 | cut -d= -f2 || true
}

# Extract the real ingress path of the first usable path (relay:<endpoint> or
# direct), from the first_usable_confirmed structured event (never inferred
# from active_path).
node_first_usable_ingress() {
  local log="$1"
  strip_ansi < "$log" | grep -m1 'event="first_usable_confirmed"' | grep -oE 'ingress=[^ ]+' | head -1 | cut -d= -f2 || true
}

# Extract the per-daemon monotonic relay-ready -> usable delta (ms) computed on
# that daemon's own clock and reported in the first_usable_confirmed event.
node_first_usable_delta_ms() {
  local log="$1"
  strip_ansi < "$log" | grep -m1 'event="first_usable_confirmed"' | grep -oE 'relay_ready_to_usable_ms=Some\([0-9]+\)' | head -1 | grep -oE '[0-9]+' || true
}

# First stable drop/cancel reason_code seen on a node's timeline (if any).
node_failure_code() {
  local log="$1"
  strip_ansi < "$log" | grep "relay_unavailable_or_first_packet_expired" | grep -oE 'reason_code=Some\("[A-Za-z0-9_]+"\)' | head -1 | sed -E 's/.*reason_code=Some\("([A-Za-z0-9_]+)"\).*/\1/' || true
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
echo "[nat-sim] traversal flags: strict_filtering=$STRICT_FILTERING fresh_mapping=$FRESH_MAPPING_PUNCH birthday=$BIRTHDAY_PROBING socket_pool=${SOCKET_POOL:-default}"
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
  mkdir -p "$ROUND_DIR"
  NAT_SEED=$((NAT_SEED_BASE + round))

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

  # Relay (safety net; TCP, bypasses the NATs).
  KEYRING_JSON="{\"relay-sim\":\"$RELAY_PUB\"}"
  RELAY_AUDIENCE="relay-sim" RELAY_REGION="local" "$BASE_DIR/relay-server" -bind "127.0.0.1:$RELAY_PORT" \
    -ticket-keyring "$KEYRING_JSON" -require-auth -allow-insecure-plaintext \
    >"$ROUND_DIR/relay.log" 2>&1 &
  RELAY_PID=$!
  PIDS+=($RELAY_PID)

  # Control server with the relay catalog (no UDP observer in the catalog:
  # every STUN flow must traverse the simulated NATs).
  export PORT DB_PATH="$ROUND_DIR/control.db" JWT_SECRET=smoke \
    RELAY_TICKET_SIGNER_JSON="{\"active\":{\"kid\":\"relay-sim\",\"private_key\":\"$RELAY_SEED\"}}" \
    RELAY_CATALOG_JSON="[{\"region\":\"local\",\"audience\":\"relay-sim\",\"endpoint\":\"tcp://127.0.0.1:$RELAY_PORT\"}]"
  "$BASE_DIR/control-server" >"$ROUND_DIR/server.log" 2>&1 &
  SERVER_PID=$!
  PIDS+=($SERVER_PID)

  for _ in {1..40}; do
    curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break
    sleep 0.25
  done
  curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null

  REGISTER_JSON=$(curl -fsS -X POST "http://127.0.0.1:$PORT/api/v1/register" \
    -H 'Content-Type: application/json' \
    -d '{"email":"smoke@example.com","password":"passw0rd"}')
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

  TRAVERSAL_FLAGS=""
  if [[ "$FRESH_MAPPING_PUNCH" == "0" ]]; then TRAVERSAL_FLAGS="$TRAVERSAL_FLAGS --disable-fresh-mapping-punch"; fi
  if [[ "$BIRTHDAY_PROBING" == "0" ]]; then TRAVERSAL_FLAGS="$TRAVERSAL_FLAGS --disable-birthday-probing"; fi
  if [[ -n "$SOCKET_POOL" ]]; then TRAVERSAL_FLAGS="$TRAVERSAL_FLAGS --socket-pool $SOCKET_POOL"; fi

  P2WLAN_DISABLE_TUN=1 RUST_LOG="$NAT_SIM_RUST_LOG" "$ROOT_DIR/target/debug/p2wlan-daemon" \
    --config "$ROUND_DIR/node-a.json" \
    --control "http://127.0.0.1:$PORT" \
    --network "$NETWORK_ID" \
    --token "$TOKEN" \
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

  P2WLAN_DISABLE_TUN=1 RUST_LOG="$NAT_SIM_RUST_LOG" "$ROOT_DIR/target/debug/p2wlan-daemon" \
    --config "$ROUND_DIR/node-b.json" \
    --control "http://127.0.0.1:$PORT" \
    --network "$NETWORK_ID" \
    --token "$TOKEN" \
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
    overlay_ok=0
    for _ in $(seq 1 $((OVERLAY_TIMEOUT_S * 2))); do
      A_OVERLAY=$(grep -c 'overlay_payload_verified' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
      B_OVERLAY=$(grep -c 'overlay_payload_verified' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
      if [[ "$A_OVERLAY" -gt 0 && "$B_OVERLAY" -gt 0 ]]; then
        overlay_ok=1
        break
      fi
      sleep 0.5
    done
    A_DIRECT=$(grep -c '→ direct' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
    B_DIRECT=$(grep -c '→ direct' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
    direct_ok=0
  else
    # Direct mode: require BOTH Direct promotions and a bidirectional encrypted
    # overlay loopback on each daemon.  The validation loop targets Direct
    # peers only in this mode, so the payload cannot be carried by Relay.
    direct_ok=0
    for _ in $(seq 1 $((DIRECT_TIMEOUT_S * 2))); do
      if grep -q '→ direct' "$ROUND_DIR/node-a.log" 2>/dev/null && \
         grep -q '→ direct' "$ROUND_DIR/node-b.log" 2>/dev/null && \
         grep -q 'overlay_payload_verified' "$ROUND_DIR/node-a.log" 2>/dev/null && \
         grep -q 'overlay_payload_verified' "$ROUND_DIR/node-b.log" 2>/dev/null; then
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
  curl -fsS --max-time 5 "http://127.0.0.1:$DIAG_A_PORT/status" >"$ROUND_DIR/node-a.status.json" || printf '{}\n' >"$ROUND_DIR/node-a.status.json"
  curl -fsS --max-time 5 "http://127.0.0.1:$DIAG_B_PORT/status" >"$ROUND_DIR/node-b.status.json" || printf '{}\n' >"$ROUND_DIR/node-b.status.json"

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
    grep -h 'direct_validation_request_sent\|direct_validation_request_received\|direct_validation_ack_received\|direct_validation_promoted' "$ROUND_DIR"/node-*.log 2>/dev/null | head -4
    echo "== promotion times =="
    grep -h 'direct_path_promoted\|candidate_pair_selected' "$ROUND_DIR"/node-*.log 2>/dev/null | head -2
    echo "== relay hedge =="
    grep -h 'relay' "$ROUND_DIR"/node-*.log 2>/dev/null | grep -i 'selected\|fallback' | head -2
    echo "== connection timeline (first usable / relay / direct milestones) =="
    grep -hE 'relay_selection_started|relay_transport_connected|relay_transport_ready_peer|relay_probe_sent|relay_probe_ack_consumed|relay_peer_confirmed|first_direct_probe_sent|direct_promoted|outbound_first_packet_wait_started|outbound_first_packet_flushed|first_usable_path|first_usable_bidirectional_overlay_ms|relay_unavailable_or_first_packet_expired' "$ROUND_DIR"/node-*.log 2>/dev/null | head -16
    echo "== overlay loopback evidence =="
    grep -h 'overlay_payload_verified\|overlay_payload_sent\|overlay_payload_echo\|first_usable_confirmed' "$ROUND_DIR"/node-*.log 2>/dev/null | head -6
  } >"$ROUND_DIR/evidence.log" 2>&1 || true

  # Per-daemon monotonic relay-ready -> usable delta: each daemon computes it
  # on its OWN clock and reports it in first_usable_confirmed; the harness only
  # SUMS the two ends' deltas, never subtracts wall clocks across machines.
  A_DELTA=$(node_first_usable_delta_ms "$ROUND_DIR/node-a.log")
  B_DELTA=$(node_first_usable_delta_ms "$ROUND_DIR/node-b.log")
  [[ -z "$A_DELTA" ]] && A_DELTA=0
  [[ -z "$B_DELTA" ]] && B_DELTA=0
  SUM_DELTA=$((A_DELTA + B_DELTA))
  DELTA_SUMS+=("$SUM_DELTA")
  A_INGRESS=$(node_first_usable_ingress "$ROUND_DIR/node-a.log")
  B_INGRESS=$(node_first_usable_ingress "$ROUND_DIR/node-b.log")
  A_RELAY_CONFIRMED=$(grep -c 'relay_peer_confirmed' "$ROUND_DIR/node-a.log" 2>/dev/null || echo 0)
  B_RELAY_CONFIRMED=$(grep -c 'relay_peer_confirmed' "$ROUND_DIR/node-b.log" 2>/dev/null || echo 0)
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
    #   - each daemon's OWN monotonic relay-ready -> usable delta <= 3000ms.
    a_relay_first=0
    b_relay_first=0
    [[ "$A_INGRESS" == relay:* ]] && a_relay_first=1
    [[ "$B_INGRESS" == relay:* ]] && b_relay_first=1
    if [[ "$overlay_ok" -eq 1 && "$A_DIRECT" -eq 0 && "$B_DIRECT" -eq 0 \
          && "$A_RELAY_CONFIRMED" -ge 1 && "$B_RELAY_CONFIRMED" -ge 1 \
          && "$a_relay_first" -eq 1 && "$b_relay_first" -eq 1 \
          && "$A_DELTA" -ge 0 && "$A_DELTA" -le 3000 \
          && "$B_DELTA" -ge 0 && "$B_DELTA" -le 3000 ]]; then
      echo "[nat-sim] ROUND $round: PASS relay_first_evidence overlay_ok=1 a_direct=$A_DIRECT b_direct=$B_DIRECT a_relay_confirmed=$A_RELAY_CONFIRMED b_relay_confirmed=$B_RELAY_CONFIRMED a_ingress=${A_INGRESS:-none} b_ingress=${B_INGRESS:-none} a_delta_ms=$A_DELTA b_delta_ms=$B_DELTA sum_delta_ms=$SUM_DELTA elapsed_ms=$ELAPSED_MS evidence=$ROUND_DIR/evidence.log"
    else
      echo "[nat-sim] ROUND $round: FAIL relay_first_evidence overlay_ok=$overlay_ok a_direct=$A_DIRECT b_direct=$B_DIRECT a_relay_confirmed=$A_RELAY_CONFIRMED b_relay_confirmed=$B_RELAY_CONFIRMED a_ingress=${A_INGRESS:-none} b_ingress=${B_INGRESS:-none} a_delta_ms=$A_DELTA b_delta_ms=$B_DELTA sum_delta_ms=$SUM_DELTA elapsed_ms=$ELAPSED_MS (strict relay-first evidence required: both RelayPeerConfirmed, ingress=relay:*, per-daemon delta <= 3000ms)"
      overall=1
    fi
  else
    # A single-sided Direct, unverified Direct payload, or relay-only round is
    # a failure.  The direct validation loop cannot use Relay in this mode.
    if [[ "$direct_ok" -eq 1 ]]; then
      echo "[nat-sim] ROUND $round: PASS both_direct a_delta_ms=$A_DELTA b_delta_ms=$B_DELTA sum_delta_ms=$SUM_DELTA a_ingress=${A_INGRESS:-none} b_ingress=${B_INGRESS:-none} elapsed_ms=$ELAPSED_MS (a_direct=$A_DIRECT b_direct=$B_DIRECT) a_overlay=$A_OVERLAY b_overlay=$B_OVERLAY evidence=$ROUND_DIR/evidence.log"
    else
      echo "[nat-sim] ROUND $round: NO-DIRECT a_direct=$A_DIRECT b_direct=$B_DIRECT a_delta_ms=$A_DELTA b_delta_ms=$B_DELTA sum_delta_ms=$SUM_DELTA elapsed_ms=$ELAPSED_MS (relay fallback expected)"
      overall=1
    fi
  fi

  # Also check for daemon crashes / socket leaks before tearing down.
  if ! kill -0 "$NODE_A_PID" 2>/dev/null || ! kill -0 "$NODE_B_PID" 2>/dev/null; then
    echo "[nat-sim] ROUND $round: FAIL (daemon exited unexpectedly)"
    overall=1
  fi

  kill "$NODE_A_PID" "$NODE_B_PID" "$RELAY_PID" "$SERVER_PID" "$NAT_PID" 2>/dev/null || true
  wait "$NODE_A_PID" "$NODE_B_PID" "$RELAY_PID" "$SERVER_PID" "$NAT_PID" 2>/dev/null || true
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
