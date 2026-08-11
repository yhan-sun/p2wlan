#!/usr/bin/env bash
# Deterministic dual-NAT cold-start verification: two independent NATs
# (address/port-dependent mapping, port-restricted filtering, configurable
# step/consumption/loss/reordering), 4+ independent STUN observers, relay
# safety net, two daemons with P2WLAN_DISABLE_TUN=1 behind the NATs.
#
# Every round is a completely cold start: fresh server DB, fresh daemon
# configs, fresh incarnation state, fresh NAT seeds.  A round PASSES only when
# BOTH sides reach Direct through the NATs (host candidates are never
# advertised, so the direct path must traverse the simulated NATs).
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# The standalone local control DB provisions only `default`; the real dual-end
# harness uses NETWORK_ID explicitly and requires a provisioned test network.
NETWORK_ID=${NETWORK_ID:-default}
NAT_SIM_RUST_LOG=${NAT_SIM_RUST_LOG:-info}
ROUNDS=${ROUNDS:-5}
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
BASE_A=${BASE_A:-36000}
BASE_B=${BASE_B:-46000}
DIRECT_TIMEOUT_S=${DIRECT_TIMEOUT_S:-60}

BASE_DIR=$(mktemp -d /tmp/p2wlan-natsim.XXXXXX)
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  echo "[nat-sim] artifacts retained: $BASE_DIR" >&2
}
trap cleanup EXIT

echo "[nat-sim] building control server, relay and daemon..."
echo "[nat-sim] isolated network id: $NETWORK_ID"
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
  NAT_SEED=$((20260806 + round))

  echo "[nat-sim] round $round: starting NAT simulator (step_a=$STEP_A step_b=$STEP_B consume_a=$CONSUME_A consume_b=$CONSUME_B loss=$LOSS reorder=$REORDER seed=$NAT_SEED)"
  REORDER_FLAG=""
  if [[ "$REORDER" == "1" ]]; then REORDER_FLAG="--reorder"; fi
  python3 "$ROOT_DIR/scripts/nat-sim/nat_sim.py" \
    --step-a "$STEP_A" --step-b "$STEP_B" \
    --consume-a "$CONSUME_A" --consume-b "$CONSUME_B" \
    --loss "$LOSS" $REORDER_FLAG \
    --seed "$NAT_SEED" --base-a "$BASE_A" --base-b "$BASE_B" \
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
    >"$ROUND_DIR/node-b.log" 2>&1 &
  NODE_B_PID=$!
  PIDS+=($NODE_B_PID)

  # Wait for BOTH sides to enter Direct through the NATs.
  direct_ok=0
  for _ in $(seq 1 $((DIRECT_TIMEOUT_S * 2))); do
    if grep -q '→ direct' "$ROUND_DIR/node-a.log" 2>/dev/null && \
       grep -q '→ direct' "$ROUND_DIR/node-b.log" 2>/dev/null; then
      direct_ok=1
      break
    fi
    sleep 0.5
  done
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
  } >"$ROUND_DIR/evidence.log" 2>&1 || true

  # A single-sided Direct or a relay-only round is a failure.
  if [[ "$direct_ok" -eq 1 ]]; then
    A_DIRECT=$(grep -c '→ direct' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
    B_DIRECT=$(grep -c '→ direct' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
    echo "[nat-sim] ROUND $round: PASS both_direct elapsed_ms=$ELAPSED_MS (a_direct=$A_DIRECT b_direct=$B_DIRECT) evidence=$ROUND_DIR/evidence.log"
  else
    A_DIRECT=$(grep -c '→ direct' "$ROUND_DIR/node-a.log" 2>/dev/null || true)
    B_DIRECT=$(grep -c '→ direct' "$ROUND_DIR/node-b.log" 2>/dev/null || true)
    echo "[nat-sim] ROUND $round: NO-DIRECT a_direct=$A_DIRECT b_direct=$B_DIRECT elapsed_ms=$ELAPSED_MS (relay fallback expected)"
    overall=1
  fi

  # Also check for daemon crashes / socket leaks before tearing down.
  if ! kill -0 "$NODE_A_PID" 2>/dev/null || ! kill -0 "$NODE_B_PID" 2>/dev/null; then
    echo "[nat-sim] ROUND $round: FAIL (daemon exited unexpectedly)"
    overall=1
  fi

  kill "$NODE_A_PID" "$NODE_B_PID" "$RELAY_PID" "$SERVER_PID" "$NAT_PID" 2>/dev/null || true
  PIDS=()
  sleep 0.5
done

echo "[nat-sim] base dir: $BASE_DIR"
echo "[nat-sim] RESULT: $([ "$overall" -eq 0 ] && echo PASS || echo FAIL)"
exit $overall
