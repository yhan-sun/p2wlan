#!/usr/bin/env bash
# Dual-end cold-start verification: fresh server DB, fresh daemon configs and
# fresh incarnation state for every round, local STUN responder, two daemons
# on loopback. Records the traversal outcome of each round.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ROUNDS=${ROUNDS:-5}
PORT=${PORT:-18080}
STUN_PORT=${STUN_PORT:-23478}
DIAG_A_PORT=${DIAG_A_PORT:-$((PORT + 101))}
DIAG_B_PORT=${DIAG_B_PORT:-$((PORT + 102))}

BASE_DIR=$(mktemp -d /tmp/p2wlan-dualend.XXXXXX)
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  pkill -f "$BASE_DIR" 2>/dev/null || true
  # rm -rf "$BASE_DIR"
}
trap cleanup EXIT

echo "[dual-end] building control server and daemon..."
(
  cd "$ROOT_DIR/server"
  go build -o "$BASE_DIR/control-server" .
)
cargo build -p p2wlan-daemon --manifest-path "$ROOT_DIR/client/daemon/Cargo.toml" >/dev/null

python3 "$ROOT_DIR/scripts/dual-end/stun_responder.py" 127.0.0.1 "$STUN_PORT" >"$BASE_DIR/stun.log" 2>&1 &
PIDS+=($!)

sleep 0.3

overall=0
for round in $(seq 1 "$ROUNDS"); do
  ROUND_DIR="$BASE_DIR/round-$round"
  mkdir -p "$ROUND_DIR"
  export PORT DB_PATH="$ROUND_DIR/control.db" JWT_SECRET=smoke
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
    echo "[dual-end] round $round: failed to parse auth token" >&2
    exit 1
  fi

  START_MS=$(python3 -c 'import time; print(int(time.time()*1000))')

  printf '%s\n' "$TOKEN" | P2WLAN_DISABLE_TUN=1 RUST_LOG=info "$ROOT_DIR/target/debug/p2wlan-daemon" \
    --config "$ROUND_DIR/node-a.json" \
    --control "http://127.0.0.1:$PORT" \
    --network default \
    --token-stdin \
    --device-name node-a \
    --udp-bind 127.0.0.1:0 \
    --stun "127.0.0.1:$STUN_PORT" \
    --diagnostics-bind 127.0.0.1:$DIAG_A_PORT \
    --heartbeat-interval 5 \
    >"$ROUND_DIR/node-a.log" 2>&1 &
  NODE_A_PID=$!
  PIDS+=($NODE_A_PID)

  for _ in {1..40}; do
    grep -q 'Control plane registration confirmed. Assigned IP: 10.20.0.2' "$ROUND_DIR/node-a.log" 2>/dev/null && break
    sleep 0.25
  done

  printf '%s\n' "$TOKEN" | P2WLAN_DISABLE_TUN=1 RUST_LOG=info "$ROOT_DIR/target/debug/p2wlan-daemon" \
    --config "$ROUND_DIR/node-b.json" \
    --control "http://127.0.0.1:$PORT" \
    --network default \
    --token-stdin \
    --device-name node-b \
    --udp-bind 127.0.0.1:0 \
    --stun "127.0.0.1:$STUN_PORT" \
    --diagnostics-bind 127.0.0.1:$DIAG_B_PORT \
    --heartbeat-interval 5 \
    >"$ROUND_DIR/node-b.log" 2>&1 &
  NODE_B_PID=$!
  PIDS+=($NODE_B_PID)

  # Wait for direct success: both sides transition the peer connection to
  # Direct (the promotion logs differ by code path — `direct_path_promoted`
  # or `candidate_pair_selected` — but the state transition is common).
  direct_ok=0
  for _ in {1..120}; do
    if grep -q '→ direct' "$ROUND_DIR/node-a.log" 2>/dev/null && \
       grep -q '→ direct' "$ROUND_DIR/node-b.log" 2>/dev/null; then
      direct_ok=1
      break
    fi
    sleep 0.5
  done
  END_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
  ELAPSED_MS=$((END_MS - START_MS))

  grep -h 'reason="received UDP punch ACK"' "$ROUND_DIR"/node-*.log 2>/dev/null | head -2 >"$ROUND_DIR/direct_ack.log" || true
  grep -h 'authenticated inbound punch observed' "$ROUND_DIR"/node-*.log 2>/dev/null | head -2 >"$ROUND_DIR/auth_punch_rx.log" || true
  grep -h 'peer_reflexive' "$ROUND_DIR"/node-*.log 2>/dev/null | head -4 >"$ROUND_DIR/peer_reflexive.log" || true
  grep -h 'relay' "$ROUND_DIR"/node-*.log 2>/dev/null | grep -i 'selected\|fallback' | head -2 >"$ROUND_DIR/relay.log" || true

  DIRECT_ACK=$(grep -hc 'reason="received UDP punch ACK"' "$ROUND_DIR"/node-*.log 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}' || true)
  AUTH_RX=$(grep -hc 'authenticated inbound punch observed' "$ROUND_DIR"/node-*.log 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}' || true)
  PRX=$(grep -hc 'peer_reflexive' "$ROUND_DIR"/node-*.log 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}' || true)
  PEER_REFLEXIVE_ENDPOINT=$(grep -h 'candidate_pair_probe_succeeded' "$ROUND_DIR"/node-*.log 2>/dev/null | grep -oE 'remote_endpoint=[0-9.:]+' | head -1 || true)

  if [[ "$direct_ok" -eq 1 ]]; then
    echo "[dual-end] ROUND $round: PASS direct_ack=$DIRECT_ACK auth_punch_rx=$AUTH_RX peer_reflexive_events=$PRX peer_reflexive_endpoint=${PEER_REFLEXIVE_ENDPOINT:-none} elapsed_ms=$ELAPSED_MS relay_fallback=none-needed"
  else
    echo "[dual-end] ROUND $round: NO-DIRECT elapsed_ms=$ELAPSED_MS (relay fallback expected)"
    overall=1
  fi
  # Tear down this round's daemons before the next round: leftover daemons
  # from a previous round keep the diagnostics ports busy and pollute the
  # next round's cold start.
  kill "$NODE_A_PID" "$NODE_B_PID" 2>/dev/null || true
  sleep 0.5
  kill "$SERVER_PID" 2>/dev/null || true
done

echo "[dual-end] base dir: $BASE_DIR"
exit $overall
