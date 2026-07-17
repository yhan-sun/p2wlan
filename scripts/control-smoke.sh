#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PORT=${PORT:-18080}
DIAG_A_PORT=${DIAG_A_PORT:-$((PORT + 101))}
DIAG_B_PORT=${DIAG_B_PORT:-$((PORT + 102))}
GO_BIN=${GO_BIN:-go}
TMP_DIR=$(mktemp -d /tmp/p2wlan-smoke.XXXXXX)

cleanup() {
  if [[ -n "${NODE_A_PID:-}" ]]; then
    pkill -P "$NODE_A_PID" 2>/dev/null || true
    kill "$NODE_A_PID" 2>/dev/null || true
  fi
  if [[ -n "${NODE_B_PID:-}" ]]; then
    pkill -P "$NODE_B_PID" 2>/dev/null || true
    kill "$NODE_B_PID" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID:-}" ]]; then
    pkill -P "$SERVER_PID" 2>/dev/null || true
    kill "$SERVER_PID" 2>/dev/null || true
  fi
  pkill -f "$TMP_DIR" 2>/dev/null || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "[smoke] temp dir: $TMP_DIR"

echo "[smoke] building control server..."
(
  cd "$ROOT_DIR/server"
  "$GO_BIN" build -o "$TMP_DIR/control-server" .
)

echo "[smoke] building p2pnet-daemon..."
(
  cd "$ROOT_DIR"
  cargo build -p p2pnet-daemon
)

PORT="$PORT" DB_PATH="$TMP_DIR/control.db" JWT_SECRET=smoke "$TMP_DIR/control-server" >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

for _ in {1..40}; do
  if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then break; fi
  sleep 0.25
done

curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null

REGISTER_JSON=$(curl -fsS -X POST "http://127.0.0.1:$PORT/api/v1/register" \
  -H 'Content-Type: application/json' \
  -d '{"email":"smoke@example.com","password":"passw0rd"}')
TOKEN=$(printf '%s' "$REGISTER_JSON" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

if [[ -z "$TOKEN" ]]; then
  echo "[smoke] failed to parse auth token" >&2
  exit 1
fi

P2WLAN_DISABLE_TUN=1 RUST_LOG=info "$ROOT_DIR/target/debug/p2pnet-daemon" \
  --config "$TMP_DIR/node-a.json" \
  --control "http://127.0.0.1:$PORT" \
  --network default \
  --token "$TOKEN" \
  --device-name node-a \
  --udp-bind 127.0.0.1:0 \
  --diagnostics-bind 127.0.0.1:$DIAG_A_PORT \
  --heartbeat-interval 5 \
  >"$TMP_DIR/node-a.log" 2>&1 &
NODE_A_PID=$!

for _ in {1..40}; do
  if grep -q 'Registered with control server! Virtual IP: 10.20.0.2' "$TMP_DIR/node-a.log" 2>/dev/null; then break; fi
  sleep 0.25
done

P2WLAN_DISABLE_TUN=1 RUST_LOG=info "$ROOT_DIR/target/debug/p2pnet-daemon" \
  --config "$TMP_DIR/node-b.json" \
  --control "http://127.0.0.1:$PORT" \
  --network default \
  --token "$TOKEN" \
  --device-name node-b \
  --udp-bind 127.0.0.1:0 \
  --diagnostics-bind 127.0.0.1:$DIAG_B_PORT \
  --heartbeat-interval 5 \
  >"$TMP_DIR/node-b.log" 2>&1 &
NODE_B_PID=$!

for _ in {1..80}; do
  if grep -q 'Peer joined: node-' "$TMP_DIR/node-a.log" 2>/dev/null && \
     grep -q 'Peer joined: node-' "$TMP_DIR/node-b.log" 2>/dev/null && \
     grep -q 'Installed WireGuard .* session for node-' "$TMP_DIR/node-a.log" 2>/dev/null && \
     grep -q 'Installed WireGuard .* session for node-' "$TMP_DIR/node-b.log" 2>/dev/null && \
     grep -Eq 'Prepared [1-9][0-9]* UDP candidate endpoints' "$TMP_DIR/node-a.log" 2>/dev/null && \
     grep -Eq 'Prepared [1-9][0-9]* UDP candidate endpoints' "$TMP_DIR/node-b.log" 2>/dev/null && \
     grep -Eq 'Sent [1-9][0-9]* UDP punch probes to peer' "$TMP_DIR/node-a.log" 2>/dev/null && \
     grep -Eq 'Sent [1-9][0-9]* UDP punch probes to peer' "$TMP_DIR/node-b.log" 2>/dev/null; then
    STATUS_A=$(curl -fsS "http://127.0.0.1:$DIAG_A_PORT/status" 2>/dev/null || true)
    STATUS_B=$(curl -fsS "http://127.0.0.1:$DIAG_B_PORT/status" 2>/dev/null || true)
    if printf '%s' "$STATUS_A" | grep -q '"peers"' && \
       printf '%s' "$STATUS_A" | grep -q '"stats"' && \
       printf '%s' "$STATUS_A" | grep -q '"relay_selection"' && \
       printf '%s' "$STATUS_B" | grep -q '"peers"' && \
       printf '%s' "$STATUS_B" | grep -q '"stats"' && \
       printf '%s' "$STATUS_B" | grep -q '"relay_selection"'; then
      "$ROOT_DIR/target/debug/p2pnet-daemon" \
        --status \
        --diagnostics-url "http://127.0.0.1:$DIAG_A_PORT/status" \
        >"$TMP_DIR/status-cli.json" 2>"$TMP_DIR/status-cli.log" || true
      if grep -q '"node_id"' "$TMP_DIR/status-cli.json" && \
         grep -q '"peers"' "$TMP_DIR/status-cli.json" && \
         grep -q '"relay_selection"' "$TMP_DIR/status-cli.json"; then
        echo "[smoke] PASS: both daemons registered, discovered peers, installed WireGuard sessions, probed UDP candidates, and served diagnostics"
        exit 0
      fi
    fi
  fi
  sleep 0.5
done

echo "[smoke] FAIL: peer discovery, WireGuard handshake, candidate gathering, UDP probing, or diagnostics did not complete" >&2
echo "--- server.log ---" >&2
tail -80 "$TMP_DIR/server.log" >&2 || true
echo "--- node-a.log ---" >&2
tail -120 "$TMP_DIR/node-a.log" >&2 || true
echo "--- node-b.log ---" >&2
tail -120 "$TMP_DIR/node-b.log" >&2 || true
echo "--- status-cli.log ---" >&2
tail -80 "$TMP_DIR/status-cli.log" >&2 || true
echo "--- status-cli.json ---" >&2
tail -80 "$TMP_DIR/status-cli.json" >&2 || true
exit 1
