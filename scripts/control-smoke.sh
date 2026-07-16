#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PORT=${PORT:-18080}
GO_BIN=${GO_BIN:-go}
TMP_DIR=$(mktemp -d /tmp/p2wlan-smoke.XXXXXX)

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  if [[ -n "${NODE_A_PID:-}" ]]; then kill "$NODE_A_PID" 2>/dev/null || true; fi
  if [[ -n "${NODE_B_PID:-}" ]]; then kill "$NODE_B_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

echo "[smoke] temp dir: $TMP_DIR"

(
  cd "$ROOT_DIR/server"
  PORT="$PORT" DB_PATH="$TMP_DIR/control.db" JWT_SECRET=smoke "$GO_BIN" run .
) >"$TMP_DIR/server.log" 2>&1 &
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

(
  cd "$ROOT_DIR"
  P2WLAN_DISABLE_TUN=1 RUST_LOG=info cargo run -p p2pnet-daemon -- \
    --config "$TMP_DIR/node-a.json" \
    --control "http://127.0.0.1:$PORT" \
    --network default \
    --token "$TOKEN" \
    --device-name node-a \
    --heartbeat-interval 5
) >"$TMP_DIR/node-a.log" 2>&1 &
NODE_A_PID=$!

for _ in {1..40}; do
  if grep -q 'Registered with control server! Virtual IP: 10.20.0.2' "$TMP_DIR/node-a.log" 2>/dev/null; then break; fi
  sleep 0.25
done

(
  cd "$ROOT_DIR"
  P2WLAN_DISABLE_TUN=1 RUST_LOG=info cargo run -p p2pnet-daemon -- \
    --config "$TMP_DIR/node-b.json" \
    --control "http://127.0.0.1:$PORT" \
    --network default \
    --token "$TOKEN" \
    --device-name node-b \
    --heartbeat-interval 5
) >"$TMP_DIR/node-b.log" 2>&1 &
NODE_B_PID=$!

for _ in {1..80}; do
  if grep -q 'Peer joined: node-' "$TMP_DIR/node-a.log" 2>/dev/null && \
     grep -q 'Peer joined: node-' "$TMP_DIR/node-b.log" 2>/dev/null && \
     grep -q 'Installed WireGuard .* session for node-' "$TMP_DIR/node-a.log" 2>/dev/null && \
     grep -q 'Installed WireGuard .* session for node-' "$TMP_DIR/node-b.log" 2>/dev/null; then
    echo "[smoke] PASS: both daemons registered, discovered peers, and installed WireGuard sessions"
    exit 0
  fi
  sleep 0.5
done

echo "[smoke] FAIL: peer discovery or WireGuard handshake did not complete" >&2
echo "--- server.log ---" >&2
tail -80 "$TMP_DIR/server.log" >&2 || true
echo "--- node-a.log ---" >&2
tail -120 "$TMP_DIR/node-a.log" >&2 || true
echo "--- node-b.log ---" >&2
tail -120 "$TMP_DIR/node-b.log" >&2 || true
exit 1
