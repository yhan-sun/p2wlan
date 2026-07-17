#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

MODE=${1:-notun}
if [[ "$MODE" != "notun" && "$MODE" != "--notun" && "$MODE" != "tun" && "$MODE" != "--tun" ]]; then
  echo "usage: $0 [--notun|--tun]" >&2
  exit 2
fi
if [[ "$MODE" == "--notun" ]]; then MODE=notun; fi
if [[ "$MODE" == "--tun" ]]; then MODE=tun; fi

ALI_HOST=${ALI_HOST:-47.109.40.237}
ALI_KEY=${ALI_KEY:-"$HOME/.ssh/ali.pem"}
REMOTE_BASE=${REMOTE_BASE:-/tmp/p2wlan-remote-test}
STUN_SERVER=${STUN_SERVER:-74.125.250.129:19302}
PORT=${PORT:-$((19000 + $$ % 500))}
ALI_UDP=${ALI_UDP:-$((25000 + $$ % 500))}
MAC_UDP=${MAC_UDP:-$((ALI_UDP + 1))}
ALI_DIAG=${ALI_DIAG:-$((39200 + $$ % 300))}
MAC_DIAG=${MAC_DIAG:-$((ALI_DIAG + 1))}
TEST_ID="mac-${MODE}-$$"
REMOTE_RUN="$REMOTE_BASE/$TEST_ID"
LOCAL_RUN=${LOCAL_RUN:-$(mktemp -d /tmp/p2wlan-mac-${MODE}.XXXXXX)}
DAEMON_BIN=${DAEMON_BIN:-"$ROOT_DIR/target/debug/p2pnet-daemon"}
MAC_CONFIG="$LOCAL_RUN/mac.json"
ALI_CONFIG="$REMOTE_RUN/ali.json"
ALI_IF=${ALI_IF:-p2wmali}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[mac-smoke] missing required command: $1" >&2
    exit 1
  }
}

remote() {
  ssh -o BatchMode=yes -i "$ALI_KEY" "root@$ALI_HOST" "$@"
}

remote_cleanup() {
  remote "for p in \$(pgrep -f '^$REMOTE_BASE/' || true); do /bin/kill -9 \$p 2>/dev/null || true; done; ip route del 10.20.0.0/16 2>/dev/null || true; ip link del '$ALI_IF' 2>/dev/null || true" >/dev/null 2>&1 || true
}

cleanup() {
  if [[ -n "${MAC_PID:-}" ]]; then
    kill "$MAC_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$MAC_PID" 2>/dev/null || true
  fi
  remote_cleanup
  if [[ "$MODE" == "tun" ]]; then
    route -n delete -net 10.20.0.0 -netmask 255.255.0.0 >/dev/null 2>&1 || true
  fi
  rm -rf "$LOCAL_RUN"
}
trap cleanup EXIT

extract_top_virtual_ip() {
  sed -n 's/.*"virtual_ip": "\([0-9.]*\)".*/\1/p' | tail -1
}

wait_http() {
  local url=$1
  for _ in {1..50}; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

require_cmd curl
require_cmd ssh
require_cmd cargo
require_cmd ping

if [[ ! -x "$DAEMON_BIN" ]]; then
  echo "[mac-smoke] building local daemon..."
  (cd "$ROOT_DIR" && cargo build -p p2pnet-daemon)
fi

if [[ "$MODE" == "tun" && "$(uname -s)" != "Darwin" ]]; then
  echo "[mac-smoke] --tun mode is intended for macOS" >&2
  exit 1
fi
if [[ "$MODE" == "tun" && "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[mac-smoke] --tun mode must run as root: sudo -E $0 --tun" >&2
  exit 1
fi

echo "[mac-smoke] mode: $MODE"
echo "[mac-smoke] local run: $LOCAL_RUN"
echo "[mac-smoke] remote run: $REMOTE_RUN"

remote_cleanup
remote "mkdir -p '$REMOTE_RUN'; cd '$REMOTE_RUN'; env PORT=$PORT DB_PATH='$REMOTE_RUN/control.db' JWT_SECRET=smoke nohup '$REMOTE_BASE/control-server' >server.log 2>&1 & echo \$! >server.pid"
wait_http "http://$ALI_HOST:$PORT/health" || {
  echo "[mac-smoke] control server did not become healthy" >&2
  remote "tail -100 '$REMOTE_RUN/server.log' || true" >&2
  exit 1
}

REGISTER_JSON=$(curl -fsS -X POST "http://$ALI_HOST:$PORT/api/v1/register" \
  -H 'Content-Type: application/json' \
  -d '{"email":"mac-smoke@example.com","password":"passw0rd"}')
TOKEN=$(printf '%s' "$REGISTER_JSON" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$TOKEN" ]]; then
  echo "[mac-smoke] failed to parse auth token" >&2
  exit 1
fi

REMOTE_TUN_ENV=""
LOCAL_TUN_ENV=""
if [[ "$MODE" == "notun" ]]; then
  REMOTE_TUN_ENV="P2WLAN_DISABLE_TUN=1"
  LOCAL_TUN_ENV="P2WLAN_DISABLE_TUN=1"
fi

remote "cd '$REMOTE_RUN'; env $REMOTE_TUN_ENV RUST_LOG=info nohup '$REMOTE_BASE/p2pnet-daemon' \
  --config '$ALI_CONFIG' \
  --control 'http://$ALI_HOST:$PORT' \
  --network default \
  --token '$TOKEN' \
  --device-name ali-$MODE \
  --interface '$ALI_IF' \
  --udp-bind 0.0.0.0:$ALI_UDP \
  --udp-advertise '$ALI_HOST:$ALI_UDP' \
  --diagnostics-bind 127.0.0.1:$ALI_DIAG \
  --heartbeat-interval 5 \
  >ali.log 2>&1 & echo \$! >ali.pid"

env $LOCAL_TUN_ENV RUST_LOG=info "$DAEMON_BIN" \
  --config "$MAC_CONFIG" \
  --control "http://$ALI_HOST:$PORT" \
  --network default \
  --token "$TOKEN" \
  --device-name "mac-$MODE" \
  --udp-bind 0.0.0.0:$MAC_UDP \
  --stun "$STUN_SERVER" \
  --diagnostics-bind 127.0.0.1:$MAC_DIAG \
  --heartbeat-interval 5 \
  >"$LOCAL_RUN/mac.log" 2>&1 &
MAC_PID=$!

PASS_DIRECT=0
for _ in {1..120}; do
  MAC_STATUS=$("$DAEMON_BIN" --status --diagnostics-url "http://127.0.0.1:$MAC_DIAG/status" 2>/dev/null || true)
  ALI_STATUS=$(remote "'$REMOTE_BASE/p2pnet-daemon' --status --diagnostics-url http://127.0.0.1:$ALI_DIAG/status" 2>/dev/null || true)
  if printf '%s' "$MAC_STATUS" | grep -q '"state": "direct"' && \
     printf '%s' "$ALI_STATUS" | grep -q '"state": "direct"'; then
    PASS_DIRECT=1
    break
  fi
  sleep 1
done

echo "--- mac log ---"
grep -E 'Control plane registration confirmed|Prepared [0-9]+ UDP candidate endpoints|Sent WireGuard handshake initiation|Received peer offer|Received peer answer|Installed WireGuard|Sent [0-9]+ UDP punch probes|state:' "$LOCAL_RUN/mac.log" || true
echo "--- ali log ---"
remote "grep -E 'Control plane registration confirmed|Prepared [0-9]+ UDP candidate endpoints|Received peer offer|Received peer answer|Installed WireGuard|Sent [0-9]+ UDP punch probes|state:' '$REMOTE_RUN/ali.log' || true"
echo "--- mac status ---"
printf '%s\n' "$MAC_STATUS"
echo "--- ali status ---"
printf '%s\n' "$ALI_STATUS"

if [[ "$PASS_DIRECT" != "1" ]]; then
  echo "[mac-smoke] FAIL: direct path did not become healthy" >&2
  exit 1
fi

if [[ "$MODE" == "tun" ]]; then
  MAC_VIP=$(printf '%s' "$MAC_STATUS" | extract_top_virtual_ip)
  ALI_VIP=$(printf '%s' "$ALI_STATUS" | extract_top_virtual_ip)
  if [[ -z "$MAC_VIP" || -z "$ALI_VIP" || "$MAC_VIP" == "$ALI_VIP" ]]; then
    echo "[mac-smoke] FAIL: could not extract distinct VIPs (mac=$MAC_VIP ali=$ALI_VIP)" >&2
    exit 1
  fi

  echo "[mac-smoke] Mac VIP: $MAC_VIP"
  echo "[mac-smoke] Ali VIP: $ALI_VIP"
  ping -c 3 "$ALI_VIP"
  remote "ping -c 3 '$MAC_VIP'"
fi

echo "[mac-smoke] PASS: Mac $MODE smoke completed"
