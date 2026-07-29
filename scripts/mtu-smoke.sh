#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

PEER=${1:-${PEER:-}}
DIAGNOSTICS_URL=${DIAGNOSTICS_URL:-http://127.0.0.1:39277/status}
P2WLAN_BIN=${P2WLAN_BIN:-}
OUT_DIR=${OUT_DIR:-$(mktemp -d /tmp/p2wlan-mtu-smoke.XXXXXX)}
MTUS=${MTUS:-"1280 1360 1380 1420 1500"}
COUNT=${COUNT:-3}
TIMEOUT=${TIMEOUT:-2}
REQUIRE=${P2WLAN_REQUIRE_MTU_SMOKE:-0}

usage() {
  cat >&2 <<'EOF'
usage: scripts/mtu-smoke.sh <peer-virtual-ip>

Environment:
  MTUS="1280 1360 1380 1420 1500"  IPv4 packet sizes to test
  DIAGNOSTICS_URL=http://127.0.0.1:39277/status
  OUT_DIR=/tmp/p2wlan-mtu-smoke.xxxxxx
  COUNT=3
  TIMEOUT=2
  P2WLAN_REQUIRE_MTU_SMOKE=1  fail instead of skip when ping is unavailable
EOF
}

skip() {
  echo "[mtu-smoke] SKIP: $*" >&2
  if [[ "$REQUIRE" == "1" ]]; then
    exit 1
  fi
  exit 0
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || skip "missing required command: $1"
}

resolve_p2wlan_bin() {
  if [[ -n "$P2WLAN_BIN" ]]; then
    printf '%s\n' "$P2WLAN_BIN"
    return
  fi
  if [[ -x "$ROOT_DIR/target/debug/p2wlan" ]]; then
    printf '%s\n' "$ROOT_DIR/target/debug/p2wlan"
    return
  fi
  if command -v p2wlan >/dev/null 2>&1; then
    command -v p2wlan
    return
  fi
  printf '\n'
}

if [[ "$PEER" == "-h" || "$PEER" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "$PEER" ]]; then
  usage
  exit 2
fi

require_cmd ping
mkdir -p "$OUT_DIR"

P2WLAN_BIN=$(resolve_p2wlan_bin)
if [[ -n "$P2WLAN_BIN" && -x "$P2WLAN_BIN" ]]; then
  "$P2WLAN_BIN" doctor >"$OUT_DIR/doctor.txt" 2>"$OUT_DIR/doctor.err" || true
else
  echo "[mtu-smoke] p2wlan binary not found; skipped doctor" >"$OUT_DIR/doctor.txt"
fi

if command -v curl >/dev/null 2>&1; then
  curl -fsS "$DIAGNOSTICS_URL" -o "$OUT_DIR/status.json" 2>"$OUT_DIR/status.err" || true
fi

echo "[mtu-smoke] peer: $PEER"
echo "[mtu-smoke] output: $OUT_DIR"
echo "[mtu-smoke] packet sizes: $MTUS"

read -r -a MTU_VALUES <<<"$MTUS"
OS_NAME=$(uname -s)
FAILURES=0
PASS_MAX=0

for mtu in "${MTU_VALUES[@]}"; do
  if ! [[ "$mtu" =~ ^[0-9]+$ ]] || [[ "$mtu" -le 28 ]]; then
    echo "[mtu-smoke] invalid MTU test size: $mtu" >&2
    exit 2
  fi

  payload=$((mtu - 28))
  log="$OUT_DIR/ping-$mtu.log"
  echo "[mtu-smoke] testing ipv4_packet=$mtu payload=$payload"

  if [[ "$OS_NAME" == "Linux" ]]; then
    if ping -M do -s "$payload" -c "$COUNT" -W "$TIMEOUT" "$PEER" >"$log" 2>&1; then
      echo "[mtu-smoke] PASS mtu=$mtu"
      PASS_MAX=$mtu
    else
      echo "[mtu-smoke] FAIL mtu=$mtu (see $log)"
      FAILURES=$((FAILURES + 1))
    fi
  elif [[ "$OS_NAME" == "Darwin" ]]; then
    if ping -D -s "$payload" -c "$COUNT" -W $((TIMEOUT * 1000)) "$PEER" >"$log" 2>&1; then
      echo "[mtu-smoke] PASS mtu=$mtu"
      PASS_MAX=$mtu
    else
      echo "[mtu-smoke] FAIL mtu=$mtu (see $log)"
      FAILURES=$((FAILURES + 1))
    fi
  else
    skip "unsupported OS for DF ping mode: $OS_NAME"
  fi
done

{
  echo "peer=$PEER"
  echo "pass_max=$PASS_MAX"
  echo "failures=$FAILURES"
  echo "out_dir=$OUT_DIR"
} >"$OUT_DIR/summary.env"

if [[ "$PASS_MAX" -eq 0 ]]; then
  echo "[mtu-smoke] FAIL: no tested packet size succeeded" >&2
  exit 1
fi

if [[ "$FAILURES" -gt 0 ]]; then
  echo "[mtu-smoke] WARN: largest passing packet size is $PASS_MAX; record this in docs/nat-traversal-matrix.*.md"
  exit 1
fi

echo "[mtu-smoke] PASS: all packet sizes succeeded; largest=$PASS_MAX"
