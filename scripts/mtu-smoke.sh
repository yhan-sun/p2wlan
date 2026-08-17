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
TCP_PORT=${TCP_PORT:-${P2WLAN_MTU_TCP_PORT:-}}
UDP_PORT=${UDP_PORT:-${P2WLAN_MTU_UDP_PORT:-}}
TCP_SMALL_BYTES=${TCP_SMALL_BYTES:-4096}
TCP_LARGE_BYTES=${TCP_LARGE_BYTES:-1048576}
UDP_PAYLOADS=${UDP_PAYLOADS:-"1200 1320 1350 1392"}
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
  TCP_PORT=9000                optional TCP discard/echo listener on peer
  UDP_PORT=9001                optional UDP listener on peer
  TCP_SMALL_BYTES=4096
  TCP_LARGE_BYTES=1048576
  UDP_PAYLOADS="1200 1320 1350 1392"
  P2WLAN_REQUIRE_MTU_SMOKE=1  fail instead of skip when ping is unavailable

Optional peer-side listeners:
  nc -lk 9000 >/dev/null
  nc -u -lk 9001 >/dev/null
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

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

emit_status_mtu_summary() {
  local status_file=$1
  [[ -s "$status_file" ]] || return 0
  has_cmd python3 || return 0

  python3 - "$status_file" <<'PY'
import json
import sys

status_file = sys.argv[1]
try:
    with open(status_file, "r", encoding="utf-8") as handle:
        data = json.load(handle)
except Exception as exc:
    print(f"[mtu-smoke] WARN: unable to parse diagnostics MTU status: {exc}", file=sys.stderr)
    sys.exit(0)

mtu = data.get("mtu") or {}
if not isinstance(mtu, dict):
    sys.exit(0)

lines = []
configured = mtu.get("configured_mtu")
if configured is not None:
    lines.append(f"runtime_mtu={configured}")

relay_path = bool(mtu.get("relay_path_observed", False))
lines.append(f"relay_path_observed={1 if relay_path else 0}")

suggested = mtu.get("suggested_safe_mtu")
if suggested is not None:
    lines.append(f"mtu_suggested_safe={suggested}")

risks = mtu.get("risks") or []
if not isinstance(risks, list):
    risks = []
codes = []
for risk in risks:
    if not isinstance(risk, dict):
        continue
    code = risk.get("code")
    message = risk.get("message")
    if code:
        codes.append(str(code))
    if code and message:
        print(f"[mtu-smoke] WARN: diagnostics mtu risk {code}: {message}", file=sys.stderr)

lines.append(f"mtu_risk_codes={','.join(codes) if codes else 'none'}")
print("\n".join(lines))
PY
}

run_self_test() {
  if ! has_cmd python3; then
    echo "[mtu-smoke] self-test SKIP: python3 unavailable"
    return 0
  fi

  local tmp
  tmp=$(mktemp -d /tmp/p2wlan-mtu-smoke-self.XXXXXX)
  cat >"$tmp/status.json" <<'JSON'
{
  "mtu": {
    "configured_mtu": 1420,
    "relay_path_observed": true,
    "suggested_safe_mtu": 1380,
    "risks": [{
      "code": "relay_path_high_mtu",
      "message": "Relay path observed with MTU 1420; try lowering MTU."
    }]
  }
}
JSON

  local summary
  summary=$(emit_status_mtu_summary "$tmp/status.json")
  rm -rf "$tmp"
  [[ "$summary" == *"runtime_mtu=1420"* ]] || {
    echo "[mtu-smoke] self-test FAIL: missing runtime_mtu" >&2
    return 1
  }
  [[ "$summary" == *"relay_path_observed=1"* ]] || {
    echo "[mtu-smoke] self-test FAIL: missing relay_path_observed" >&2
    return 1
  }
  [[ "$summary" == *"mtu_suggested_safe=1380"* ]] || {
    echo "[mtu-smoke] self-test FAIL: missing mtu_suggested_safe" >&2
    return 1
  }
  [[ "$summary" == *"mtu_risk_codes=relay_path_high_mtu"* ]] || {
    echo "[mtu-smoke] self-test FAIL: missing risk code" >&2
    return 1
  }
  echo "[mtu-smoke] self-test PASS"
}

write_zero_payload() {
  local bytes=$1
  dd if=/dev/zero bs="$bytes" count=1 2>/dev/null
}

record_optional_failure() {
  echo "[mtu-smoke] FAIL: $*" >&2
  FAILURES=$((FAILURES + 1))
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

if [[ "${P2WLAN_MTU_SMOKE_SELF_TEST:-0}" == "1" ]]; then
  run_self_test
  exit $?
fi

if [[ "$PEER" == "-h" || "$PEER" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "$PEER" ]]; then
  usage
  exit 2
fi

require_cmd ping
source "$ROOT_DIR/scripts/diagnostics-auth.sh"
mkdir -p "$OUT_DIR"

P2WLAN_BIN=$(resolve_p2wlan_bin)
if [[ -n "$P2WLAN_BIN" && -x "$P2WLAN_BIN" ]]; then
  "$P2WLAN_BIN" doctor >"$OUT_DIR/doctor.txt" 2>"$OUT_DIR/doctor.err" || true
else
  echo "[mtu-smoke] p2wlan binary not found; skipped doctor" >"$OUT_DIR/doctor.txt"
fi

if command -v curl >/dev/null 2>&1; then
  p2wlan_diagnostics_curl -fsS "$DIAGNOSTICS_URL" -o "$OUT_DIR/status.json" 2>"$OUT_DIR/status.err" || true
fi
MTU_STATUS_SUMMARY=""
if [[ -s "$OUT_DIR/status.json" ]]; then
  MTU_STATUS_SUMMARY=$(emit_status_mtu_summary "$OUT_DIR/status.json" || true)
fi

echo "[mtu-smoke] peer: $PEER"
echo "[mtu-smoke] output: $OUT_DIR"
echo "[mtu-smoke] packet sizes: $MTUS"
if [[ -n "$MTU_STATUS_SUMMARY" ]]; then
  echo "[mtu-smoke] diagnostics mtu: $(printf '%s' "$MTU_STATUS_SUMMARY" | tr '\n' ' ')"
fi
if [[ -n "$TCP_PORT" ]]; then
  echo "[mtu-smoke] tcp payload test: $TCP_PORT small=$TCP_SMALL_BYTES large=$TCP_LARGE_BYTES"
else
  echo "[mtu-smoke] tcp payload test: skipped (set TCP_PORT)"
fi
if [[ -n "$UDP_PORT" ]]; then
  echo "[mtu-smoke] udp payload test: $UDP_PORT payloads=$UDP_PAYLOADS"
else
  echo "[mtu-smoke] udp payload test: skipped (set UDP_PORT)"
fi

read -r -a MTU_VALUES <<<"$MTUS"
OS_NAME=$(uname -s)
FAILURES=0
PASS_MAX=0
TCP_SMALL_RESULT=skip
TCP_LARGE_RESULT=skip
UDP_RESULT=skip

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

run_tcp_payload() {
  local label=$1
  local bytes=$2
  local log="$OUT_DIR/tcp-$label.log"

  if [[ -z "$TCP_PORT" ]]; then
    return 0
  fi
  if ! [[ "$TCP_PORT" =~ ^[0-9]+$ ]] || [[ "$TCP_PORT" -le 0 ]]; then
    echo "[mtu-smoke] invalid TCP_PORT: $TCP_PORT" >&2
    exit 2
  fi
  if ! [[ "$bytes" =~ ^[0-9]+$ ]] || [[ "$bytes" -le 0 ]]; then
    echo "[mtu-smoke] invalid TCP payload size: $bytes" >&2
    exit 2
  fi
  if ! has_cmd nc; then
    record_optional_failure "TCP payload test requested but nc is missing"
    return 1
  fi

  echo "[mtu-smoke] testing tcp_$label bytes=$bytes port=$TCP_PORT"
  if write_zero_payload "$bytes" | nc -w "$TIMEOUT" "$PEER" "$TCP_PORT" >"$log" 2>&1; then
    echo "[mtu-smoke] PASS tcp_$label bytes=$bytes"
    return 0
  fi

  record_optional_failure "tcp_$label bytes=$bytes failed (see $log)"
  return 1
}

run_udp_payloads() {
  local bytes
  local log
  local udp_failures=0

  if [[ -z "$UDP_PORT" ]]; then
    return 0
  fi
  if ! [[ "$UDP_PORT" =~ ^[0-9]+$ ]] || [[ "$UDP_PORT" -le 0 ]]; then
    echo "[mtu-smoke] invalid UDP_PORT: $UDP_PORT" >&2
    exit 2
  fi
  if ! has_cmd nc; then
    record_optional_failure "UDP payload test requested but nc is missing"
    return 1
  fi

  read -r -a UDP_PAYLOAD_VALUES <<<"$UDP_PAYLOADS"
  for bytes in "${UDP_PAYLOAD_VALUES[@]}"; do
    if ! [[ "$bytes" =~ ^[0-9]+$ ]] || [[ "$bytes" -le 0 ]]; then
      echo "[mtu-smoke] invalid UDP payload size: $bytes" >&2
      exit 2
    fi

    log="$OUT_DIR/udp-$bytes.log"
    echo "[mtu-smoke] testing udp_payload bytes=$bytes port=$UDP_PORT (send-only)"
    if write_zero_payload "$bytes" | nc -u -w "$TIMEOUT" "$PEER" "$UDP_PORT" >"$log" 2>&1; then
      echo "[mtu-smoke] PASS udp_payload bytes=$bytes"
    else
      record_optional_failure "udp_payload bytes=$bytes failed (see $log)"
      udp_failures=$((udp_failures + 1))
    fi
  done

  [[ "$udp_failures" -eq 0 ]]
}

if [[ -n "$TCP_PORT" ]]; then
  if run_tcp_payload small "$TCP_SMALL_BYTES"; then
    TCP_SMALL_RESULT=pass
  else
    TCP_SMALL_RESULT=fail
  fi
  if run_tcp_payload large "$TCP_LARGE_BYTES"; then
    TCP_LARGE_RESULT=pass
  else
    TCP_LARGE_RESULT=fail
  fi
fi

if [[ -n "$UDP_PORT" ]]; then
  if run_udp_payloads; then
    UDP_RESULT=pass
  else
    UDP_RESULT=fail
  fi
fi

{
  echo "peer=$PEER"
  echo "pass_max=$PASS_MAX"
  echo "failures=$FAILURES"
  echo "tcp_small=$TCP_SMALL_RESULT"
  echo "tcp_large=$TCP_LARGE_RESULT"
  echo "udp_payload=$UDP_RESULT"
  echo "out_dir=$OUT_DIR"
  if [[ -n "$MTU_STATUS_SUMMARY" ]]; then
    printf '%s\n' "$MTU_STATUS_SUMMARY"
  fi
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
