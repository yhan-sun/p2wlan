#!/usr/bin/env bash
# Pre-flight link health check for the Mini-Air cold-start harness.
#
# The Mini-Air round time tracks the lab link, not the daemon build (proven by
# interleaved A/B: baseline and current build show the same distribution at the
# same hour).  This script measures the channels the harness depends on and
# prints a verdict so mini-air-smoke.sh is only attempted on a healthy link:
#
#   - STUN reachability + RTT from BOTH ends (the daemons' profile/observation
#     phase): a single timeout or a slow tail pushes a round past 10s.
#   - SSH session establishment over FRP (the channel the harness uses to spawn
#     daemon B and collect its diagnostics).
#   - SSH over Tailscale (proxy for the Air -> Mini control/relay path).
#
# Exit codes:
#   0  HEALTHY  - all probes answered, latencies below thresholds.
#   1  DEGRADED - some probe timed out or a latency threshold was exceeded.
#   2  UNREACHABLE - SSH to the Air failed entirely.
#
# NOTE: bash 3.2 on macOS has no associative arrays; all aggregation is done
# with plain strings.

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
AIR_SSH_KEY=${AIR_SSH_KEY:-/Users/pyu/Desktop/codex_local_ed25519}
AIR_SSH_PORT=${AIR_SSH_PORT:-2300}
AIR_HOST=${AIR_HOST:-139.199.55.169}
AIR_TAILSCALE=${AIR_TAILSCALE:-100.74.65.1}
TAILSCALE_PORT=${TAILSCALE_PORT:-2222}
STUN_SERVERS=${STUN_SERVERS:-"stun.cloudflare.com:3478,stun.l.google.com:19302,stun.miwifi.com:3478"}
PROBES=${PROBES:-5}
# Thresholds (from the healthy-window evidence: 0 timeouts, FRP SSH ~0.6s,
# Tailscale SSH ~0.6-1s, STUN tail well under 250ms).
SSH_FRP_MAX_MS=${SSH_FRP_MAX_MS:-1500}
SSH_TS_MAX_MS=${SSH_TS_MAX_MS:-3000}
STUN_P95_MAX_MS=${STUN_P95_MAX_MS:-250}

AIR_SSH_BASE=(-i "$AIR_SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o BatchMode=yes)

measure_stun() {
  # $1 = "local" or "air". Emits lines: server_name rtt_ms  (rtt_ms = -1 on timeout)
  local target=$1
  local py='import socket, struct, time, os, sys
servers = sys.argv[1].split(",")
probes = int(sys.argv[2])
for srv in servers:
    name, _, port = srv.rpartition(":")
    for i in range(probes):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(6)
        msg = struct.pack(">HHI", 0x0001, 0, 0x2112A442) + os.urandom(12)
        t = time.time()
        try:
            s.sendto(msg, (name, int(port)))
            d, _ = s.recvfrom(1024)
            rtt = round((time.time() - t) * 1000)
            print(f"{name} {rtt}")
        except Exception:
            print(f"{name} -1")
        finally:
            s.close()
        time.sleep(0.15)
'
  if [[ "$target" == "local" ]]; then
    python3 -c "$py" "$STUN_SERVERS" "$PROBES"
  else
    ssh "${AIR_SSH_BASE[@]}" -p "$AIR_SSH_PORT" "pyu@$AIR_HOST" \
      "python3 -c $(printf '%q' "$py") $(printf '%q' "$STUN_SERVERS") $(printf '%q' "$PROBES")" 2>/dev/null
  fi
}

measure_ssh_ms() {
  # $1 = host, $2 = port. Prints connect round-trip ms or -1.
  local host=$1 port=$2
  local start end
  start=$(python3 -c 'import time; print(int(time.time()*1000))')
  if ssh "${AIR_SSH_BASE[@]}" -p "$port" "pyu@$host" 'true' >/dev/null 2>&1; then
    end=$(python3 -c 'import time; print(int(time.time()*1000))')
    echo $((end - start))
  else
    echo -1
  fi
}

RTT_LOCAL=""
RTT_AIR=""
TIMEOUTS_LOCAL=0
TIMEOUTS_AIR=0

echo "[link-health] STUN servers: $STUN_SERVERS (probes=$PROBES)"
echo "[link-health] measuring STUN from Mini (local)..."
while read -r name rtt; do
  echo "[link-health]   mini -> $name: ${rtt}ms"
  if [[ "$rtt" == "-1" ]]; then
    TIMEOUTS_LOCAL=$((TIMEOUTS_LOCAL + 1))
  else
    RTT_LOCAL="$RTT_LOCAL$rtt "
  fi
done < <(measure_stun local)

echo "[link-health] measuring STUN from Air ($AIR_HOST:$AIR_SSH_PORT)..."
AIR_STUN_OK=1
while read -r name rtt; do
  echo "[link-health]   air  -> $name: ${rtt}ms"
  if [[ "$rtt" == "-1" ]]; then
    TIMEOUTS_AIR=$((TIMEOUTS_AIR + 1))
  else
    RTT_AIR="$RTT_AIR$rtt "
  fi
done < <(measure_stun air) || AIR_STUN_OK=0
if [[ "$AIR_STUN_OK" -eq 0 ]]; then
  echo "[link-health] UNREACHABLE: could not run STUN measurement on the Air" >&2
  exit 2
fi

echo "[link-health] SSH session establishment..."
SSH_FRP_MS=$(measure_ssh_ms "$AIR_HOST" "$AIR_SSH_PORT")
echo "[link-health]   FRP      ($AIR_HOST:$AIR_SSH_PORT): ${SSH_FRP_MS}ms"
SSH_TS_MS=$(measure_ssh_ms "$AIR_TAILSCALE" "$TAILSCALE_PORT")
echo "[link-health]   Tailscale($AIR_TAILSCALE:$TAILSCALE_PORT): ${SSH_TS_MS}ms"

p95() {
  local vals=$1 sorted n idx
  if [[ -z "$vals" ]]; then echo -1; return; fi
  sorted=$(printf '%s\n' $vals | sort -n)
  n=$(printf '%s\n' $vals | wc -l | tr -d ' ')
  idx=$(( (n * 95) / 100 - 1 ))
  [[ $idx -lt 0 ]] && idx=0
  echo "$sorted" | sed -n "$((idx + 1))p"
}

P95_LOCAL=$(p95 "$RTT_LOCAL")
P95_AIR=$(p95 "$RTT_AIR")

echo "================ link health summary ================"
echo "STUN timeouts: mini=$TIMEOUTS_LOCAL air=$TIMEOUTS_AIR (out of $PROBES per server)"
echo "STUN p95 RTT: mini=${P95_LOCAL}ms air=${P95_AIR}ms"
echo "SSH FRP: ${SSH_FRP_MS}ms (max ${SSH_FRP_MAX_MS}ms)  SSH Tailscale: ${SSH_TS_MS}ms (max ${SSH_TS_MAX_MS}ms)"

FAIL_REASONS=""
add_reason() {
  FAIL_REASONS="${FAIL_REASONS}${1}"$'\n'
}
if [[ "$TIMEOUTS_LOCAL" -gt 0 || "$TIMEOUTS_AIR" -gt 0 ]]; then
  add_reason "STUN timeouts (mini=$TIMEOUTS_LOCAL air=$TIMEOUTS_AIR of ${PROBES}/server)"
fi
if [[ "$P95_LOCAL" != "-1" && "$P95_LOCAL" -gt "$STUN_P95_MAX_MS" ]]; then
  add_reason "mini STUN p95 ${P95_LOCAL}ms > ${STUN_P95_MAX_MS}ms"
fi
if [[ "$P95_AIR" != "-1" && "$P95_AIR" -gt "$STUN_P95_MAX_MS" ]]; then
  add_reason "air STUN p95 ${P95_AIR}ms > ${STUN_P95_MAX_MS}ms"
fi
if [[ "$SSH_FRP_MS" == "-1" || "$SSH_FRP_MS" -gt "$SSH_FRP_MAX_MS" ]]; then
  add_reason "FRP SSH ${SSH_FRP_MS}ms > ${SSH_FRP_MAX_MS}ms or unreachable"
fi
if [[ "$SSH_TS_MS" == "-1" || "$SSH_TS_MS" -gt "$SSH_TS_MAX_MS" ]]; then
  add_reason "Tailscale SSH ${SSH_TS_MS}ms > ${SSH_TS_MAX_MS}ms or unreachable"
fi

if [[ -z "$FAIL_REASONS" ]]; then
  echo "[link-health] VERDICT: HEALTHY"
  exit 0
else
  echo "[link-health] VERDICT: DEGRADED"
  printf '[link-health]   - %s\n' "$FAIL_REASONS"
  exit 1
fi
