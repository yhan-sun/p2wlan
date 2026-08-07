#!/usr/bin/env bash
# Real Mini <-> Air dual-end cold-start verification.
#
# Topology:
#   Mini (this machine, macOS M4)  --daemon A-->  real NAT A
#   Air  (tailscale.example.com via SSH, macOS arm64) --daemon B-->  real NAT B
#
# The control server, relay and the daemon-A side run on the Mini; daemon B
# runs on the Air over SSH.  The two machines connect through their REAL
# public NATs: STUN servers are public, the peer candidates are the real
# public endpoints, and Direct must be confirmed by both sides within the
# deadline (target <= 15s, allowance for cold relay handshake included).
#
# The 100.x Tailscale address is used ONLY for control/relay management
# traffic; the Direct data path must show a public IPv4 endpoint.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ROUNDS=${ROUNDS:-5}
PORT=${PORT:-18080}
RELAY_PORT=${RELAY_PORT:-18081}
DIAG_A_PORT=${DIAG_A_PORT:-18101}
DIAG_B_PORT=${DIAG_B_PORT:-18102}
AIR_HOST=${AIR_HOST:-tailscale.example.com}
AIR_USER=${AIR_USER:-pyu}
# The lab's Mini-Air SSH service listens on port 2222. Keep the environment
# override for setups that deliberately use a different port.
AIR_SSH_PORT=${AIR_SSH_PORT:-2222}
AIR_SSH_KEY=${AIR_SSH_KEY:-/Users/pyu/Desktop/codex_local_ed25519}
# Set this to an executable already present on the Air to skip the binary
# upload. The harness never overwrites a pre-positioned binary; it only adds
# the owner execute bit when needed. This is useful on constrained SSH links.
AIR_DAEMON_BIN=${AIR_DAEMON_BIN:-}
REMOTE_DAEMON_BIN=${AIR_DAEMON_BIN:-/tmp/p2wlan-miniair/p2wlan-daemon}
MINI_TAILSCALE_IP=$(tailscale ip -4 2>/dev/null | head -1 || echo "100.84.190.40")
DIRECT_TIMEOUT_S=${DIRECT_TIMEOUT_S:-90}
STUN_SERVERS=${STUN_SERVERS:-"stun.cloudflare.com:3478,stun.l.google.com:19302,stun.miwifi.com:3478"}

AIR_SSH="ssh -i $AIR_SSH_KEY -p $AIR_SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 $AIR_USER@$AIR_HOST"
AIR_SCP="scp -O -i $AIR_SSH_KEY -P $AIR_SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

BASE_DIR=$(mktemp -d /tmp/p2wlan-miniair.XXXXXX)
PIDS=()
REMOTE_NODE_B_PID_FILE=""
# Do not inherit an ambient application-level RUST_LOG (often `warn`) here:
# this harness needs Info promotion telemetry in both logs. Callers that need
# a different filter can override the harness-specific variable explicitly.
HARNESS_RUST_LOG=${HARNESS_RUST_LOG:-info,p2pnet_daemon::network_outbound=debug}

count_log_events() {
  local log_file=$1
  local pattern=$2
  grep -E -c -- "$pattern" "$log_file" 2>/dev/null || true
}

count_log_events_insensitive() {
  local log_file=$1
  local pattern=$2
  grep -E -i -c -- "$pattern" "$log_file" 2>/dev/null || true
}

sha256_file() {
  local file=$1
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    echo "[mini-air] neither shasum nor sha256sum is available locally" >&2
    return 1
  fi
}

# Direct-validation lifecycle stages are retained in the diagnostics snapshot
# and emitted as structured tracing events.  The snapshot is a bounded ring,
# so prefer the durable log count and fall back to the snapshot when a caller
# uses a filter that suppresses those events.
count_status_stage() {
  local status_file=$1
  local stage=$2
  python3 - "$status_file" "$stage" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        status = json.load(stream)
except (OSError, ValueError):
    print(0)
    raise SystemExit

stage = sys.argv[2]
events = []
for peer in status.get("peers", []):
    events.extend(peer.get("direct_events", []))
print(sum(1 for event in events if event.get("stage") == stage))
PY
}

count_stage() {
  local status_file=$1
  local log_file=$2
  local stage=$3
  local log_count
  local status_count
  log_count=$(count_log_events "$log_file" "event=\\\"$stage\\\"|$stage")
  status_count=$(count_status_stage "$status_file" "$stage")
  if [[ "$log_count" -gt 0 ]]; then
    printf '%s\n' "$log_count"
  else
    printf '%s\n' "$status_count"
  fi
}

# The Direct state is authoritative in diagnostics. Log lines are retained as
# evidence and for endpoint extraction, but an ambient filtering change must
# never turn a real Direct path into a harness timeout.
status_reports_direct() {
  local status_url=$1
  curl -fsS --max-time 5 "$status_url" | python3 -c '
import json
import sys

try:
    status = json.load(sys.stdin)
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if any(peer.get("state") == "direct" for peer in status.get("peers", [])) else 1)
'
}

remote_status_reports_direct() {
  $AIR_SSH "curl -fsS --max-time 5 http://127.0.0.1:$DIAG_B_PORT/status | python3 -c 'import json,sys; status=json.load(sys.stdin); raise SystemExit(0 if any(peer.get(\"state\") == \"direct\" for peer in status.get(\"peers\", [])) else 1)'"
}

direct_endpoint_from_log() {
  local log_file=$1
  grep -E 'direct_path_promoted|candidate_pair_selected' "$log_file" 2>/dev/null \
    | grep -oE 'remote_endpoint=[0-9.]+:[0-9]+' \
    | sed 's/^remote_endpoint=//' \
    | tail -1 || true
}

is_public_ipv4_endpoint() {
  local endpoint=$1
  local ip=${endpoint%:*}
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  case "$ip" in
    ''|0.*|10.*|100.*|127.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*|255.*)
      return 1
      ;;
  esac
  return 0
}

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  if [[ -n "$REMOTE_NODE_B_PID_FILE" ]]; then
    # The PID file is written by the remote shell immediately before it execs
    # the daemon. Verify both the numeric PID and its command before signalling
    # it so an interrupted run cannot kill an unrelated Air process.
    $AIR_SSH "pid_file='$REMOTE_NODE_B_PID_FILE'; if [ -r \"\$pid_file\" ]; then pid=\$(cat \"\$pid_file\"); case \"\$pid\" in ''|*[!0-9]*) ;; *) if ps -p \"\$pid\" -o command= 2>/dev/null | grep -F -- '$REMOTE_DAEMON_BIN' >/dev/null; then kill \"\$pid\" 2>/dev/null || true; fi ;; esac; fi" >/dev/null 2>&1 || true
  fi
  pkill -f "$BASE_DIR" 2>/dev/null || true
  echo "[mini-air] artifacts retained: $BASE_DIR" >&2
}
trap cleanup EXIT

echo "[mini-air] building control server, relay and daemon (release)..."
(
  cd "$ROOT_DIR/server"
  go build -o "$BASE_DIR/control-server" .
  go build -o "$BASE_DIR/relay-server" ./relay
)
cargo build --release -p p2wlan-daemon --manifest-path "$ROOT_DIR/client/daemon/Cargo.toml" >/dev/null
DAEMON_BIN="$ROOT_DIR/target/release/p2wlan-daemon"
LOCAL_DAEMON_SHA256=$(sha256_file "$DAEMON_BIN")

echo "[mini-air] Air reachability check..."
$AIR_SSH 'uname -m' | tail -1
echo "[mini-air] Air public IPv4: $($AIR_SSH 'curl -s --max-time 8 ifconfig.me || true' | tail -1)"
echo "[mini-air] Mini public IPv4: $(curl -s4 --max-time 8 ifconfig.me || true)"

# One relay keypair for the whole run. The helper uses only Go's standard
# library, so the harness is portable to hosts without Python cryptography.
read -r RELAY_SEED RELAY_PUB < <(go run "$ROOT_DIR/scripts/relay_keygen.go")

# Copy the binary to the Air once unless the caller supplied an already
# transferred executable. On constrained SSH links this avoids a redundant
# multi-megabyte transfer; the supplied file is never overwritten.
if [[ -n "$AIR_DAEMON_BIN" ]]; then
  echo "[mini-air] using pre-positioned Air daemon: $REMOTE_DAEMON_BIN"
  $AIR_SSH "test -f '$REMOTE_DAEMON_BIN' && chmod u+x '$REMOTE_DAEMON_BIN' && file '$REMOTE_DAEMON_BIN' && '$REMOTE_DAEMON_BIN' --version"
else
  $AIR_SSH 'mkdir -p /tmp/p2wlan-miniair'
  $AIR_SSH "cat > '$REMOTE_DAEMON_BIN'" < "$DAEMON_BIN"
  $AIR_SSH "chmod +x '$REMOTE_DAEMON_BIN' && ls -la '$REMOTE_DAEMON_BIN'"
fi

# A matching semantic version is not enough here: a user can correctly upload
# an older 0.1.107 build after the source tree has changed.  Refuse to run a
# two-ended smoke test unless the Air executes the exact local release binary.
REMOTE_DAEMON_SHA256=$($AIR_SSH "if command -v shasum >/dev/null 2>&1; then shasum -a 256 '$REMOTE_DAEMON_BIN' | awk '{print \$1}'; elif command -v sha256sum >/dev/null 2>&1; then sha256sum '$REMOTE_DAEMON_BIN' | awk '{print \$1}'; else exit 127; fi")
if [[ "$REMOTE_DAEMON_SHA256" != "$LOCAL_DAEMON_SHA256" ]]; then
  echo "[mini-air] Air daemon SHA-256 mismatch; refusing to start smoke daemons." >&2
  echo "[mini-air] local release:  $DAEMON_BIN ($LOCAL_DAEMON_SHA256)" >&2
  echo "[mini-air] Air binary:     $REMOTE_DAEMON_BIN (${REMOTE_DAEMON_SHA256:-unavailable})" >&2
  echo "[mini-air] Upload the exact local release binary to AIR_DAEMON_BIN, then rerun." >&2
  exit 1
fi
echo "[mini-air] Air daemon SHA-256 verified: $LOCAL_DAEMON_SHA256"

overall=0
printf 'round\telapsed_ms\ta_direct\tb_direct\ta_endpoint\tb_endpoint\ta_validation_sessions\tb_validation_sessions\ta_validation_requests\tb_validation_requests\ta_validation_acks\tb_validation_acks\ta_matched_acks\tb_matched_acks\ta_http_429\tb_http_429\ta_relay_hedges\tb_relay_hedges\ta_relay_fallbacks\tb_relay_fallbacks\ta_relay_selections\tb_relay_selections\n' >"$BASE_DIR/round-metrics.tsv"
for round in $(seq 1 "$ROUNDS"); do
  ROUND_DIR="$BASE_DIR/round-$round"
  mkdir -p "$ROUND_DIR"

  # Relay + control server on the Mini, reachable by the Air via Tailscale.
  KEYRING_JSON="{\"relay-sim\":\"$RELAY_PUB\"}"
  RELAY_AUDIENCE="relay-sim" RELAY_REGION="local" "$BASE_DIR/relay-server" -bind "0.0.0.0:$RELAY_PORT" \
    -ticket-keyring "$KEYRING_JSON" -require-auth -allow-insecure-plaintext \
    >"$ROUND_DIR/relay.log" 2>&1 &
  RELAY_PID=$!
  PIDS+=($RELAY_PID)
  export PORT DB_PATH="$ROUND_DIR/control.db" JWT_SECRET=smoke \
    RELAY_TICKET_SIGNER_JSON="{\"active\":{\"kid\":\"relay-sim\",\"private_key\":\"$RELAY_SEED\"}}" \
    RELAY_CATALOG_JSON="[{\"region\":\"local\",\"audience\":\"relay-sim\",\"endpoint\":\"tcp://$MINI_TAILSCALE_IP:$RELAY_PORT\"}]"
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
    echo "[mini-air] round $round: failed to parse auth token" >&2
    exit 1
  fi

  START_MS=$(python3 -c 'import time; print(int(time.time()*1000))')

  # Daemon A on the Mini.
  P2WLAN_DISABLE_TUN=1 RUST_LOG="$HARNESS_RUST_LOG" "$DAEMON_BIN" \
    --config "$ROUND_DIR/node-a.json" \
    --control "http://127.0.0.1:$PORT" \
    --network default \
    --token "$TOKEN" \
    --device-name mini-a \
    --udp-bind 0.0.0.0:0 \
    --stun "$STUN_SERVERS" \
    --stun-timeout-ms 1000 \
    --diagnostics-bind 127.0.0.1:$DIAG_A_PORT \
    --heartbeat-interval 5 \
    >"$ROUND_DIR/node-a.log" 2>&1 &
  NODE_A_PID=$!
  PIDS+=($NODE_A_PID)

  for _ in {1..60}; do
    grep -q 'Control plane registration confirmed' "$ROUND_DIR/node-a.log" 2>/dev/null && break
    sleep 0.25
  done

  # Daemon B on the Air (fresh config every round).
  AIR_CONFIG="/tmp/p2wlan-miniair/node-b-round-$round.json"
  REMOTE_NODE_B_PID_FILE="/tmp/p2wlan-miniair/node-b-round-$round.pid"
  # The daemon runs in the FOREGROUND of the remote session; the LOCAL ssh is
  # backgrounded and held, so the daemon can never be SIGHUP'd by a session
  # teardown race. NODE_B_PID is the local ssh pid: it stays alive exactly
  # while the remote daemon runs; the remote daemon has its own verified PID
  # file for precise teardown.
  $AIR_SSH "echo \$\$ > $REMOTE_NODE_B_PID_FILE; exec env P2WLAN_DISABLE_TUN=1 RUST_LOG='$HARNESS_RUST_LOG' '$REMOTE_DAEMON_BIN' \
    --config $AIR_CONFIG \
    --control http://$MINI_TAILSCALE_IP:$PORT \
    --network default \
    --token $TOKEN \
    --device-name air-b \
    --udp-bind 0.0.0.0:0 \
    --stun '$STUN_SERVERS' \
    --stun-timeout-ms 1000 \
    --diagnostics-bind 127.0.0.1:$DIAG_B_PORT \
    --heartbeat-interval 5 \
    </dev/null >/tmp/p2wlan-miniair/node-b-round-$round.log 2>&1" >/dev/null 2>&1 &
  NODE_B_PID=$!
  PIDS+=($NODE_B_PID)
  echo "$NODE_B_PID" >"$ROUND_DIR/node-b.pid"
  # The daemon must actually be up before the Direct wait begins (a fresh
  # config is generated on first start, which takes a beat).
  sleep 3

  # Wait for BOTH sides to enter Direct. Diagnostics is the authority; logs
  # are deliberately not used as a state predicate because trace filtering is
  # configurable in real deployments.
  direct_ok=0
  for _ in $(seq 1 $((DIRECT_TIMEOUT_S * 2))); do
    if status_reports_direct "http://127.0.0.1:$DIAG_A_PORT/status" && \
       remote_status_reports_direct; then
      direct_ok=1
      break
    fi
    sleep 0.5
  done
  END_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
  ELAPSED_MS=$((END_MS - START_MS))

  # Preserve the complete Air log beside the Mini log before teardown.  A
  # failed remote copy is itself test evidence; do not silently collapse a
  # two-ended failure into a single-sided PASS/FAIL line.
  if ! $AIR_SSH "cat /tmp/p2wlan-miniair/node-b-round-$round.log" >"$ROUND_DIR/node-b.log"; then
    echo "[mini-air] ROUND $round: FAIL (could not collect complete Air daemon log)" >&2
    : >"$ROUND_DIR/node-b.log"
    overall=1
  fi

  # Capture diagnostics before teardown.  The Air endpoint is loopback-local
  # to the remote daemon, so fetch it over the existing SSH session.
  if ! curl -fsS --max-time 5 "http://127.0.0.1:$DIAG_A_PORT/status" >"$ROUND_DIR/node-a.status.json"; then
    printf '{}\n' >"$ROUND_DIR/node-a.status.json"
    echo "[mini-air] round $round: could not collect Mini diagnostics snapshot" >&2
  fi
  if ! $AIR_SSH "curl -fsS --max-time 5 http://127.0.0.1:$DIAG_B_PORT/status" >"$ROUND_DIR/node-b.status.json"; then
    printf '{}\n' >"$ROUND_DIR/node-b.status.json"
    echo "[mini-air] round $round: could not collect Air diagnostics snapshot" >&2
  fi

  A_DIRECT=$(count_log_events "$ROUND_DIR/node-a.log" '→ direct')
  B_DIRECT=$(count_log_events "$ROUND_DIR/node-b.log" '→ direct')
  A_EP=$(direct_endpoint_from_log "$ROUND_DIR/node-a.log")
  B_EP=$(direct_endpoint_from_log "$ROUND_DIR/node-b.log")
  A_VALIDATION_SESSIONS=$(count_stage "$ROUND_DIR/node-a.status.json" "$ROUND_DIR/node-a.log" 'encrypted_trial_started')
  B_VALIDATION_SESSIONS=$(count_stage "$ROUND_DIR/node-b.status.json" "$ROUND_DIR/node-b.log" 'encrypted_trial_started')
  A_VALIDATION_REQUESTS=$(count_stage "$ROUND_DIR/node-a.status.json" "$ROUND_DIR/node-a.log" 'direct_validation_request_sent')
  B_VALIDATION_REQUESTS=$(count_stage "$ROUND_DIR/node-b.status.json" "$ROUND_DIR/node-b.log" 'direct_validation_request_sent')
  A_VALIDATION_ACKS=$(count_stage "$ROUND_DIR/node-a.status.json" "$ROUND_DIR/node-a.log" 'direct_validation_ack_received')
  B_VALIDATION_ACKS=$(count_stage "$ROUND_DIR/node-b.status.json" "$ROUND_DIR/node-b.log" 'direct_validation_ack_received')
  A_MATCHED_ACKS=$(count_log_events "$ROUND_DIR/node-a.log" 'candidate_pair_probe_succeeded|received authenticated UDP punch ACK|received UDP punch ACK')
  B_MATCHED_ACKS=$(count_log_events "$ROUND_DIR/node-b.log" 'candidate_pair_probe_succeeded|received authenticated UDP punch ACK|received UDP punch ACK')
  A_HTTP_429=$(count_log_events "$ROUND_DIR/node-a.log" 'HTTP 429|status.?429|429 Too Many')
  B_HTTP_429=$(count_log_events "$ROUND_DIR/node-b.log" 'HTTP 429|status.?429|429 Too Many')
  A_RELAY_HEDGES=$(count_log_events "$ROUND_DIR/node-a.log" 'relay_hedged=true')
  B_RELAY_HEDGES=$(count_log_events "$ROUND_DIR/node-b.log" 'relay_hedged=true')
  A_RELAY_FALLBACKS=$(count_log_events "$ROUND_DIR/node-a.log" 'relay_fallback_selected')
  B_RELAY_FALLBACKS=$(count_log_events "$ROUND_DIR/node-b.log" 'relay_fallback_selected')
  A_RELAY_SELECTIONS=$(count_log_events_insensitive "$ROUND_DIR/node-a.log" 'selected relay region')
  B_RELAY_SELECTIONS=$(count_log_events_insensitive "$ROUND_DIR/node-b.log" 'selected relay region')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$round" "$ELAPSED_MS" "$A_DIRECT" "$B_DIRECT" "$A_EP" "$B_EP" \
    "$A_VALIDATION_SESSIONS" "$B_VALIDATION_SESSIONS" \
    "$A_VALIDATION_REQUESTS" "$B_VALIDATION_REQUESTS" \
    "$A_VALIDATION_ACKS" "$B_VALIDATION_ACKS" \
    "$A_MATCHED_ACKS" "$B_MATCHED_ACKS" "$A_HTTP_429" "$B_HTTP_429" \
    "$A_RELAY_HEDGES" "$B_RELAY_HEDGES" \
    "$A_RELAY_FALLBACKS" "$B_RELAY_FALLBACKS" \
    "$A_RELAY_SELECTIONS" "$B_RELAY_SELECTIONS" >>"$BASE_DIR/round-metrics.tsv"
  {
    echo "round=$round elapsed_ms=$ELAPSED_MS"
    echo "a_endpoint=$A_EP b_endpoint=$B_EP"
    echo "a_validation_sessions=$A_VALIDATION_SESSIONS b_validation_sessions=$B_VALIDATION_SESSIONS"
    echo "a_validation_requests=$A_VALIDATION_REQUESTS b_validation_requests=$B_VALIDATION_REQUESTS"
    echo "a_validation_acks=$A_VALIDATION_ACKS b_validation_acks=$B_VALIDATION_ACKS"
    echo "a_matched_acks=$A_MATCHED_ACKS b_matched_acks=$B_MATCHED_ACKS"
    echo "a_http_429=$A_HTTP_429 b_http_429=$B_HTTP_429"
    echo "a_relay_hedges=$A_RELAY_HEDGES b_relay_hedges=$B_RELAY_HEDGES"
    echo "a_relay_fallbacks=$A_RELAY_FALLBACKS b_relay_fallbacks=$B_RELAY_FALLBACKS"
    echo "a_relay_selections=$A_RELAY_SELECTIONS b_relay_selections=$B_RELAY_SELECTIONS"
  } >"$ROUND_DIR/metrics.env"

  # Record evidence.
  {
    echo "== Mini public IPv4 =="
    curl -s4 --max-time 8 ifconfig.me || true
    echo
    echo "== Air public IPv4 =="
    $AIR_SSH 'curl -s --max-time 8 ifconfig.me || true'
    echo
    echo "== A: STUN order / profile =="
    grep -h 'Local NAT profile\|fresh_mapping_observer' "$ROUND_DIR/node-a.log" | head -8
    echo "== B: STUN order / profile =="
    grep -h 'Local NAT profile\|fresh_mapping_observer' "$ROUND_DIR/node-b.log" | head -8
    echo "== A: fresh model + prediction =="
    grep -h 'fresh_mapping_model\|fresh_mapping_prediction_signaled' "$ROUND_DIR/node-a.log" | head -3
    echo "== B: fresh model + prediction =="
    grep -h 'fresh_mapping_model\|fresh_mapping_prediction_signaled' "$ROUND_DIR/node-b.log" | head -3
    echo "== A: matched ACKs / peer-reflexive / validation =="
    grep -h 'candidate_pair_probe_succeeded\|direct_validation\|peer_reflexive' "$ROUND_DIR/node-a.log" | grep -v Aborting | head -6
    echo "== B: matched ACKs / peer-reflexive / validation =="
    grep -h 'candidate_pair_probe_succeeded\|direct_validation\|peer_reflexive' "$ROUND_DIR/node-b.log" | grep -v Aborting | head -6
    echo "== A promotion =="
    grep -h 'direct_path_promoted\|candidate_pair_selected' "$ROUND_DIR/node-a.log" | head -2
    echo "== B promotion =="
    grep -h 'direct_path_promoted\|candidate_pair_selected' "$ROUND_DIR/node-b.log" | head -2
    echo "== per-round metrics =="
    cat "$ROUND_DIR/metrics.env"
    echo "== A relay hedge/fallback/selection =="
    grep -h -i -E 'relay_hedged=true|relay_fallback_selected|selected relay region' "$ROUND_DIR/node-a.log" | head -4
    echo "== B relay hedge/fallback/selection =="
    grep -h -i -E 'relay_hedged=true|relay_fallback_selected|selected relay region' "$ROUND_DIR/node-b.log" | head -4
  } >"$ROUND_DIR/evidence.log" 2>&1 || true

  if [[ "$direct_ok" -eq 1 ]] && is_public_ipv4_endpoint "$A_EP" && is_public_ipv4_endpoint "$B_EP"; then
    echo "[mini-air] ROUND $round: PASS both_direct elapsed_ms=$ELAPSED_MS (a_direct=$A_DIRECT b_direct=$B_DIRECT) a_ep=$A_EP b_ep=$B_EP evidence=$ROUND_DIR/evidence.log"
  else
    echo "[mini-air] ROUND $round: NO-DIRECT-or-nonpublic-path a_direct=$A_DIRECT b_direct=$B_DIRECT elapsed_ms=$ELAPSED_MS a_ep=$A_EP b_ep=$B_EP evidence=$ROUND_DIR/evidence.log"
    overall=1
  fi

  # Verify daemons are still alive (no auto-exit, no crash).
  if ! kill -0 "$NODE_A_PID" 2>/dev/null; then
    echo "[mini-air] ROUND $round: FAIL (Mini daemon exited unexpectedly)"
    overall=1
  fi
  # Probe the daemon itself (the local ssh session may drop while the daemon
  # keeps running happily on the Air).
  if ! $AIR_SSH "pgrep -f 'node-b-round-$round.json' >/dev/null" 2>/dev/null; then
    echo "[mini-air] ROUND $round: FAIL (Air daemon exited unexpectedly)"
    overall=1
  fi

  # Teardown. NODE_B_PID is the local ssh pid; the remote daemon is signalled
  # only through this round's verified PID file.
  kill "$NODE_B_PID" 2>/dev/null || true
  $AIR_SSH "pid_file='$REMOTE_NODE_B_PID_FILE'; if [ -r \"\$pid_file\" ]; then pid=\$(cat \"\$pid_file\"); case \"\$pid\" in ''|*[!0-9]*) ;; *) if ps -p \"\$pid\" -o command= 2>/dev/null | grep -F -- '$REMOTE_DAEMON_BIN' >/dev/null; then kill \"\$pid\" 2>/dev/null || true; fi ;; esac; fi; rm -f \"\$pid_file\" '$AIR_CONFIG'" 2>/dev/null || true
  REMOTE_NODE_B_PID_FILE=""
  kill "$NODE_A_PID" "$RELAY_PID" "$SERVER_PID" 2>/dev/null || true
  PIDS=()
  sleep 0.5
done

echo "[mini-air] base dir: $BASE_DIR"
echo "[mini-air] round metrics: $BASE_DIR/round-metrics.tsv"
echo "[mini-air] RESULT: $([ "$overall" -eq 0 ] && echo PASS || echo FAIL)"
exit $overall
