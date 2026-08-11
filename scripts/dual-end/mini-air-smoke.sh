#!/usr/bin/env bash
# Real Mini <-> Air dual-end cold-start verification.
#
# Topology:
#   Mini (this machine, macOS M4)  --daemon A-->  real NAT A
#   Air  (air.example.com via SSH, macOS arm64) --daemon B--> real NAT B
#
# The verification control and relay are external. The two temporary daemons
# connect through their real public NATs; Direct must be proven by both sides
# within the configured strict target.
set -euo pipefail

HARNESS_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
ROOT_DIR=${P2WLAN_ROOT_DIR:-$HARNESS_ROOT}
REMOTE_CONTROL_URL=${REMOTE_CONTROL_URL:-}
ROUNDS=${ROUNDS:-}
ACCEPTANCE_MODE=${ACCEPTANCE_MODE:-strict}
STRICT_PHASE=${STRICT_PHASE:-preflight}
DIAG_A_PORT=${DIAG_A_PORT:-49377}
DIAG_B_PORT=${DIAG_B_PORT:-49378}
AIR_HOST=${AIR_HOST:-air.example.com}
AIR_USER=${AIR_USER:-pyu}
# The lab's Mini-Air SSH service listens on port 2222. Keep the environment
# override for setups that deliberately use a different port.
AIR_SSH_PORT=${AIR_SSH_PORT:-2300}
AIR_SSH_KEY=${AIR_SSH_KEY:-/Users/pyu/Desktop/codex_local_ed25519}
AIR_DAEMON_BIN=${AIR_DAEMON_BIN:-}
MINI_TAILSCALE_IP=$(tailscale ip -4 2>/dev/null | head -1 || echo "100.84.190.40")
DIRECT_TIMEOUT_S=${DIRECT_TIMEOUT_S:-30}
DIRECT_SUCCESS_TARGET_MS=${DIRECT_SUCCESS_TARGET_MS:-10000}
VALIDATE_OVERLAY=${VALIDATE_OVERLAY:-0}
OVERLAY_TIMEOUT_S=${OVERLAY_TIMEOUT_S:-12}
STUN_SERVERS=${STUN_SERVERS:-"stun.cloudflare.com:3478,stun.l.google.com:19302,stun.miwifi.com:3478"}
NETWORK_ID=${NETWORK_ID:-default}
ISOLATION_HELPER="$HARNESS_ROOT/scripts/dual-end/network-isolation.py"
RUN_ID=${RUN_ID:-$(date +%s)-$$}
ARTIFACT_ROOT=${ARTIFACT_ROOT:-}
AB_SEQUENCE_DIR=${AB_SEQUENCE_DIR:-${ARTIFACT_ROOT:-}}
STRICT_PARSER="$HARNESS_ROOT/scripts/dual-end/strict-direct-parser.py"
REMOTE_RUN_DIR="/tmp/p2wlan-direct-$RUN_ID"
REMOTE_DAEMON_BIN="$REMOTE_RUN_DIR/p2wlan-daemon"
DAEMON_BIN_OVERRIDE=$(printenv DAEMON_BIN_OVERRIDE 2>/dev/null || true)

AIR_SSH="ssh -i $AIR_SSH_KEY -p $AIR_SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPersist=120 -o ControlPath=/tmp/p2wlan-direct-$RUN_ID-%C $AIR_USER@$AIR_HOST"

umask 077
if [[ "$(cd "$ROOT_DIR" && pwd -P)" != "$HARNESS_ROOT" ]]; then
  echo "[mini-air] P2WLAN_ROOT_DIR must resolve to the current harness tree; do not point it at a baseline worktree" >&2
  exit 2
fi
ROOT_DIR=$HARNESS_ROOT
case "$ACCEPTANCE_MODE" in
  compat)
    if [[ -z "$DAEMON_BIN_OVERRIDE" ]]; then
      echo "[mini-air] ACCEPTANCE_MODE=compat requires DAEMON_BIN_OVERRIDE for the legacy binary" >&2
      exit 2
    fi
    if [[ "$STRICT_PHASE" != "preflight" ]]; then
      echo "[mini-air] STRICT_PHASE is only meaningful with ACCEPTANCE_MODE=strict" >&2
      exit 2
    fi
    ACCEPTANCE_STAGE=compat-baseline
    ROUNDS=${ROUNDS:-3}
    ;;
  strict)
    if [[ -n "$DAEMON_BIN_OVERRIDE" ]]; then
      echo "[mini-air] ACCEPTANCE_MODE=strict only permits the current-tree build; unset DAEMON_BIN_OVERRIDE" >&2
      exit 2
    fi
    case "$STRICT_PHASE" in
      preflight)
        ACCEPTANCE_STAGE=strict-preflight
        ROUNDS=${ROUNDS:-3}
        ;;
      acceptance)
        ACCEPTANCE_STAGE=strict-acceptance
        ROUNDS=${ROUNDS:-10}
        ;;
      *)
        echo "[mini-air] STRICT_PHASE must be preflight or acceptance" >&2
        exit 2
        ;;
    esac
    ;;
  *)
    echo "[mini-air] ACCEPTANCE_MODE must be compat or strict" >&2
    exit 2
    ;;
esac
case "$ACCEPTANCE_STAGE" in
  compat-baseline|strict-preflight)
    [[ "$ROUNDS" == "3" ]] || { echo "[mini-air] $ACCEPTANCE_STAGE requires ROUNDS=3" >&2; exit 2; }
    ;;
  strict-acceptance)
    [[ "$ROUNDS" == "10" ]] || { echo "[mini-air] strict acceptance requires ROUNDS=10" >&2; exit 2; }
    ;;
esac
if [[ -z "$ARTIFACT_ROOT" || -z "$AB_SEQUENCE_DIR" ]]; then
  echo "[mini-air] ARTIFACT_ROOT and AB_SEQUENCE_DIR are required for auditable A/B runs" >&2
  exit 2
fi
if [[ -n "$ARTIFACT_ROOT" ]]; then
  if [[ ! -d "$ARTIFACT_ROOT" ]]; then
    echo "[mini-air] artifact root does not exist: $ARTIFACT_ROOT" >&2
    exit 2
  fi
  BASE_DIR="$ARTIFACT_ROOT/mini-air-$RUN_ID"
  if [[ -e "$BASE_DIR" ]]; then
    echo "[mini-air] refusing to reuse artifact directory: $BASE_DIR" >&2
    exit 2
  fi
  mkdir -m 700 "$BASE_DIR"
else
  BASE_DIR=$(mktemp -d /tmp/p2wlan-direct-final.XXXXXX)
  chmod 700 "$BASE_DIR"
fi
if [[ ! -d "$AB_SEQUENCE_DIR" ]]; then
  echo "[mini-air] A/B sequence directory does not exist: $AB_SEQUENCE_DIR" >&2
  exit 2
fi
REMOTE_NODE_B_PID_FILE=""
LOCAL_NODE_A_PID=""
LOCAL_NODE_A_CONFIG=""
LOCAL_NODE_A_DEVICE=""
REMOTE_NODE_B_LOG=""
REMOTE_NODE_B_DEVICE=""
# Do not inherit an ambient application-level RUST_LOG (often `warn`) here:
# this harness needs Info promotion telemetry in both logs. Callers that need
# a different filter can override the harness-specific variable explicitly.
HARNESS_RUST_LOG=${HARNESS_RUST_LOG:-info,p2pnet_daemon::network_outbound=debug}

if [[ -z "$REMOTE_CONTROL_URL" ]]; then
  echo "[mini-air] REMOTE_CONTROL_URL is required; this harness must not start a local control or relay service" >&2
  exit 2
fi
if [[ ! -f "$ISOLATION_HELPER" ]]; then
  echo "[mini-air] network isolation helper is missing: $ISOLATION_HELPER" >&2
  exit 2
fi
# Isolation is proven live per round (the active roster must be exactly this
# round's two nodes), so the default network is usable for a two-device test
# run without ever being exempted from the isolation requirement.
if [[ "$ACCEPTANCE_MODE" == "strict" && "$NETWORK_ID" == "default" ]]; then
  echo "[mini-air] strict verification on the default network requires the per-round isolation proof and device cleanup" >&2
fi

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

dirty_diff_sha256() {
  {
    git -C "$ROOT_DIR" diff --binary
    git -C "$ROOT_DIR" ls-files --others --exclude-standard -z | sort -z | \
      while IFS= read -r -d '' path; do
        printf '\n-- untracked: %s --\n' "$path"
        cat "$ROOT_DIR/$path"
      done
  } | sha256_file /dev/stdin
}

write_sequence_invalid() {
  local reason=$1
  python3 - "$AB_SEQUENCE_DIR/sequence-invalid.json" "$reason" <<'PY'
import json
import os
import sys

path, reason = sys.argv[1:]
tmp = "%s.%s" % (path, os.getpid())
with open(tmp, "w", encoding="utf-8") as stream:
    json.dump({"valid": False, "reason": reason}, stream, indent=2, sort_keys=True)
    stream.write("\n")
os.replace(tmp, path)
PY
}

record_and_lock_fingerprint() {
  local manifest=$1
  local lock_file="$AB_SEQUENCE_DIR/sequence-fingerprints.json"
  local invalid_file="$AB_SEQUENCE_DIR/sequence-invalid.json"
  python3 - "$lock_file" "$invalid_file" "$manifest" \
    "$HARNESS_SHA256" "$STRICT_PARSER_SHA256" "$GIT_HEAD" "$DIRTY_DIFF_SHA256" \
    "$ACCEPTANCE_MODE" "$ACCEPTANCE_STAGE" "$LOCAL_DAEMON_SHA256" "$FIX_DAEMON_SHA256" "$DAEMON_BIN" <<'PY'
import json
import os
import sys

(lock_path, invalid_path, manifest_path, harness_sha, parser_sha, head, dirty_sha,
 mode, stage, daemon_sha, fix_sha, daemon_path) = sys.argv[1:]
invariants = {
    "current_harness_sha256": harness_sha,
    "strict_parser_sha256": parser_sha,
    "head": head,
    "dirty_diff_sha256": dirty_sha,
}

record = dict(invariants)
record.update({
    "acceptance_mode": mode,
    "acceptance_stage": stage,
    "daemon_binary_sha256": daemon_sha,
    "daemon_binary_path": daemon_path,
    "binary_role": "baseline" if mode == "compat" else "fix",
    "fix_binary_sha256": fix_sha,
})

def write(path, value):
    tmp = "%s.%s" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(tmp, path)

if os.path.exists(invalid_path):
    raise SystemExit("A/B sequence is already invalid: %s" % invalid_path)
if os.path.exists(lock_path):
    with open(lock_path, encoding="utf-8") as stream:
        lock = json.load(stream)
    if lock.get("invariants") != invariants:
        write(invalid_path, {
            "valid": False,
            "reason": "harness/parser/HEAD/dirty-diff fingerprint changed",
            "expected": lock.get("invariants"),
            "actual": invariants,
        })
        raise SystemExit("A/B sequence invalidated: invariant fingerprint changed")
else:
    lock = {"invariants": invariants, "modes": {}}

existing_fix = lock.get("fix_binary_sha256")
if existing_fix is not None and existing_fix != fix_sha:
    write(invalid_path, {
        "valid": False,
        "reason": "fix binary fingerprint changed",
        "expected": existing_fix,
        "actual": fix_sha,
    })
    raise SystemExit("A/B sequence invalidated: fix binary fingerprint changed")
lock["fix_binary_sha256"] = fix_sha

mode_record = {"daemon_binary_sha256": daemon_sha, "daemon_binary_path": daemon_path}
existing = lock["modes"].get(mode)
if existing is not None and existing != mode_record:
    write(invalid_path, {
        "valid": False,
        "reason": "%s binary fingerprint changed" % mode,
        "expected": existing,
        "actual": mode_record,
    })
    raise SystemExit("A/B sequence invalidated: %s binary fingerprint changed" % mode)
lock["modes"][mode] = mode_record
baseline = lock["modes"].get("compat", {}).get("daemon_binary_sha256")
if mode == "strict" and baseline is None:
    raise SystemExit("strict acceptance requires a locked compatibility baseline binary")
record["baseline_binary_sha256"] = baseline or daemon_sha
write(lock_path, lock)
write(manifest_path, record)
PY
}

require_sequence_phase() {
  python3 - "$AB_SEQUENCE_DIR/sequence-results.json" "$AB_SEQUENCE_DIR/dirty-diff-freeze.json" \
    "$ACCEPTANCE_STAGE" "$DIRTY_DIFF_SHA256" <<'PY'
import json
import os
import sys

results_path, freeze_path, stage, dirty_sha = sys.argv[1:]
results = []
if os.path.exists(results_path):
    with open(results_path, encoding="utf-8") as stream:
        results = json.load(stream)
if any(row.get("stage") == stage for row in results):
    raise SystemExit("A/B sequence already contains %s results; start a new sequence after an incomplete stage" % stage)

def passed(required_stage, expected):
    rows = [row for row in results if row.get("stage") == required_stage]
    return len(rows) == expected and all(row.get("ok") is True for row in rows)

if stage == "strict-preflight":
    if not passed("compat-baseline", 3):
        raise SystemExit("strict preflight requires exactly 3/3 completed compatibility baseline rounds")
    if not os.path.exists(freeze_path):
        raise SystemExit("strict preflight requires the frozen dirty-diff manifest")
    with open(freeze_path, encoding="utf-8") as stream:
        freeze = json.load(stream)
    if freeze.get("dirty_diff_sha256") != dirty_sha:
        raise SystemExit("strict preflight refuses a dirty diff different from the baseline freeze")
elif stage == "strict-acceptance" and not passed("strict-preflight", 3):
    raise SystemExit("strict acceptance requires 3/3 completed strict preflight rounds")
PY
}

record_sequence_round() {
  local round=$1
  local ok=$2
  local functional_ms=$3
  local strict_ms=$4
  python3 - "$AB_SEQUENCE_DIR/sequence-results.json" "$AB_SEQUENCE_DIR/dirty-diff-freeze.json" \
    "$ACCEPTANCE_STAGE" "$round" "$ok" "$functional_ms" "$strict_ms" "$DIRTY_DIFF_SHA256" <<'PY'
import json
import os
import sys

(results_path, freeze_path, stage, round_number, ok, functional_ms, strict_ms,
 dirty_sha) = sys.argv[1:]
results = []
if os.path.exists(results_path):
    with open(results_path, encoding="utf-8") as stream:
        results = json.load(stream)
results.append({
    "stage": stage,
    "round": int(round_number),
    "ok": ok == "1",
    "functional_direct_ms": int(functional_ms) if functional_ms else None,
    "strict_convergence_ms": int(strict_ms) if strict_ms else None,
})

def write(path, value):
    tmp = "%s.%s" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(tmp, path)

write(results_path, results)
baseline = [row for row in results if row.get("stage") == "compat-baseline"]
if len(baseline) == 3 and all(row.get("ok") is True for row in baseline):
    write(freeze_path, {
        "dirty_diff_sha256": dirty_sha,
        "frozen_after": "3/3 compatibility baseline rounds",
    })
PY
}

# Direct-validation lifecycle stages are retained in the diagnostics snapshot
# and emitted as structured tracing events.  The snapshot is a bounded ring,
# so prefer the durable log count and fall back to the snapshot when a caller
# uses a filter that suppresses those events.
count_status_stage() {
  local status_file=$1
  local peer_id=$2
  local stage=$3
  python3 - "$status_file" "$peer_id" "$stage" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        status = json.load(stream)
except (OSError, ValueError):
    print(0)
    raise SystemExit

peer_id = sys.argv[2]
stage = sys.argv[3]
events = []
for peer in ([status["peer"]] if status.get("peer") else status.get("peers", [])):
    if peer.get("node_id") == peer_id:
        events.extend(peer.get("direct_events", []))
print(sum(1 for event in events if event.get("stage") == stage))
PY
}

count_log_events_for_peer() {
  local log_file=$1
  local peer_id=$2
  local pattern=$3
  grep -F -- "$peer_id" "$log_file" 2>/dev/null | grep -E -c -- "$pattern" || true
}

count_non_target_traversal_activity() {
  local log_file=$1
  local target_peer=$2
  grep -E 'peer_id=.*(offer|probe|direct_validation|punch)|event=.*(offer|probe|direct_validation|punch)' "$log_file" 2>/dev/null | \
    grep -F 'peer_id=' | grep -F -v -- "$target_peer" | wc -l | tr -d ' ' || true
}

count_non_target_peer_events() {
  local log_file=$1
  local target_peer=$2
  local pattern=$3
  grep -E -- "$pattern" "$log_file" 2>/dev/null | grep -F 'peer_id=' | \
    grep -F -v -- "$target_peer" | wc -l | tr -d ' ' || true
}

log_reports_overlay_round_trip() {
  local log_file=$1
  local peer_id=$2
  count_log_events_for_peer "$log_file" "$peer_id" 'overlay_payload_verified'
}

count_stage() {
  local status_file=$1
  local log_file=$2
  local peer_id=$3
  local stage=$4
  local log_count
  local status_count
  log_count=$(count_log_events_for_peer "$log_file" "$peer_id" "event=\\\"$stage\\\"|$stage")
  status_count=$(count_status_stage "$status_file" "$peer_id" "$stage")
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
  local peer_id=$2
  curl -fsS --max-time 5 "$status_url" | python3 -c '
import json
import sys

try:
    status = json.load(sys.stdin)
except ValueError:
    raise SystemExit(1)
peer_id = sys.argv[1]
peers = [status["peer"]] if status.get("peer") else status.get("peers", [])
raise SystemExit(0 if any(
    peer.get("node_id") == peer_id
    and peer.get("state") == "direct"
    and peer.get("active_path") == "direct"
    for peer in peers
) else 1)
' "$peer_id"
}

status_reports_strict_direct() {
  local status_file=$1
  local peer_id=$2
  python3 - "$status_file" "$peer_id" <<'PY'
import ipaddress
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        status = json.load(stream)
except (OSError, ValueError):
    raise SystemExit(1)

peer_id = sys.argv[2]
for peer in ([status["peer"]] if status.get("peer") else status.get("peers", [])):
    if peer.get("node_id") != peer_id:
        continue
    pair = peer.get("selected_pair") or peer.get("current_direct_pair") or {}
    endpoint = pair.get("remote_endpoint") or ""
    try:
        address = ipaddress.ip_address(endpoint.rsplit(":", 1)[0])
    except ValueError:
        raise SystemExit(1)
    if not (
        peer.get("state") == "direct"
        and peer.get("active_path") == "direct"
        and peer.get("is_public_udp_direct") is True
        and address.version == 4
        and address.is_global
    ):
        raise SystemExit(1)
    raise SystemExit(0)
raise SystemExit(1)
PY
}

# The legacy release cannot supply the current owned-validation diagnostics
# schema. Compatibility acceptance deliberately checks only observable
# functional Direct state for this round's two temporary node IDs.
status_reports_compat_direct() {
  local status_file=$1
  local peer_id=$2
  python3 - "$status_file" "$peer_id" <<'PY'
import ipaddress
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        status = json.load(stream)
except (OSError, ValueError):
    raise SystemExit(1)

for peer in ([status["peer"]] if status.get("peer") else status.get("peers", [])):
    if peer.get("node_id") != sys.argv[2]:
        continue
    pair = peer.get("selected_pair") or peer.get("current_direct_pair") or {}
    endpoint = pair.get("remote_endpoint") or ""
    try:
        address = ipaddress.ip_address(endpoint.rsplit(":", 1)[0])
    except ValueError:
        raise SystemExit(1)
    raise SystemExit(0 if (
        peer.get("state") == "direct"
        and peer.get("active_path") == "direct"
        and address.version == 4
        and address.is_global
    ) else 1)
raise SystemExit(1)
PY
}

compatibility_direct_pair() {
  local a_status=$1
  local a_peer=$2
  local b_status=$3
  local b_peer=$4
  status_reports_compat_direct "$a_status" "$a_peer" && \
    status_reports_compat_direct "$b_status" "$b_peer"
}

status_endpoint_from_json() {
  local status_file=$1
  local peer_id=$2
  python3 - "$status_file" "$peer_id" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        status = json.load(stream)
except (OSError, ValueError):
    raise SystemExit(1)
peer_id = sys.argv[2]
for peer in ([status["peer"]] if status.get("peer") else status.get("peers", [])):
    if peer.get("node_id") == peer_id:
        pair = peer.get("selected_pair") or peer.get("current_direct_pair") or {}
        print(pair.get("remote_endpoint") or "")
        raise SystemExit(0)
raise SystemExit(1)
PY
}

strict_validation_session() {
  local status_file=$1
  local peer_id=$2
  python3 "$STRICT_PARSER" "$status_file" "$peer_id"
}

strict_validation_pair() {
  local a_status=$1
  local a_peer=$2
  local b_status=$3
  local b_peer=$4
  python3 "$STRICT_PARSER" --pair "$a_status" "$a_peer" "$b_status" "$b_peer"
}

capture_status_pair() {
  POLL_INDEX=$((POLL_INDEX + 1))
  local poll_id
  poll_id=$(printf '%03d' "$POLL_INDEX")
  CURRENT_A_POLL="$ROUND_DIR/node-a.poll-$poll_id.json"
  CURRENT_B_POLL="$ROUND_DIR/node-b.poll-$poll_id.json"
  CURRENT_RESULT="$ROUND_DIR/strict-result-$poll_id.json"
  local a_tmp="$CURRENT_A_POLL.tmp.$$"
  local b_tmp="$CURRENT_B_POLL.tmp.$$"
  local a_err="$ROUND_DIR/node-a.poll-$poll_id.stderr"
  local b_err="$ROUND_DIR/node-b.poll-$poll_id.stderr"
  local capture_started_ms
  capture_started_ms=$(python3 -c 'import time; print(int(time.time()*1000))')
  # Fetch both endpoint-scoped snapshots concurrently.  ControlMaster keeps
  # the Air SSH transport warm between polls.
  local mini_status_path="/status"
  local air_status_path="/status"
  if [[ "$ACCEPTANCE_MODE" == "strict" ]]; then
    mini_status_path="/status/peer/$AIR_NODE_ID"
    air_status_path="/status/peer/$MINI_NODE_ID"
  fi
  curl -fsS --max-time 5 "http://127.0.0.1:$DIAG_A_PORT$mini_status_path" >"$a_tmp" 2>"$a_err" &
  local mini_pid=$!
  $AIR_SSH "curl -fsS --max-time 5 http://127.0.0.1:$DIAG_B_PORT$air_status_path" >"$b_tmp" 2>"$b_err" &
  local air_pid=$!
  local mini_rc=0
  local air_rc=0
  wait "$mini_pid" || mini_rc=$?
  local mini_captured_ms
  mini_captured_ms=$(python3 -c 'import time; print(int(time.time()*1000))')
  wait "$air_pid" || air_rc=$?
  local air_captured_ms
  air_captured_ms=$(python3 -c 'import time; print(int(time.time()*1000))')
  if [[ "$mini_rc" -ne 0 || "$air_rc" -ne 0 ]]; then
    rm -f "$a_tmp" "$b_tmp"
    printf 'mini_rc=%s air_rc=%s\n' "$mini_rc" "$air_rc" >"$ROUND_DIR/poll-$poll_id.capture-error"
    return 1
  fi
  mv "$a_tmp" "$CURRENT_A_POLL"
  mv "$b_tmp" "$CURRENT_B_POLL"
  local parser_rc
  set +e
  python3 "$STRICT_PARSER" --pair "$CURRENT_A_POLL" "$AIR_NODE_ID" "$CURRENT_B_POLL" "$MINI_NODE_ID" >"$CURRENT_RESULT.tmp.$$"
  parser_rc=$?
  set -e
  mv "$CURRENT_RESULT.tmp.$$" "$CURRENT_RESULT"
  python3 - "$ROUND_DIR/poll-$poll_id.json" "$CURRENT_A_POLL" "$CURRENT_B_POLL" "$CURRENT_RESULT" "$POLL_INDEX" "$parser_rc" "$START_MS" "$capture_started_ms" "$mini_captured_ms" "$air_captured_ms" "$AIR_NODE_ID" "$MINI_NODE_ID" <<'PY'
import hashlib
import json
import sys
import time

out, a_path, b_path, result_path, poll_index, parser_rc, started, capture_started, mini_ms, air_ms, air_peer, mini_peer = sys.argv[1:]
def load(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)
def sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
def target(status, peer_id):
    peer = status.get("peer") or next((p for p in status.get("peers", []) if p.get("node_id") == peer_id), {})
    pair = peer.get("selected_pair") or peer.get("current_direct_pair") or {}
    return {
        "state": peer.get("state"),
        "active_path": peer.get("active_path"),
        "selected_endpoint": pair.get("remote_endpoint"),
    }
a = load(a_path)
b = load(b_path)
result = load(result_path)
meta = {
    "poll_index": int(poll_index),
    "round_started_ms": int(started),
    "capture_started_ms": int(capture_started),
    "mini_status_captured_ms": int(mini_ms),
    "air_status_captured_ms": int(air_ms),
    "mini_file_sha256": sha(a_path),
    "air_file_sha256": sha(b_path),
    "parser_exit_code": int(parser_rc),
    "parser_reason": {
        "mini": result.get("left", {}).get("reason"),
        "air": result.get("right", {}).get("reason"),
    },
    "mini_target_state": target(a, air_peer)["state"],
    "mini_target_active_path": target(a, air_peer)["active_path"],
    "mini_selected_endpoint": target(a, air_peer)["selected_endpoint"],
    "air_target_state": target(b, mini_peer)["state"],
    "air_target_active_path": target(b, mini_peer)["active_path"],
    "air_selected_endpoint": target(b, mini_peer)["selected_endpoint"],
    "strict_result_sha256": sha(result_path),
}
tmp = out + ".tmp"
with open(tmp, "w", encoding="utf-8") as stream:
    json.dump(meta, stream, indent=2, sort_keys=True)
    stream.write("\n")
import os
os.replace(tmp, out)
PY
}

collect_air_log() {
  $AIR_SSH "cat '$REMOTE_NODE_B_LOG'" >"$ROUND_DIR/node-b.log"
}

remote_status_reports_direct() {
  local peer_id=$1
  $AIR_SSH "curl -fsS --max-time 5 http://127.0.0.1:$DIAG_B_PORT/status | python3 -c 'import json,sys; status=json.load(sys.stdin); peer_id=sys.argv[1]; raise SystemExit(0 if any(peer.get(\"node_id\") == peer_id and peer.get(\"state\") == \"direct\" and peer.get(\"active_path\") == \"direct\" for peer in status.get(\"peers\", [])) else 1)' '$peer_id'"
}

direct_endpoint_from_log() {
  local log_file=$1
  local peer_id=$2
  grep -F -- "$peer_id" "$log_file" 2>/dev/null | grep -E 'direct_path_promoted|candidate_pair_selected' \
    | grep -oE 'remote_endpoint=[0-9.]+:[0-9]+' \
    | sed 's/^remote_endpoint=//' \
    | tail -1 || true
}

is_public_ipv4_endpoint() {
  local endpoint=$1
  python3 - "$endpoint" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1].rsplit(":", 1)[0])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if address.version == 4 and address.is_global else 1)
PY
}

cleanup() {
  local_daemon_cleanup || true
  remote_daemon_cleanup || true
  redact_local_config || true
  if [[ -n "$REMOTE_NODE_B_PID_FILE" ]]; then
    echo "[mini-air] remote PID file retained after cleanup verification failure: $REMOTE_NODE_B_PID_FILE" >&2
  fi
  echo "[mini-air] artifacts retained: $BASE_DIR" >&2
}

redact_local_config() {
  [[ -n "$LOCAL_NODE_A_CONFIG" && -f "$LOCAL_NODE_A_CONFIG" ]] || return 0
  python3 - "$LOCAL_NODE_A_CONFIG" <<'PY'
import json
import os
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as stream:
    value = json.load(stream)

def redact(item):
    if isinstance(item, dict):
        for key, child in list(item.items()):
            lowered = key.lower()
            if any(marker in lowered for marker in (
                "token", "secret", "password", "private_key", "credential"
            )):
                item[key] = "<redacted>"
            else:
                redact(child)
    elif isinstance(item, list):
        for child in item:
            redact(child)

redact(value)
tmp = "%s.redacted.%s" % (path, os.getpid())
with open(tmp, "w", encoding="utf-8") as stream:
    json.dump(value, stream, indent=2, sort_keys=True)
    stream.write("\n")
os.replace(tmp, path)
PY
}

local_daemon_cleanup() {
  [[ -n "$LOCAL_NODE_A_PID" ]] || return 0
  local command
  command=$(ps -ww -p "$LOCAL_NODE_A_PID" -o command= 2>/dev/null || true)
  if [[ "$command" != *"$DAEMON_BIN"* ||
        "$command" != *"$LOCAL_NODE_A_CONFIG"* ||
        "$command" != *"$LOCAL_NODE_A_DEVICE"* ||
        ( "$LOCAL_NODE_A_CONFIG" != *"$RUN_ID"* && "$LOCAL_NODE_A_DEVICE" != *"$RUN_ID"* ) ]]; then
    echo "[mini-air] Mini cleanup verification failed; PID retained: $LOCAL_NODE_A_PID" >&2
    return 1
  fi
  kill "$LOCAL_NODE_A_PID" 2>/dev/null || true
  LOCAL_NODE_A_PID=""
}

remote_daemon_matches() {
  [[ -n "$REMOTE_NODE_B_PID_FILE" ]] || return 1
  $AIR_SSH "pid_file='$REMOTE_NODE_B_PID_FILE'; config='$AIR_CONFIG'; device='$REMOTE_NODE_B_DEVICE'; bin='$REMOTE_DAEMON_BIN'; run_id='$RUN_ID'; case \"\$pid_file:\$config:\$device:\$bin\" in *\"\$run_id\"*) ;; *) exit 1 ;; esac; test -r \"\$pid_file\" || exit 1; pid=\$(cat \"\$pid_file\"); case \"\$pid\" in ''|*[!0-9]*) exit 1 ;; esac; cmd=\$(ps -ww -p \"\$pid\" -o command= 2>/dev/null) || exit 1; case \"\$cmd\" in *\"\$bin\"*\"\$config\"*\"\$device\"*) exit 0 ;; *) exit 1 ;; esac" >/dev/null 2>&1
}

remote_daemon_cleanup() {
  [[ -n "$REMOTE_NODE_B_PID_FILE" ]] || return 0
  if $AIR_SSH "pid_file='$REMOTE_NODE_B_PID_FILE'; config='$AIR_CONFIG'; device='$REMOTE_NODE_B_DEVICE'; bin='$REMOTE_DAEMON_BIN'; run_id='$RUN_ID'; case \"\$pid_file:\$config:\$device:\$bin\" in *\"\$run_id\"*) ;; *) exit 3 ;; esac; if [ ! -r \"\$pid_file\" ]; then exit 3; fi; pid=\$(cat \"\$pid_file\"); case \"\$pid\" in ''|*[!0-9]*) exit 3 ;; esac; cmd=\$(ps -ww -p \"\$pid\" -o command= 2>/dev/null) || exit 3; case \"\$cmd\" in *\"\$bin\"*\"\$config\"*\"\$device\"*) kill \"\$pid\" && rm -f \"\$pid_file\" \"\$config\" ;; *) exit 3 ;; esac" >/dev/null 2>&1; then
    REMOTE_NODE_B_PID_FILE=""
    return 0
  fi
  echo "[mini-air] Air cleanup verification failed; remote PID/config/log retained" >&2
  return 1
}
trap cleanup EXIT

echo "[mini-air] building temporary daemon (release)..."
echo "[mini-air] verification control/relay: $REMOTE_CONTROL_URL"
# Both sides of the A/B comparison are fingerprinted before the run begins.
# Compatibility executes the override, while the current-tree build remains a
# frozen reference for the later strict phase.
cargo build --release -p p2wlan-daemon --manifest-path "$ROOT_DIR/client/daemon/Cargo.toml" >/dev/null
FIX_DAEMON_BIN="$ROOT_DIR/target/release/p2wlan-daemon"
FIX_DAEMON_SHA256=$(sha256_file "$FIX_DAEMON_BIN")
if [[ -n "$DAEMON_BIN_OVERRIDE" ]]; then
  if [[ ! -x "$DAEMON_BIN_OVERRIDE" ]]; then
    echo "[mini-air] DAEMON_BIN_OVERRIDE is not executable: $DAEMON_BIN_OVERRIDE" >&2
    exit 2
  fi
  DAEMON_BIN="$DAEMON_BIN_OVERRIDE"
else
  DAEMON_BIN="$FIX_DAEMON_BIN"
fi
LOCAL_DAEMON_SHA256=$(sha256_file "$DAEMON_BIN")
HARNESS_SHA256=$(sha256_file "$HARNESS_ROOT/scripts/dual-end/mini-air-smoke.sh")
STRICT_PARSER_SHA256=$(sha256_file "$STRICT_PARSER")
GIT_HEAD=$(git -C "$ROOT_DIR" rev-parse HEAD)
DIRTY_DIFF_SHA256=$(dirty_diff_sha256)
record_and_lock_fingerprint "$BASE_DIR/run-manifest.json"
require_sequence_phase
printf '%s\n' "$LOCAL_DAEMON_SHA256" >"$BASE_DIR/daemon-binary.sha256"
printf '%s\n' "$HARNESS_SHA256" >"$BASE_DIR/current-harness.sha256"
printf '%s\n' "$STRICT_PARSER_SHA256" >"$BASE_DIR/strict-parser.sha256"
printf '%s\n' "$DIRTY_DIFF_SHA256" >"$BASE_DIR/dirty-diff.sha256"

echo "[mini-air] Air reachability check..."
$AIR_SSH 'uname -m' | tail -1
echo "[mini-air] Air public IPv4: $($AIR_SSH 'curl -s --max-time 8 ifconfig.me || true' | tail -1)"
echo "[mini-air] Mini public IPv4: $(curl -s4 --max-time 8 ifconfig.me || true)"

if lsof -nP -iTCP:"$DIAG_A_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "[mini-air] Mini diagnostics port is already occupied: $DIAG_A_PORT" >&2
  exit 2
fi
if $AIR_SSH "lsof -nP -iTCP:$DIAG_B_PORT -sTCP:LISTEN >/dev/null 2>&1"; then
  echo "[mini-air] Air diagnostics port is already occupied: $DIAG_B_PORT" >&2
  exit 2
fi

# Every run gets an independent Air directory. A pre-positioned binary would
# defeat the required upload SHA audit, so refuse that legacy escape hatch.
if [[ -n "$AIR_DAEMON_BIN" ]]; then
  echo "[mini-air] AIR_DAEMON_BIN is not allowed for audited dual-end runs" >&2
  exit 2
fi
$AIR_SSH "umask 077; mkdir -m 700 '$REMOTE_RUN_DIR'"
# Upload only to the `.new` sibling, verify its digest before it becomes
# executable, then atomically install it inside this run's directory.
$AIR_SSH "cat > '$REMOTE_DAEMON_BIN.new'" < "$DAEMON_BIN"
REMOTE_NEW_SHA256=$($AIR_SSH "if command -v shasum >/dev/null 2>&1; then shasum -a 256 '$REMOTE_DAEMON_BIN.new' | awk '{print \$1}'; elif command -v sha256sum >/dev/null 2>&1; then sha256sum '$REMOTE_DAEMON_BIN.new' | awk '{print \$1}'; else exit 127; fi")
if [[ "$REMOTE_NEW_SHA256" != "$LOCAL_DAEMON_SHA256" ]]; then
  echo "[mini-air] Air uploaded binary SHA-256 mismatch; refusing to install it" >&2
  exit 1
fi
$AIR_SSH "chmod 700 '$REMOTE_DAEMON_BIN.new' && mv '$REMOTE_DAEMON_BIN.new' '$REMOTE_DAEMON_BIN'"

# A matching semantic version is not enough here: a user can correctly upload
# an older release build after the source tree has changed.  Refuse to run a
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
echo "[mini-air] isolated network id: $NETWORK_ID"

overall=0
if [[ "$ACCEPTANCE_MODE" == "compat" ]]; then
  printf 'round\tacceptance_mode\tfunctional_direct_ms\telapsed_ms\ta_endpoint\tb_endpoint\ta_crash_panic\tb_crash_panic\n' >"$BASE_DIR/round-metrics.tsv"
else
  printf 'round\tacceptance_mode\tfunctional_direct_ms\tstrict_convergence_ms\telapsed_ms\ta_direct\tb_direct\ta_endpoint\tb_endpoint\ta_validation_sessions\tb_validation_sessions\ta_validation_requests\tb_validation_requests\ta_validation_acks\tb_validation_acks\ta_validation_promoted\tb_validation_promoted\ta_strict_validation\tb_strict_validation\ta_matched_acks\tb_matched_acks\ta_overlay_round_trips\tb_overlay_round_trips\ta_http_429\tb_http_429\ta_relay_hedges\tb_relay_hedges\ta_relay_fallbacks\tb_relay_fallbacks\ta_relay_selections\tb_relay_selections\ta_crash_panic\tb_crash_panic\ta_post_direct_traversal\tb_post_direct_traversal\ta_non_target_traversal\tb_non_target_traversal\n' >"$BASE_DIR/round-metrics.tsv"
fi
LOCAL_VALIDATE_OVERLAY_FLAG=""
REMOTE_VALIDATE_OVERLAY_ARG=""
if [[ "$VALIDATE_OVERLAY" == "1" ]]; then
  LOCAL_VALIDATE_OVERLAY_FLAG="--validate-overlay"
  REMOTE_VALIDATE_OVERLAY_ARG="--validate-overlay"
fi
for round in $(seq 1 "$ROUNDS"); do
  ROUND_DIR="$BASE_DIR/round-$round"
  mkdir -p "$ROUND_DIR"
  POLL_INDEX=0
  CURRENT_A_POLL=""
  CURRENT_B_POLL=""
  CURRENT_RESULT=""

  CONTROL_URL="$REMOTE_CONTROL_URL"
  for _ in {1..40}; do
    curl -fsS --max-time 5 "$CONTROL_URL/health" >/dev/null 2>&1 && break
    sleep 0.25
  done
  curl -fsS --max-time 5 "$CONTROL_URL/health" >/dev/null
  # The verification control DB is shared, so every round needs a new account.
  REMOTE_EMAIL="smoke-$(date +%s)-${round}@example.com"
  REGISTER_JSON=$(curl -fsS --max-time 8 -X POST "$CONTROL_URL/api/v1/register" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$REMOTE_EMAIL\",\"password\":\"passw0rd\"}")
  TOKEN=$(printf '%s' "$REGISTER_JSON" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  if [[ -z "$TOKEN" ]]; then
    echo "[mini-air] round $round: failed to parse auth token" >&2
    exit 1
  fi

  START_MS=$(python3 -c 'import time; print(int(time.time()*1000))')

  # Daemon A on the Mini.
  LOCAL_NODE_A_CONFIG="$ROUND_DIR/node-a.json"
  LOCAL_NODE_A_DEVICE="mini-a-$RUN_ID-round-$round"
  P2WLAN_DISABLE_TUN=1 P2WLAN_TEST_RUN_ID="$RUN_ID" RUST_LOG="$HARNESS_RUST_LOG" "$DAEMON_BIN" \
    --config "$LOCAL_NODE_A_CONFIG" \
    --control "$CONTROL_URL" \
    --network "$NETWORK_ID" \
    --token "$TOKEN" \
    --device-name "$LOCAL_NODE_A_DEVICE" \
    --udp-bind 0.0.0.0:0 \
    --stun "$STUN_SERVERS" \
    --stun-timeout-ms 1000 \
    --diagnostics-bind 127.0.0.1:$DIAG_A_PORT \
    --heartbeat-interval 5 \
    $LOCAL_VALIDATE_OVERLAY_FLAG \
    >"$ROUND_DIR/node-a.log" 2>&1 &
  NODE_A_PID=$!
  LOCAL_NODE_A_PID=$NODE_A_PID

  for _ in {1..60}; do
    grep -q 'Control plane registration confirmed' "$ROUND_DIR/node-a.log" 2>/dev/null && break
    sleep 0.25
  done

  # Daemon B on the Air (fresh config every round).
  AIR_CONFIG="$REMOTE_RUN_DIR/node-b-$RUN_ID-round-$round.json"
  REMOTE_NODE_B_PID_FILE="$REMOTE_RUN_DIR/node-b-$RUN_ID-round-$round.pid"
  REMOTE_NODE_B_LOG="$REMOTE_RUN_DIR/node-b-$RUN_ID-round-$round.log"
  REMOTE_NODE_B_DEVICE="air-b-$RUN_ID-round-$round"
  # The daemon runs in the FOREGROUND of the remote session; the LOCAL ssh is
  # backgrounded and held, so the daemon can never be SIGHUP'd by a session
  # teardown race. NODE_B_PID is the local ssh pid: it stays alive exactly
  # while the remote daemon runs; the remote daemon has its own verified PID
  # file for precise teardown.
  $AIR_SSH "echo \$\$ > '$REMOTE_NODE_B_PID_FILE'; exec env P2WLAN_DISABLE_TUN=1 P2WLAN_TEST_RUN_ID='$RUN_ID' RUST_LOG='$HARNESS_RUST_LOG' '$REMOTE_DAEMON_BIN' \\
    --config '$AIR_CONFIG' \\
    --control '$CONTROL_URL' \\
    --network '$NETWORK_ID' \\
    --token '$TOKEN' \\
    --device-name '$REMOTE_NODE_B_DEVICE' \\
    --udp-bind 0.0.0.0:0 \
    --stun '$STUN_SERVERS' \
    --stun-timeout-ms 1000 \
    --diagnostics-bind 127.0.0.1:$DIAG_B_PORT \
    --heartbeat-interval 5 \
    $REMOTE_VALIDATE_OVERLAY_ARG \
     </dev/null >'$REMOTE_NODE_B_LOG' 2>&1" >/dev/null 2>&1 &
  NODE_B_PID=$!
  echo "$NODE_B_PID" >"$ROUND_DIR/node-b.pid"
  # The daemon must actually be up before the Direct wait begins (a fresh
  # config is generated on first start, which takes a beat).  Instead of a
  # fixed padding, wait for the daemon's diagnostics endpoint to answer so the
  # measured cold-start window is not inflated by a constant sleep.
  B_READY=0
  for _ in $(seq 1 40); do
    if $AIR_SSH "curl -fsS --max-time 3 http://127.0.0.1:$DIAG_B_PORT/status >/dev/null 2>&1" 2>/dev/null; then
      B_READY=1
      break
    fi
    sleep 0.25
  done
  if [[ "$B_READY" -ne 1 ]]; then
    echo "[mini-air] ROUND $round: FAIL (Air daemon diagnostics never became ready)" >&2
    overall=1
    collect_air_log || : >"$ROUND_DIR/node-b.log"
    capture_status_pair || true
    remote_daemon_cleanup || true
    kill "$NODE_B_PID" 2>/dev/null || true
    local_daemon_cleanup || true
    continue
  fi

  # The verification control plane is shared with other test nodes.  Resolve
  # this round's two independently generated identities from their own
  # diagnostics and use those exact peer IDs for every success predicate and
  # evidence counter below.  A third node's Direct path must never make this
  # Mini <-> Air round pass.
  MINI_NODE_ID=$(curl -fsS --max-time 5 "http://127.0.0.1:$DIAG_A_PORT/status" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("node_id", ""))')
  AIR_NODE_ID=$($AIR_SSH "curl -fsS --max-time 5 http://127.0.0.1:$DIAG_B_PORT/status | python3 -c 'import json,sys; print(json.load(sys.stdin).get(\"node_id\", \"\"))'")
  if [[ -z "$MINI_NODE_ID" || -z "$AIR_NODE_ID" ]]; then
    echo "[mini-air] ROUND $round: FAIL (could not resolve this round's test node IDs)" >&2
    overall=1
    remote_daemon_cleanup || true
    kill "$NODE_B_PID" 2>/dev/null || true
    local_daemon_cleanup || true
    continue
  fi

  # Real-time isolation proof before the traversal window opens: the
  # network's ACTIVE roster must be exactly this round's two nodes.  Any
  # third-party active node, a control-plane listing failure, or a proof
  # timeout aborts the run immediately as isolation-invalid — it is never
  # counted as a product failure or a PASS.
  if [[ "$ACCEPTANCE_MODE" == "strict" ]]; then
    ISOLATION_REPORT="$ROUND_DIR/isolation-prove.json"
    if python3 "$ISOLATION_HELPER" --prove "$CONTROL_URL" "$TOKEN" "$NETWORK_ID" \
      "$MINI_NODE_ID" "$AIR_NODE_ID" --deadline 25 \
      >"$ISOLATION_REPORT" 2>"$ROUND_DIR/isolation-prove.err"; then
      ISOLATION_OK=1
    else
      ISOLATION_OK=0
      echo "[mini-air] ROUND $round: ISOLATION-INVALID (network isolation proof failed); aborting run" >&2
      cat "$ISOLATION_REPORT" >&2
      record_sequence_round "$round" 0 "" ""
      collect_air_log || true
      remote_daemon_cleanup || true
      kill "$NODE_B_PID" 2>/dev/null || true
      local_daemon_cleanup || true
      redact_local_config || true
      exit 1
    fi
  else
    ISOLATION_OK=0
  fi

  # Capture both snapshots in the same poll. Compatibility accepts observable
  # Direct state only; strict mode additionally requires the owned lifecycle.
  direct_ok=0
  INFRASTRUCTURE_INVALID=0
  FUNCTIONAL_DIRECT_MS=""
  STRICT_CONVERGENCE_MS=""
  POLL_INDEX=0
  CURRENT_A_POLL=""
  CURRENT_B_POLL=""
  CURRENT_RESULT=""
  EVIDENCE_A_STATUS=""
  EVIDENCE_B_STATUS=""
  EVIDENCE_RESULT=""
  CAPTURE_WINDOW_S=$DIRECT_TIMEOUT_S
  if [[ "$ACCEPTANCE_MODE" == "strict" && "$CAPTURE_WINDOW_S" -lt 45 ]]; then
    CAPTURE_WINDOW_S=45
  fi
  for _ in $(seq 1 $((CAPTURE_WINDOW_S * 2))); do
    accepted_pair=0
    if capture_status_pair; then
      if [[ "$ACCEPTANCE_MODE" == "compat" ]]; then
        compatibility_direct_pair "$CURRENT_A_POLL" "$AIR_NODE_ID" "$CURRENT_B_POLL" "$MINI_NODE_ID" && accepted_pair=1
      else
        strict_validation_pair "$CURRENT_A_POLL" "$AIR_NODE_ID" "$CURRENT_B_POLL" "$MINI_NODE_ID" >/dev/null && accepted_pair=1
        if [[ "$accepted_pair" -eq 1 ]]; then
          # Strict acceptance is based on the daemon's committed promotion
          # event, reconstructed from the scoped snapshot timestamp and event
          # age. Transport/SSH completion time is not a traversal metric.
          promotion_ms=$(python3 - "$CURRENT_RESULT" "$START_MS" "$DIRECT_SUCCESS_TARGET_MS" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)
values = [
    side.get("key", {}).get("direct_promotion_at_ms")
    for side in (result.get("left", {}), result.get("right", {}))
]
if any(value is None for value in values):
    raise SystemExit(1)
elapsed = max(values) - int(sys.argv[2])
if elapsed < 0 or elapsed > int(sys.argv[3]):
    raise SystemExit(1)
print(elapsed)
PY
          ) || accepted_pair=0
          if [[ "$accepted_pair" -eq 1 ]]; then
            STRICT_CONVERGENCE_MS="$promotion_ms"
          fi
        fi
      fi
    fi
    if [[ "$accepted_pair" -eq 1 ]]; then
      direct_ok=1
      END_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
      if [[ "$ACCEPTANCE_MODE" == "compat" ]]; then
        FUNCTIONAL_DIRECT_MS=$((END_MS - START_MS))
      fi
      if [[ "$ACCEPTANCE_MODE" == "strict" ]]; then
        cp "$CURRENT_A_POLL" "$ROUND_DIR/strict-success-node-a.json"
        cp "$CURRENT_B_POLL" "$ROUND_DIR/strict-success-node-b.json"
        cp "$CURRENT_RESULT" "$ROUND_DIR/strict-success-result.json"
        EVIDENCE_RESULT="$ROUND_DIR/strict-success-result.json"
      fi
      EVIDENCE_A_STATUS="$CURRENT_A_POLL"
      EVIDENCE_B_STATUS="$CURRENT_B_POLL"
      break
    fi
    sleep 0.5
  done
  END_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
  ELAPSED_MS=$((END_MS - START_MS))

  # Preserve the complete Air log beside the Mini log before teardown.  A
  # failed remote copy is itself test evidence; do not silently collapse a
  # two-ended failure into a single-sided PASS/FAIL line.
  if ! collect_air_log; then
    echo "[mini-air] ROUND $round: FAIL (could not collect complete Air daemon log)" >&2
    : >"$ROUND_DIR/node-b.log"
    INFRASTRUCTURE_INVALID=1
    overall=1
    # Preserve the transport error, remote PID, daemon stderr/log, and the
    # last status attempt as infrastructure evidence rather than product
    # failure evidence.
    $AIR_SSH "printf 'remote_pid=%s\\n' \"\$(cat '$REMOTE_NODE_B_PID_FILE' 2>/dev/null || true)\"; ps -p \"\$(cat '$REMOTE_NODE_B_PID_FILE' 2>/dev/null || true)\" -o pid=,stat=,command= 2>&1; cat '$REMOTE_NODE_B_LOG' 2>&1" \
      >"$ROUND_DIR/air-infrastructure.txt" 2>"$ROUND_DIR/air-ssh-error.txt" || true
  fi

  # Preserve a failed poll separately. A failed snapshot can never replace a
  # strict-success snapshot from an earlier poll.
  STATUS_CAPTURE_OK=1
  if [[ "$direct_ok" -ne 1 ]] && ! capture_status_pair; then
    printf '{}\n' >"$ROUND_DIR/strict-last-failed-node-a.json"
    printf '{}\n' >"$ROUND_DIR/strict-last-failed-node-b.json"
    printf '{"ok":false,"reason":"status_capture_failed"}\n' >"$ROUND_DIR/strict-last-failed-result.json"
    EVIDENCE_A_STATUS="$ROUND_DIR/strict-last-failed-node-a.json"
    EVIDENCE_B_STATUS="$ROUND_DIR/strict-last-failed-node-b.json"
    EVIDENCE_RESULT="$ROUND_DIR/strict-last-failed-result.json"
    echo "[mini-air] round $round: could not collect final paired diagnostics snapshot" >&2
    STATUS_CAPTURE_OK=0
    INFRASTRUCTURE_INVALID=1
    : >"$ROUND_DIR/air-status-last-error.txt"
    cat "$ROUND_DIR/node-b.poll-$POLL_INDEX.stderr" >>"$ROUND_DIR/air-status-last-error.txt" 2>/dev/null || true
  elif [[ "$direct_ok" -ne 1 ]]; then
    cp "$CURRENT_A_POLL" "$ROUND_DIR/strict-last-failed-node-a.json"
    cp "$CURRENT_B_POLL" "$ROUND_DIR/strict-last-failed-node-b.json"
    cp "$CURRENT_RESULT" "$ROUND_DIR/strict-last-failed-result.json"
    EVIDENCE_A_STATUS="$ROUND_DIR/strict-last-failed-node-a.json"
    EVIDENCE_B_STATUS="$ROUND_DIR/strict-last-failed-node-b.json"
    EVIDENCE_RESULT="$ROUND_DIR/strict-last-failed-result.json"
  fi

  if [[ "$direct_ok" -eq 1 && "$ACCEPTANCE_MODE" == "strict" ]]; then
    EVIDENCE_A_STATUS="$ROUND_DIR/strict-success-node-a.json"
    EVIDENCE_B_STATUS="$ROUND_DIR/strict-success-node-b.json"
  fi
  if [[ -z "$EVIDENCE_RESULT" ]]; then
    EVIDENCE_RESULT="$CURRENT_RESULT"
  fi
  SNAPSHOT_POLL_INDEX="$POLL_INDEX"
  SNAPSHOT_ID=$(printf 'poll-%03d' "$SNAPSHOT_POLL_INDEX")
  SNAPSHOT_A_SHA256=$(sha256_file "$EVIDENCE_A_STATUS")
  SNAPSHOT_B_SHA256=$(sha256_file "$EVIDENCE_B_STATUS")
  SNAPSHOT_RESULT_SHA256=$(sha256_file "$EVIDENCE_RESULT")

  A_POST_DIRECT_TRAVERSAL=0
  B_POST_DIRECT_TRAVERSAL=0
  A_STRICT_VALIDATION=""
  B_STRICT_VALIDATION=""
  if [[ "$ACCEPTANCE_MODE" == "strict" ]]; then
    # Materialize the strict predicate and audit independently from the poll.
    python3 "$STRICT_PARSER" --summary "$EVIDENCE_A_STATUS" "$AIR_NODE_ID" >"$ROUND_DIR/node-a.audit.json"
    python3 "$STRICT_PARSER" --summary "$EVIDENCE_B_STATUS" "$MINI_NODE_ID" >"$ROUND_DIR/node-b.audit.json"
    python3 - "$ROUND_DIR/node-a.audit.json" "$ROUND_DIR/node-b.audit.json" "$EVIDENCE_RESULT" "$SNAPSHOT_ID" "$SNAPSHOT_POLL_INDEX" "$SNAPSHOT_A_SHA256" "$SNAPSHOT_B_SHA256" "$SNAPSHOT_RESULT_SHA256" <<'PY' >"$ROUND_DIR/round-audit.json"
import json
import sys

def load(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)

print(json.dumps({
    "mini": load(sys.argv[1]),
    "air": load(sys.argv[2]),
    "strict_pair": load(sys.argv[3]),
    "snapshot_id": sys.argv[4],
    "poll_index": int(sys.argv[5]),
    "snapshot_sha256": {
        "mini": sys.argv[6],
        "air": sys.argv[7],
        "result": sys.argv[8],
    },
}, indent=2, sort_keys=True))
PY
    A_POST_DIRECT_TRAVERSAL=$(python3 - "$ROUND_DIR/node-a.audit.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(len(json.load(stream).get("post_direct_traversal_starts", [])))
PY
)
    B_POST_DIRECT_TRAVERSAL=$(python3 - "$ROUND_DIR/node-b.audit.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(len(json.load(stream).get("post_direct_traversal_starts", [])))
PY
)
  fi

  A_DIRECT=$(count_log_events_for_peer "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" '→ direct')
  B_DIRECT=$(count_log_events_for_peer "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" '→ direct')
  A_EP=$(direct_endpoint_from_log "$ROUND_DIR/node-a.log" "$AIR_NODE_ID")
  B_EP=$(direct_endpoint_from_log "$ROUND_DIR/node-b.log" "$MINI_NODE_ID")
  A_VALIDATION_SESSIONS=$(count_stage "$EVIDENCE_A_STATUS" "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'encrypted_trial_started')
  B_VALIDATION_SESSIONS=$(count_stage "$EVIDENCE_B_STATUS" "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'encrypted_trial_started')
  A_VALIDATION_REQUESTS=$(count_stage "$EVIDENCE_A_STATUS" "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'direct_validation_request_sent')
  B_VALIDATION_REQUESTS=$(count_stage "$EVIDENCE_B_STATUS" "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'direct_validation_request_sent')
  A_VALIDATION_ACKS=$(count_stage "$EVIDENCE_A_STATUS" "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'direct_validation_ack_received')
  B_VALIDATION_ACKS=$(count_stage "$EVIDENCE_B_STATUS" "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'direct_validation_ack_received')
  A_VALIDATION_PROMOTED=$(count_stage "$EVIDENCE_A_STATUS" "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'direct_validation_promoted')
  B_VALIDATION_PROMOTED=$(count_stage "$EVIDENCE_B_STATUS" "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'direct_validation_promoted')
  A_PATH_PROMOTIONS=$(count_log_events_for_peer "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'event=\\"direct_path_promoted\\"|direct_path_promoted')
  B_PATH_PROMOTIONS=$(count_log_events_for_peer "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'event=\\"direct_path_promoted\\"|direct_path_promoted')
  A_NON_TARGET_TRAVERSAL=$(count_non_target_traversal_activity "$ROUND_DIR/node-a.log" "$AIR_NODE_ID")
  B_NON_TARGET_TRAVERSAL=$(count_non_target_traversal_activity "$ROUND_DIR/node-b.log" "$MINI_NODE_ID")
  A_NON_TARGET_OFFERS=$(count_non_target_peer_events "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'offer')
  B_NON_TARGET_OFFERS=$(count_non_target_peer_events "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'offer')
  A_NON_TARGET_PROBES=$(count_non_target_peer_events "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'probe|punch')
  B_NON_TARGET_PROBES=$(count_non_target_peer_events "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'probe|punch')
  A_NON_TARGET_VALIDATIONS=$(count_non_target_peer_events "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'direct_validation|encrypted_trial')
  B_NON_TARGET_VALIDATIONS=$(count_non_target_peer_events "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'direct_validation|encrypted_trial')
  if [[ "$ACCEPTANCE_MODE" == "strict" ]]; then
    A_STRICT_VALIDATION=0
    B_STRICT_VALIDATION=0
    if [[ "$direct_ok" -eq 1 && -f "$ROUND_DIR/strict-success-result.json" ]]; then
      strict_validation_session "$EVIDENCE_A_STATUS" "$AIR_NODE_ID" >"$ROUND_DIR/node-a.strict.json" && A_STRICT_VALIDATION=1 || true
      strict_validation_session "$EVIDENCE_B_STATUS" "$MINI_NODE_ID" >"$ROUND_DIR/node-b.strict.json" && B_STRICT_VALIDATION=1 || true
    else
      printf '{"ok":false,"reason":"no_strict_success_snapshot"}\n' >"$ROUND_DIR/node-a.strict.json"
      printf '{"ok":false,"reason":"no_strict_success_snapshot"}\n' >"$ROUND_DIR/node-b.strict.json"
    fi
  else
    python3 - "$EVIDENCE_A_STATUS" "$AIR_NODE_ID" "$EVIDENCE_B_STATUS" "$MINI_NODE_ID" <<'PY' >"$ROUND_DIR/round-audit.json"
import json
import sys

print(json.dumps({
    "acceptance_mode": "compat",
    "classification": "functional_direct_baseline",
    "mini_peer_id": sys.argv[2],
    "air_peer_id": sys.argv[4],
    "mini_endpoint": next((p.get("selected_pair", p.get("current_direct_pair", {})).get("remote_endpoint") for p in json.load(open(sys.argv[1])).get("peers", []) if p.get("node_id") == sys.argv[2]), ""),
    "air_endpoint": next((p.get("selected_pair", p.get("current_direct_pair", {})).get("remote_endpoint") for p in json.load(open(sys.argv[3])).get("peers", []) if p.get("node_id") == sys.argv[4]), ""),
}, indent=2, sort_keys=True))
PY
  fi
  A_EP=$(status_endpoint_from_json "$EVIDENCE_A_STATUS" "$AIR_NODE_ID" 2>/dev/null || true)
  B_EP=$(status_endpoint_from_json "$EVIDENCE_B_STATUS" "$MINI_NODE_ID" 2>/dev/null || true)
  SNAPSHOT_POLL_INDEX="$POLL_INDEX"
  SNAPSHOT_A_SHA256=$(sha256_file "$EVIDENCE_A_STATUS")
  SNAPSHOT_B_SHA256=$(sha256_file "$EVIDENCE_B_STATUS")
  SNAPSHOT_RESULT_SHA256=$(sha256_file "$EVIDENCE_RESULT")
  if [[ "$ACCEPTANCE_MODE" == "strict" ]]; then
    python3 - "$EVIDENCE_RESULT" "$ROUND_DIR/strict-validation-final.json" "$SNAPSHOT_ID" "$SNAPSHOT_POLL_INDEX" "$SNAPSHOT_A_SHA256" "$SNAPSHOT_B_SHA256" "$SNAPSHOT_RESULT_SHA256" <<'PY'
import json
import os
import sys

source, destination, snapshot_id, poll_index, mini_sha, air_sha, result_sha = sys.argv[1:]
with open(source, encoding="utf-8") as stream:
    value = json.load(stream)
value["snapshot_id"] = snapshot_id
value["poll_index"] = int(poll_index)
value["snapshot_sha256"] = {
    "mini": mini_sha,
    "air": air_sha,
    "result": result_sha,
}
tmp = destination + ".tmp"
with open(tmp, "w", encoding="utf-8") as stream:
    json.dump(value, stream, indent=2, sort_keys=True)
    stream.write("\n")
os.replace(tmp, destination)
PY
  fi
  A_MATCHED_ACKS=$(count_log_events_for_peer "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'candidate_pair_probe_succeeded|received authenticated UDP punch ACK|received UDP punch ACK')
  B_MATCHED_ACKS=$(count_log_events_for_peer "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'candidate_pair_probe_succeeded|received authenticated UDP punch ACK|received UDP punch ACK')
  A_OVERLAY_ROUND_TRIPS=0
  B_OVERLAY_ROUND_TRIPS=0
  overlay_ok=1
  if [[ "$VALIDATE_OVERLAY" == "1" ]]; then
    overlay_ok=0
    for _ in $(seq 1 $((OVERLAY_TIMEOUT_S * 2))); do
      A_OVERLAY_ROUND_TRIPS=$(log_reports_overlay_round_trip "$ROUND_DIR/node-a.log" "$AIR_NODE_ID")
      if ! $AIR_SSH "cat '$REMOTE_NODE_B_LOG'" >"$ROUND_DIR/node-b.log"; then
        break
      fi
      B_OVERLAY_ROUND_TRIPS=$(log_reports_overlay_round_trip "$ROUND_DIR/node-b.log" "$MINI_NODE_ID")
      if [[ "$A_OVERLAY_ROUND_TRIPS" -gt 0 && "$B_OVERLAY_ROUND_TRIPS" -gt 0 ]]; then
        overlay_ok=1
        break
      fi
      sleep 0.5
    done
  fi
  A_HTTP_429=$(count_log_events "$ROUND_DIR/node-a.log" 'HTTP 429|status.?429|429 Too Many')
  B_HTTP_429=$(count_log_events "$ROUND_DIR/node-b.log" 'HTTP 429|status.?429|429 Too Many')
  A_RELAY_HEDGES=$(count_log_events "$ROUND_DIR/node-a.log" 'relay_hedged=true')
  B_RELAY_HEDGES=$(count_log_events "$ROUND_DIR/node-b.log" 'relay_hedged=true')
  A_RELAY_FALLBACKS=$(count_log_events "$ROUND_DIR/node-a.log" 'relay_fallback_selected')
  B_RELAY_FALLBACKS=$(count_log_events "$ROUND_DIR/node-b.log" 'relay_fallback_selected')
  A_RELAY_SELECTIONS=$(count_log_events_insensitive "$ROUND_DIR/node-a.log" 'selected relay region')
  B_RELAY_SELECTIONS=$(count_log_events_insensitive "$ROUND_DIR/node-b.log" 'selected relay region')
  A_CRASH_PANIC=$(count_log_events_insensitive "$ROUND_DIR/node-a.log" 'panic|fatal runtime error|thread .* panicked')
  B_CRASH_PANIC=$(count_log_events_insensitive "$ROUND_DIR/node-b.log" 'panic|fatal runtime error|thread .* panicked')
  if [[ "$ACCEPTANCE_MODE" == "compat" ]]; then
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$round" "$ACCEPTANCE_MODE" "$FUNCTIONAL_DIRECT_MS" "$ELAPSED_MS" "$A_EP" "$B_EP" "$A_CRASH_PANIC" "$B_CRASH_PANIC" \
      >>"$BASE_DIR/round-metrics.tsv"
    {
      echo "round=$round acceptance_mode=compat classification=functional_direct_baseline functional_direct_ms=$FUNCTIONAL_DIRECT_MS elapsed_ms=$ELAPSED_MS"
      echo "network_id=$NETWORK_ID"
      echo "mini_node_id=$MINI_NODE_ID air_node_id=$AIR_NODE_ID"
      echo "a_endpoint=$A_EP b_endpoint=$B_EP"
      echo "a_crash_panic=$A_CRASH_PANIC b_crash_panic=$B_CRASH_PANIC"
      echo "isolation_prove=$ROUND_DIR/isolation-prove.json isolation_delete=$ROUND_DIR/isolation-delete.json isolation_cleaned=$ROUND_DIR/isolation-cleaned.json"
      echo "round_audit=$ROUND_DIR/round-audit.json"
      echo "snapshot_id=$SNAPSHOT_ID snapshot_poll_index=$SNAPSHOT_POLL_INDEX"
      echo "snapshot_a_sha256=$SNAPSHOT_A_SHA256 snapshot_b_sha256=$SNAPSHOT_B_SHA256 snapshot_result_sha256=$SNAPSHOT_RESULT_SHA256"
    } >"$ROUND_DIR/metrics.env"
  else
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$round" "$ACCEPTANCE_MODE" "$FUNCTIONAL_DIRECT_MS" "$STRICT_CONVERGENCE_MS" "$ELAPSED_MS" "$A_DIRECT" "$B_DIRECT" "$A_EP" "$B_EP" \
      "$A_VALIDATION_SESSIONS" "$B_VALIDATION_SESSIONS" \
      "$A_VALIDATION_REQUESTS" "$B_VALIDATION_REQUESTS" \
      "$A_VALIDATION_ACKS" "$B_VALIDATION_ACKS" \
      "$A_VALIDATION_PROMOTED" "$B_VALIDATION_PROMOTED" \
      "$A_STRICT_VALIDATION" "$B_STRICT_VALIDATION" \
      "$A_MATCHED_ACKS" "$B_MATCHED_ACKS" "$A_OVERLAY_ROUND_TRIPS" "$B_OVERLAY_ROUND_TRIPS" "$A_HTTP_429" "$B_HTTP_429" \
      "$A_RELAY_HEDGES" "$B_RELAY_HEDGES" \
      "$A_RELAY_FALLBACKS" "$B_RELAY_FALLBACKS" \
      "$A_RELAY_SELECTIONS" "$B_RELAY_SELECTIONS" "$A_CRASH_PANIC" "$B_CRASH_PANIC" \
      "$A_POST_DIRECT_TRAVERSAL" "$B_POST_DIRECT_TRAVERSAL" \
      "$A_NON_TARGET_TRAVERSAL" "$B_NON_TARGET_TRAVERSAL" >>"$BASE_DIR/round-metrics.tsv"
    {
      echo "round=$round acceptance_mode=strict strict_convergence_ms=$STRICT_CONVERGENCE_MS elapsed_ms=$ELAPSED_MS"
    echo "network_id=$NETWORK_ID"
    echo "mini_node_id=$MINI_NODE_ID air_node_id=$AIR_NODE_ID"
    echo "a_endpoint=$A_EP b_endpoint=$B_EP"
    echo "a_validation_sessions=$A_VALIDATION_SESSIONS b_validation_sessions=$B_VALIDATION_SESSIONS"
    echo "a_validation_requests=$A_VALIDATION_REQUESTS b_validation_requests=$B_VALIDATION_REQUESTS"
    echo "a_validation_acks=$A_VALIDATION_ACKS b_validation_acks=$B_VALIDATION_ACKS"
    echo "a_validation_promoted=$A_VALIDATION_PROMOTED b_validation_promoted=$B_VALIDATION_PROMOTED"
    echo "a_strict_validation=$A_STRICT_VALIDATION b_strict_validation=$B_STRICT_VALIDATION"
    echo "a_matched_acks=$A_MATCHED_ACKS b_matched_acks=$B_MATCHED_ACKS"
    echo "a_overlay_round_trips=$A_OVERLAY_ROUND_TRIPS b_overlay_round_trips=$B_OVERLAY_ROUND_TRIPS"
    echo "a_http_429=$A_HTTP_429 b_http_429=$B_HTTP_429"
    echo "a_relay_hedges=$A_RELAY_HEDGES b_relay_hedges=$B_RELAY_HEDGES"
    echo "a_relay_fallbacks=$A_RELAY_FALLBACKS b_relay_fallbacks=$B_RELAY_FALLBACKS"
    echo "a_relay_selections=$A_RELAY_SELECTIONS b_relay_selections=$B_RELAY_SELECTIONS"
    echo "a_crash_panic=$A_CRASH_PANIC b_crash_panic=$B_CRASH_PANIC"
    echo "a_post_direct_traversal=$A_POST_DIRECT_TRAVERSAL b_post_direct_traversal=$B_POST_DIRECT_TRAVERSAL"
    echo "a_non_target_traversal=$A_NON_TARGET_TRAVERSAL b_non_target_traversal=$B_NON_TARGET_TRAVERSAL"
    echo "a_non_target_offers=$A_NON_TARGET_OFFERS b_non_target_offers=$B_NON_TARGET_OFFERS"
    echo "a_non_target_probes=$A_NON_TARGET_PROBES b_non_target_probes=$B_NON_TARGET_PROBES"
    echo "a_non_target_validations=$A_NON_TARGET_VALIDATIONS b_non_target_validations=$B_NON_TARGET_VALIDATIONS"
    echo "isolation_prove=$ROUND_DIR/isolation-prove.json isolation_delete=$ROUND_DIR/isolation-delete.json isolation_cleaned=$ROUND_DIR/isolation-cleaned.json"
    echo "round_audit=$ROUND_DIR/round-audit.json"
    echo "snapshot_id=$SNAPSHOT_ID snapshot_poll_index=$SNAPSHOT_POLL_INDEX"
    echo "snapshot_a_sha256=$SNAPSHOT_A_SHA256 snapshot_b_sha256=$SNAPSHOT_B_SHA256 snapshot_result_sha256=$SNAPSHOT_RESULT_SHA256"
    } >"$ROUND_DIR/metrics.env"
  fi

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
    grep -F -- "$AIR_NODE_ID" "$ROUND_DIR/node-a.log" | grep -E 'candidate_pair_probe_succeeded|direct_validation|peer_reflexive' | grep -v Aborting | head -6
    echo "== B: matched ACKs / peer-reflexive / validation =="
    grep -F -- "$MINI_NODE_ID" "$ROUND_DIR/node-b.log" | grep -E 'candidate_pair_probe_succeeded|direct_validation|peer_reflexive' | grep -v Aborting | head -6
    echo "== A promotion =="
    grep -F -- "$AIR_NODE_ID" "$ROUND_DIR/node-a.log" | grep -E 'direct_path_promoted|candidate_pair_selected' | head -2
    echo "== B promotion =="
    grep -F -- "$MINI_NODE_ID" "$ROUND_DIR/node-b.log" | grep -E 'direct_path_promoted|candidate_pair_selected' | head -2
    if [[ "$VALIDATE_OVERLAY" == "1" ]]; then
      echo "== A encrypted overlay payload =="
      grep -F -- "$AIR_NODE_ID" "$ROUND_DIR/node-a.log" | grep 'overlay_payload_verified' | head -2
      echo "== B encrypted overlay payload =="
      grep -F -- "$MINI_NODE_ID" "$ROUND_DIR/node-b.log" | grep 'overlay_payload_verified' | head -2
    fi
    echo "== per-round metrics =="
    cat "$ROUND_DIR/metrics.env"
    echo "== A relay hedge/fallback/selection =="
    grep -h -i -E 'relay_hedged=true|relay_fallback_selected|selected relay region' "$ROUND_DIR/node-a.log" | head -4
    echo "== B relay hedge/fallback/selection =="
    grep -h -i -E 'relay_hedged=true|relay_fallback_selected|selected relay region' "$ROUND_DIR/node-b.log" | head -4
    if [[ "$ACCEPTANCE_MODE" == "strict" ]]; then
      echo "== network isolation proof =="
      cat "$ROUND_DIR/isolation-prove.json" 2>/dev/null || echo "isolation-prove.json missing"
      echo "== device cleanup proof =="
      cat "$ROUND_DIR/isolation-delete.json" 2>/dev/null || echo "isolation-delete.json missing"
      cat "$ROUND_DIR/isolation-cleaned.json" 2>/dev/null || echo "isolation-cleaned.json missing"
    fi
  } >"$ROUND_DIR/evidence.log" 2>&1 || true

  MINI_ALIVE=1
  AIR_ALIVE=1
  if ! kill -0 "$NODE_A_PID" 2>/dev/null; then
    MINI_ALIVE=0
    echo "[mini-air] ROUND $round: FAIL (Mini daemon exited unexpectedly)"
  fi
  if ! remote_daemon_matches; then
    AIR_ALIVE=0
    echo "[mini-air] ROUND $round: FAIL (Air daemon exited unexpectedly)"
  fi

  round_ok=0
  if [[ "$ACCEPTANCE_MODE" == "compat" ]] && \
     [[ "$INFRASTRUCTURE_INVALID" -eq 0 ]] && \
     [[ "$direct_ok" -eq 1 ]] && [[ "$STATUS_CAPTURE_OK" -eq 1 ]] && \
     [[ "$A_CRASH_PANIC" -eq 0 ]] && [[ "$B_CRASH_PANIC" -eq 0 ]] && \
     is_public_ipv4_endpoint "$A_EP" && is_public_ipv4_endpoint "$B_EP" && \
     [[ -n "$FUNCTIONAL_DIRECT_MS" ]] && \
     [[ "$MINI_ALIVE" -eq 1 ]] && [[ "$AIR_ALIVE" -eq 1 ]]; then
    round_ok=1
  elif [[ "$ACCEPTANCE_MODE" == "strict" ]] && \
     [[ "$INFRASTRUCTURE_INVALID" -eq 0 ]] && \
     [[ "$direct_ok" -eq 1 ]] && [[ "$STATUS_CAPTURE_OK" -eq 1 ]] && \
     [[ "$A_STRICT_VALIDATION" -eq 1 ]] && [[ "$B_STRICT_VALIDATION" -eq 1 ]] && \
     [[ "$A_VALIDATION_PROMOTED" -gt 0 ]] && [[ "$B_VALIDATION_PROMOTED" -gt 0 ]] && \
     [[ "$A_PATH_PROMOTIONS" -gt 0 ]] && [[ "$B_PATH_PROMOTIONS" -gt 0 ]] && \
     [[ "$A_CRASH_PANIC" -eq 0 ]] && [[ "$B_CRASH_PANIC" -eq 0 ]] && \
     [[ "$A_HTTP_429" -eq 0 ]] && [[ "$B_HTTP_429" -eq 0 ]] && \
     [[ "$A_POST_DIRECT_TRAVERSAL" -eq 0 ]] && [[ "$B_POST_DIRECT_TRAVERSAL" -eq 0 ]] && \
     [[ "$A_NON_TARGET_TRAVERSAL" -eq 0 ]] && [[ "$B_NON_TARGET_TRAVERSAL" -eq 0 ]] && \
     [[ "$overlay_ok" -eq 1 ]] && is_public_ipv4_endpoint "$A_EP" && \
     is_public_ipv4_endpoint "$B_EP" && [[ "$STRICT_CONVERGENCE_MS" -le "$DIRECT_SUCCESS_TARGET_MS" ]] && \
     [[ "$MINI_ALIVE" -eq 1 ]] && [[ "$AIR_ALIVE" -eq 1 ]]; then
    round_ok=1
  fi
  record_sequence_round "$round" "$round_ok" "$FUNCTIONAL_DIRECT_MS" "$STRICT_CONVERGENCE_MS"
  if [[ "$round_ok" -eq 1 ]]; then
    if [[ "$ACCEPTANCE_MODE" == "compat" ]]; then
      echo "[mini-air] ROUND $round: FUNCTIONAL-DIRECT baseline functional_direct_ms=$FUNCTIONAL_DIRECT_MS a_ep=$A_EP b_ep=$B_EP evidence=$ROUND_DIR/evidence.log"
    else
      echo "[mini-air] ROUND $round: PASS strict_convergence_ms=$STRICT_CONVERGENCE_MS a_ep=$A_EP b_ep=$B_EP evidence=$ROUND_DIR/evidence.log"
    fi
  else
    if [[ "$ACCEPTANCE_MODE" == "compat" ]]; then
      echo "[mini-air] ROUND $round: FUNCTIONAL-DIRECT baseline incomplete a_direct=$A_DIRECT b_direct=$B_DIRECT elapsed_ms=$ELAPSED_MS a_ep=$A_EP b_ep=$B_EP evidence=$ROUND_DIR/evidence.log"
    else
      echo "[mini-air] ROUND $round: NO-DIRECT-or-nonpublic-path a_direct=$A_DIRECT b_direct=$B_DIRECT elapsed_ms=$ELAPSED_MS a_ep=$A_EP b_ep=$B_EP evidence=$ROUND_DIR/evidence.log"
    fi
    overall=1
    # Strict acceptance gets a full evidence window for later regression
    # gates. Compatibility has no lifecycle gate, so its timeout is enough.
    if [[ "$ACCEPTANCE_MODE" == "strict" ]]; then
      FAILURE_CAPTURE_DEADLINE_MS=$((START_MS + 45000))
      while :; do
        NOW_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
        [[ "$NOW_MS" -ge "$FAILURE_CAPTURE_DEADLINE_MS" ]] && break
        sleep 0.5
      done
    fi
    if capture_status_pair; then
      cp "$CURRENT_A_POLL" "$ROUND_DIR/teardown-node-a.json"
      cp "$CURRENT_B_POLL" "$ROUND_DIR/teardown-node-b.json"
      cp "$CURRENT_RESULT" "$ROUND_DIR/teardown-strict-result.json"
    else
      printf '{}\n' >"$ROUND_DIR/teardown-node-a.json"
      printf '{}\n' >"$ROUND_DIR/teardown-node-b.json"
      printf '{"ok":false,"reason":"status_capture_failed"}\n' >"$ROUND_DIR/teardown-strict-result.json"
    fi
    collect_air_log || true
  fi

  # Teardown. NODE_B_PID is the local ssh pid; the remote daemon is signalled
  # only through this round's verified PID file.
  remote_daemon_cleanup || true
  kill "$NODE_B_PID" 2>/dev/null || true
  local_daemon_cleanup || true
  redact_local_config || true

  # Delete this round's two devices so the next round starts on a clean
  # roster, then prove the network is clean again (no active nodes).  Deletion
  # is matched by the run-scoped device names, so it also covers early-failure
  # paths where the diagnostics node IDs were never resolved.  A cleanup leak
  # or third-party activity during cleanup aborts the run: the following
  # rounds would start on a polluted network and their verdicts would be
  # meaningless.
  CLEANUP_OK=1
  DELETED_IDS=()
  if python3 "$ISOLATION_HELPER" --delete-by-name "$CONTROL_URL" "$TOKEN" "$NETWORK_ID" \
    "$LOCAL_NODE_A_DEVICE" "$REMOTE_NODE_B_DEVICE" \
    >"$ROUND_DIR/isolation-delete.json" 2>"$ROUND_DIR/isolation-delete.err"; then
    DELETED_IDS=$(python3 - "$ROUND_DIR/isolation-delete.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(" ".join(json.load(stream).get("deleted_ids", [])))
PY
)
  else
    echo "[mini-air] ROUND $round: FAIL (device cleanup failed); aborting run" >&2
    cat "$ROUND_DIR/isolation-delete.json" >&2
    CLEANUP_OK=0
    overall=1
  fi
  if [[ -n "$DELETED_IDS" ]] && ! python3 "$ISOLATION_HELPER" --prove-cleaned \
    "$CONTROL_URL" "$TOKEN" "$NETWORK_ID" $DELETED_IDS --deadline 15 \
    >"$ROUND_DIR/isolation-cleaned.json" 2>>"$ROUND_DIR/isolation-delete.err"; then
    echo "[mini-air] ROUND $round: FAIL (network not clean after device deletion); aborting run" >&2
    cat "$ROUND_DIR/isolation-cleaned.json" >&2
    CLEANUP_OK=0
    overall=1
  fi
  if [[ "$CLEANUP_OK" -ne 1 ]]; then
    exit 1
  fi
  sleep 0.5
done

echo "[mini-air] base dir: $BASE_DIR"
echo "[mini-air] round metrics: $BASE_DIR/round-metrics.tsv"
echo "[mini-air] RESULT: $([ "$overall" -eq 0 ] && echo PASS || echo FAIL)"
exit $overall
