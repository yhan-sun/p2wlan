#!/usr/bin/env bash
# Stable CI entry point for the deterministic NAT simulator.
#
# Each topology profile has one authoritative attempt. A follow-up diagnostic
# run is not allowed to erase a business-validation failure, and readiness
# failures remain failures unless positive pre-business infrastructure
# evidence is available. Every attempt is recorded next to its evidence.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SMOKE="$ROOT_DIR/scripts/nat-sim/nat-sim-smoke.sh"
PROFILE=${1:-unit}
RUN_ID=${GITHUB_RUN_ID:-local-$$}
RUN_ATTEMPT=${GITHUB_RUN_ATTEMPT:-1}
REPLICA=${NAT_TOPOLOGY_REPLICA:-1}
EXPECTED_HEAD_SHA=${NAT_TOPOLOGY_HEAD_SHA:-}
ARTIFACT_PARENT=${NAT_TOPOLOGY_ARTIFACT_ROOT:-${RUNNER_TEMP:-/tmp}}
ARTIFACT_DIR="$ARTIFACT_PARENT/p2wlan-nat-topology-${RUN_ID}-${RUN_ATTEMPT}-${PROFILE}-${REPLICA}"
RUN_NAME="nat-ci-${PROFILE}-${RUN_ID}-${RUN_ATTEMPT}-${REPLICA}"

if ! [[ "$REPLICA" =~ ^[1-9][0-9]*$ ]]; then
  echo "[nat-ci] NAT_TOPOLOGY_REPLICA must be a positive integer" >&2
  exit 2
fi
if [[ -n "$EXPECTED_HEAD_SHA" ]]; then
  ACTUAL_HEAD_SHA=$(git -C "$ROOT_DIR" rev-parse HEAD)
  if [[ "$ACTUAL_HEAD_SHA" != "$EXPECTED_HEAD_SHA" ]]; then
    echo "[nat-ci] exact Head mismatch expected=$EXPECTED_HEAD_SHA actual=$ACTUAL_HEAD_SHA replica=$REPLICA" >&2
    exit 2
  fi
else
  ACTUAL_HEAD_SHA=$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)
fi
WORKFLOW_SHA=$(git -C "$ROOT_DIR" rev-parse "$ACTUAL_HEAD_SHA:.github/workflows/nat-topology-gate.yml")

mkdir -p "$ARTIFACT_PARENT"

TIMEOUT_BIN=$(command -v timeout || command -v gtimeout || true)
if [[ -z "$TIMEOUT_BIN" ]]; then
  # CI runners always provide GNU timeout; this fallback only covers local
  # development hosts (e.g. macOS without coreutils) and is announced loudly.
  echo "[nat-ci] WARNING: GNU timeout not found; running without the 20m hang guard (local development only)" >&2
fi

run_smoke() {
  local expected=$1 attempt_dir=$2 attempt_log=$3
  shift 3
  local status

  if [[ -e "$attempt_dir" || -e "$attempt_log" ]]; then
    echo "[nat-ci] refusing to reuse artifact path: $attempt_dir" >&2
    exit 2
  fi

  set +e
  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" --signal=TERM --kill-after=30s 20m \
      env \
        NETWORK_ID=default \
        ROUNDS=1 \
        NAT_SEED_BASE=20260828 \
        NAT_SIM_RUN_ID="$RUN_NAME" \
        NAT_TOPOLOGY_HEAD_SHA="$ACTUAL_HEAD_SHA" \
        NAT_TOPOLOGY_WORKFLOW_SHA="$WORKFLOW_SHA" \
        NAT_TOPOLOGY_REPLICA="$REPLICA" \
        NAT_SIM_ARTIFACT_DIR="$attempt_dir" \
        "$@" \
        bash "$SMOKE" 2>&1 | tee "$attempt_log"
  else
    env \
      NETWORK_ID=default \
      ROUNDS=1 \
      NAT_SEED_BASE=20260828 \
      NAT_SIM_RUN_ID="$RUN_NAME" \
      NAT_TOPOLOGY_HEAD_SHA="$ACTUAL_HEAD_SHA" \
      NAT_TOPOLOGY_WORKFLOW_SHA="$WORKFLOW_SHA" \
      NAT_TOPOLOGY_REPLICA="$REPLICA" \
      NAT_SIM_ARTIFACT_DIR="$attempt_dir" \
      "$@" \
      bash "$SMOKE" 2>&1 | tee "$attempt_log"
  fi
  status=${PIPESTATUS[0]}
  set -e

  if [[ "$expected" == success ]]; then
    if [[ "$status" -ne 0 ]]; then
      echo "[nat-ci] profile=$PROFILE failed status=$status log=$attempt_log artifacts=$attempt_dir" >&2
      return "$status"
    fi
    echo "[nat-ci] profile=$PROFILE PASS log=$attempt_log artifacts=$attempt_dir"
    return 0
  fi

  if [[ "$status" -eq 0 ]]; then
    echo "[nat-ci] profile=$PROFILE unexpectedly succeeded" >&2
    return 1
  fi
  if ! grep -Eq 'reason_code=status_(http_500_injected|unavailable|schema_invalid|auth_token_missing)' "$attempt_log"; then
    echo "[nat-ci] profile=$PROFILE failed without the expected fail-closed reason" >&2
    return 1
  fi
  echo "[nat-ci] profile=$PROFILE PASS expected_failure_status=$status"
}

write_attempt_manifest() {
  local attempt_dir="$1" attempt_log="$2" exit_code="$3" topology="$4" classification_path="$5"
  local output_dir="$attempt_dir/round-1"
  local manifest_path="$attempt_dir/nat-attempts.json"
  if [[ -d "$output_dir" ]]; then manifest_path="$output_dir/nat-attempts.json"; fi
  mkdir -p "$(dirname "$manifest_path")"
  python3 - "$attempt_dir" "$attempt_log" "$exit_code" "$topology" "$REPLICA" \
    "$ACTUAL_HEAD_SHA" "$WORKFLOW_SHA" "$classification_path" "$manifest_path" <<'PY'
import json
import re
import sys
from pathlib import Path

attempt_dir, log_path, exit_text, topology, replica_text, head_sha, workflow_sha, classification_path, manifest_path = sys.argv[1:]
root = Path(attempt_dir)
manifest = Path(manifest_path)
round_dir = manifest.parent
evidence = round_dir / "nat-evidence.json"
marker = round_dir / "business-validation.started"
readiness = sorted(path.name for path in round_dir.glob("*.readiness.json"))
try:
    log = Path(log_path).read_text(encoding="utf-8", errors="replace")
except OSError:
    log = ""
reason_codes = list(dict.fromkeys(re.findall(r"(?:^|\s)reason_code=([A-Za-z0-9_]+)", log)))
exit_code = int(exit_text)
if exit_code == 0:
    classification = {"retryable": False, "reason": "accepted"}
else:
    try:
        classification = json.loads(Path(classification_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        classification = {"retryable": False, "reason": "classification_unavailable"}
scenario_id = f"{topology}:replica-{int(replica_text)}:round-1"
record = {
    "schema_version": 1,
    "scenario_id": scenario_id,
    "source_head_sha": head_sha,
    "workflow_sha": workflow_sha,
    "attempts": [
        {
            "attempt": 1,
            "exit_code": exit_code,
            "business_validation_started": marker.is_file(),
            "reason_codes": reason_codes,
            "evidence_path": "nat-evidence.json" if evidence.is_file() else None,
            "readiness_paths": readiness,
            "classification": {
                "retryable": classification.get("retryable") is True,
                "reason": str(classification.get("reason", "classification_unavailable")),
            },
            "infrastructure_evidence": None,
        }
    ],
    "final_adjudication": {
        "result": "pass" if exit_code == 0 else "fail",
        "attempt": 1,
        "reason_code": None if exit_code == 0 else str(classification.get("reason", "attempt_failed")),
    },
}
manifest.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(record["final_adjudication"], sort_keys=True))
PY
}

run_single_attempt() {
  local attempt_dir="${ARTIFACT_DIR}-attempt-1"
  local attempt_log="${attempt_dir}.log"
  local topology classification_path evidence_path marker rc classification_status
  local -a readiness_args=()
  case "$PROFILE" in
    direct) topology=direct-cold-start ;;
    relay) topology=relay-blackhole ;;
    *) echo "unsupported attempt profile=$PROFILE" >&2; return 2 ;;
  esac
  classification_path="$attempt_dir/retry-classification.json"
  evidence_path="$attempt_dir/round-1/nat-evidence.json"
  marker="$attempt_dir/round-1/business-validation.started"

  rc=0
  run_smoke success "$attempt_dir" "$attempt_log" "$@" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    for readiness_file in "$attempt_dir"/round-1/*.readiness.json; do
      [[ -f "$readiness_file" ]] && readiness_args+=(--readiness "$readiness_file")
    done
    classification_status=0
    python3 "$ROOT_DIR/scripts/nat-sim/transient.py" classify \
      --profile "$topology" \
      --log "$attempt_log" \
      --evidence "$evidence_path" \
      --business-started "$marker" \
      --attempt 1 \
      --output "$classification_path" \
      "${readiness_args[@]}" || classification_status=$?
    echo "[nat-ci] profile=$PROFILE failure classification_exit=$classification_status record=$classification_path" >&2
  fi

  write_attempt_manifest "$attempt_dir" "$attempt_log" "$rc" "$topology" "$classification_path"
  local first_attempt_pass=0 final_failures=1
  if [[ "$rc" -eq 0 ]]; then first_attempt_pass=1; final_failures=0; fi
  echo "[nat-ci] profile=$PROFILE attempt_stats first_attempt_pass=$first_attempt_pass diagnostic_retries=0 recovery_count=0 final_failure_count=$final_failures"
  return "$rc"
}

case "$PROFILE" in
  unit)
    bash -n "$SMOKE"
    bash -n "$0"
    python3 -m unittest discover \
      -s "$ROOT_DIR/scripts/nat-sim" \
      -p 'test_nat_sim.py' \
      -v 2>&1 | tee "${ARTIFACT_DIR}-attempt-1.log"
    ;;
  direct)
    run_single_attempt \
      MODE=direct \
      STEP_A=1 STEP_B=1 \
      CONSUME_A=0 CONSUME_B=0 \
      LOSS=0 REORDER=0 STRICT_FILTERING=0 \
      DIRECT_TIMEOUT_S=90 \
      OVERLAY_TIMEOUT_S=60 \
      OVERLAY_BURST=32
    ;;
  relay)
    run_single_attempt \
      MODE=relay-only \
      STEP_A=1 STEP_B=1 \
      CONSUME_A=0 CONSUME_B=0 \
      LOSS=0 REORDER=0 STRICT_FILTERING=0 \
      DIRECT_TIMEOUT_S=60 \
      OVERLAY_TIMEOUT_S=90 \
      OVERLAY_BURST=64 \
      RELAY_COUNT=1
    ;;
  fail-closed)
    # Expected-failure profile: never retried, its verdict is the failure.
    run_smoke failure \
      "${ARTIFACT_DIR}-attempt-1" \
      "${ARTIFACT_DIR}-attempt-1.log" \
      MODE=relay-only \
      STEP_A=1 STEP_B=1 \
      CONSUME_A=0 CONSUME_B=0 \
      LOSS=0 REORDER=0 STRICT_FILTERING=0 \
      DIRECT_TIMEOUT_S=60 \
      OVERLAY_TIMEOUT_S=90 \
      OVERLAY_BURST=16 \
      RELAY_COUNT=1 \
      STATUS_FAILURE_INJECTION=1
    ;;
  *)
    echo "usage: $0 {unit|direct|relay|fail-closed}" >&2
    exit 2
    ;;
esac
