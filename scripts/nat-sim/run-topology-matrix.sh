#!/usr/bin/env bash
# Named, deterministic profiles for the existing dual-NAT smoke harness.
#
# This runner does not emulate real phones, carrier NATs, or OS network
# hand-offs. It gives CI a stable contract around the deterministic simulator:
# every scenario has an explicit topology, expected outcome, isolated ports,
# and an evidence directory that can be uploaded after a failure.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SMOKE="$ROOT_DIR/scripts/nat-sim/nat-sim-smoke.sh"
PROFILE=${1:-pr}
ARTIFACT_ROOT=${NAT_TOPOLOGY_ARTIFACT_ROOT:-${RUNNER_TEMP:-/tmp}/p2wlan-nat-topology-${GITHUB_RUN_ID:-$$}-${GITHUB_RUN_ATTEMPT:-1}}
ROUNDS=${NAT_TOPOLOGY_ROUNDS:-1}

usage() {
  cat <<'EOF'
Usage: scripts/nat-sim/run-topology-matrix.sh <profile-or-scenario>

Profiles:
  unit       Python simulator unit tests and shell contract checks only
  pr         direct-baseline + relay-blackhole
  extended   all deterministic success and fail-closed scenarios

Scenarios:
  direct-baseline, strict-hard, reordered-lossy, relay-blackhole,
  relay-restart, relay-failover, status-failclosed, metrics-failclosed,
  schema-failclosed

Set NAT_TOPOLOGY_ARTIFACT_ROOT to an absolute, non-existing-parent-safe output
root. Each scenario creates its own child and never overwrites prior evidence.
EOF
}

profile_scenarios() {
  case "$1" in
    unit) printf '%s\n' unit ;;
    pr) printf '%s\n' direct-baseline relay-blackhole ;;
    extended)
      printf '%s\n' \
        direct-baseline \
        strict-hard \
        reordered-lossy \
        relay-blackhole \
        relay-restart \
        relay-failover \
        status-failclosed \
        metrics-failclosed \
        schema-failclosed
      ;;
    direct-baseline|strict-hard|reordered-lossy|relay-blackhole|relay-restart|relay-failover|status-failclosed|metrics-failclosed|schema-failclosed)
      printf '%s\n' "$1"
      ;;
    -h|--help) usage; exit 0 ;;
    --list)
      profile_scenarios "${2:-pr}"
      exit 0
      ;;
    *)
      echo "unknown NAT topology profile or scenario: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
}

run_unit_contracts() {
  python3 -m unittest discover -s "$ROOT_DIR/scripts/nat-sim" -p 'test_*.py'
  bash -n "$SMOKE"
  bash -n "$0"

  local actual expected
  actual=$(profile_scenarios pr | paste -sd, -)
  expected=direct-baseline,relay-blackhole
  if [[ "$actual" != "$expected" ]]; then
    echo "PR profile contract drifted: expected=$expected actual=$actual" >&2
    return 1
  fi

  actual=$(profile_scenarios extended | wc -l | tr -d ' ')
  if [[ "$actual" -ne 9 ]]; then
    echo "extended profile must contain exactly 9 scenarios, found $actual" >&2
    return 1
  fi
}

scenario_index() {
  case "$1" in
    direct-baseline) echo 1 ;;
    strict-hard) echo 2 ;;
    reordered-lossy) echo 3 ;;
    relay-blackhole) echo 4 ;;
    relay-restart) echo 5 ;;
    relay-failover) echo 6 ;;
    status-failclosed) echo 7 ;;
    metrics-failclosed) echo 8 ;;
    schema-failclosed) echo 9 ;;
    *) return 1 ;;
  esac
}

run_scenario() {
  local name="$1"
  local index port artifact_dir log_file expected reason_pattern
  local -a topology

  index=$(scenario_index "$name")
  port=$((39080 + index * 400))
  artifact_dir="$ARTIFACT_ROOT/$name"
  log_file="$ARTIFACT_ROOT/$name.log"
  expected=success
  reason_pattern=

  case "$name" in
    direct-baseline)
      topology=(MODE=direct STEP_A=1 STEP_B=1 CONSUME_A=0 CONSUME_B=0 LOSS=0 REORDER=0 STRICT_FILTERING=0)
      ;;
    strict-hard)
      # Address/port-dependent mapping and filtering with asymmetric port
      # progression. This is deterministic synthetic evidence, not a claim
      # that every real APDM/APDF carrier NAT is traversable.
      topology=(MODE=direct STEP_A=3 STEP_B=5 CONSUME_A=2 CONSUME_B=3 LOSS=0 REORDER=0 STRICT_FILTERING=1 SOCKET_POOL=32)
      ;;
    reordered-lossy)
      topology=(MODE=direct STEP_A=2 STEP_B=3 CONSUME_A=1 CONSUME_B=1 LOSS=0.01 REORDER=1 STRICT_FILTERING=0)
      ;;
    relay-blackhole)
      topology=(MODE=relay-only OVERLAY_BURST=64)
      ;;
    relay-restart)
      topology=(MODE=relay-only OVERLAY_BURST=64 RELAY_KILL_RESTART=1)
      ;;
    relay-failover)
      topology=(MODE=relay-only OVERLAY_BURST=64 RELAY_COUNT=2 RELAY_FAILOVER=1)
      ;;
    status-failclosed)
      topology=(MODE=relay-only OVERLAY_BURST=32 STATUS_FAILURE_INJECTION=1)
      expected=failure
      reason_pattern='reason_code=status_http_500_injected'
      ;;
    metrics-failclosed)
      topology=(MODE=relay-only OVERLAY_BURST=32 METRICS_FAILURE_INJECTION=1)
      expected=failure
      reason_pattern='reason_code=metrics_http_500_injected'
      ;;
    schema-failclosed)
      topology=(MODE=relay-only OVERLAY_BURST=32 STATUS_SCHEMA_INJECTION=1)
      expected=failure
      reason_pattern='reason_code=status_schema_invalid'
      ;;
  esac

  if [[ -e "$artifact_dir" ]]; then
    echo "refusing to overwrite topology evidence: $artifact_dir" >&2
    return 2
  fi
  mkdir -p "$ARTIFACT_ROOT"

  echo "[topology-matrix] scenario=$name expected=$expected artifact_dir=$artifact_dir"
  set +e
  env \
    "${topology[@]}" \
    ROUNDS="$ROUNDS" \
    NAT_SEED_BASE="$((2026082800 + index * 100))" \
    NAT_SIM_RUN_ID="topology-${name}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}" \
    NAT_SIM_ARTIFACT_DIR="$artifact_dir" \
    PORT="$port" \
    RELAY_PORT="$((port + 1))" \
    RELAY_METRICS_PORT="$((port + 100))" \
    DIAG_A_PORT="$((port + 201))" \
    DIAG_B_PORT="$((port + 202))" \
    bash "$SMOKE" 2>&1 | tee "$log_file"
  local smoke_status=${PIPESTATUS[0]}
  set -e

  if [[ "$expected" == success ]]; then
    if [[ "$smoke_status" -ne 0 ]]; then
      echo "[topology-matrix] FAIL scenario=$name expected=success status=$smoke_status" >&2
      return "$smoke_status"
    fi
  else
    if [[ "$smoke_status" -eq 0 ]]; then
      echo "[topology-matrix] FAIL scenario=$name expected=failure status=0" >&2
      return 1
    fi
    if ! grep -Fq "$reason_pattern" "$log_file"; then
      echo "[topology-matrix] FAIL scenario=$name missing_reason=$reason_pattern" >&2
      return 1
    fi
  fi

  printf '{"scenario":"%s","expected":"%s","status":%d,"rounds":%d}\n' \
    "$name" "$expected" "$smoke_status" "$ROUNDS" \
    > "$ARTIFACT_ROOT/$name.result.json"
  echo "[topology-matrix] PASS scenario=$name expected=$expected status=$smoke_status"
}

mapfile -t scenarios < <(profile_scenarios "$PROFILE")
if [[ "${scenarios[*]}" == unit ]]; then
  run_unit_contracts
  exit 0
fi

# Run parser/unit contracts once before any expensive topology process. A
# malformed simulator or matrix must fail before consuming runner minutes.
run_unit_contracts
for scenario in "${scenarios[@]}"; do
  run_scenario "$scenario"
done

echo "[topology-matrix] profile=$PROFILE PASS scenarios=${scenarios[*]}"
