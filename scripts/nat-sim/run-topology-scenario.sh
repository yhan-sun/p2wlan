#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SMOKE="$ROOT_DIR/scripts/nat-sim/nat-sim-smoke.sh"
SCENARIO=${1:-}

list_scenarios() {
  cat <<'EOF'
simulator-unit
direct-baseline
hard-hard-strict
relay-blackhole
relay-failover
observability-fail-closed
EOF
}

if [[ "$SCENARIO" == "--list" ]]; then
  list_scenarios
  exit 0
fi

if [[ -z "$SCENARIO" ]]; then
  echo "usage: bash scripts/nat-sim/run-topology-scenario.sh <scenario>" >&2
  echo "available scenarios:" >&2
  list_scenarios >&2
  exit 2
fi

artifact_dir() {
  if [[ -n "${NAT_SIM_ARTIFACT_DIR:-}" ]]; then
    printf '%s\n' "$NAT_SIM_ARTIFACT_DIR"
    return
  fi
  local run_id=${GITHUB_RUN_ID:-local}
  local attempt=${GITHUB_RUN_ATTEMPT:-1}
  printf '%s/p2wlan-nat-%s-%s-%s\n' "${RUNNER_TEMP:-/tmp}" "$SCENARIO" "$run_id" "$attempt"
}

run_smoke() {
  local output
  output=$(artifact_dir)
  NAT_SIM_ARTIFACT_DIR="$output" \
    NAT_SIM_RUN_ID="topology-${SCENARIO}-${GITHUB_RUN_ID:-local}" \
    bash "$SMOKE"
}

case "$SCENARIO" in
  simulator-unit)
    python3 -m unittest -v "$ROOT_DIR/scripts/nat-sim/test_nat_sim.py"
    ;;

  direct-baseline)
    MODE=direct \
    ROUNDS=1 \
    NAT_SEED_BASE=2026082801 \
    STEP_A=1 STEP_B=1 \
    CONSUME_A=0 CONSUME_B=0 \
    LOSS=0 REORDER=0 STRICT_FILTERING=0 \
    DIRECT_TIMEOUT_S=60 OVERLAY_TIMEOUT_S=30 \
    run_smoke
    ;;

  hard-hard-strict)
    # Both sides use endpoint-dependent mapping/filtering, deterministic
    # non-unit port strides and pre-punch allocation consumption. This forces
    # fresh mapping, prediction and bounded Birthday probing to participate.
    MODE=direct \
    ROUNDS=1 \
    NAT_SEED_BASE=2026082811 \
    STEP_A=3 STEP_B=5 \
    CONSUME_A=8 CONSUME_B=11 \
    LOSS=0 REORDER=0 STRICT_FILTERING=1 \
    FRESH_MAPPING_PUNCH=1 PREDICTED_CANDIDATES=1 BIRTHDAY_PROBING=1 \
    SOCKET_POOL=64 \
    DIRECT_TIMEOUT_S=90 OVERLAY_TIMEOUT_S=30 \
    run_smoke
    ;;

  relay-blackhole)
    # STUN still works, while all inter-NAT UDP is blackholed. Relay must be
    # the only usable encrypted data path and the burst must be lossless.
    MODE=relay-only \
    ROUNDS=1 \
    NAT_SEED_BASE=2026082821 \
    OVERLAY_BURST=64 \
    DIRECT_TIMEOUT_S=30 OVERLAY_TIMEOUT_S=45 \
    run_smoke
    ;;

  relay-failover)
    # Start with two relay candidates, kill the active one after first usable
    # evidence and require a newly confirmed relay plus recovered overlay.
    MODE=relay-only \
    ROUNDS=1 \
    NAT_SEED_BASE=2026082831 \
    OVERLAY_BURST=32 \
    RELAY_COUNT=2 RELAY_FAILOVER=1 \
    DIRECT_TIMEOUT_S=30 OVERLAY_TIMEOUT_S=60 \
    run_smoke
    ;;

  observability-fail-closed)
    # An unavailable required status endpoint must make the harness fail. A
    # zero exit here would mean missing evidence was silently accepted.
    set +e
    MODE=relay-only \
    ROUNDS=1 \
    NAT_SEED_BASE=2026082841 \
    OVERLAY_BURST=8 \
    STATUS_FAILURE_INJECTION=1 \
    DIRECT_TIMEOUT_S=20 OVERLAY_TIMEOUT_S=30 \
    run_smoke
    status=$?
    set -e
    if [[ "$status" -eq 0 ]]; then
      echo "observability fail-closed scenario unexpectedly passed" >&2
      exit 1
    fi
    echo "observability fail-closed scenario rejected missing status evidence as expected"
    ;;

  *)
    echo "unknown NAT topology scenario: $SCENARIO" >&2
    echo "available scenarios:" >&2
    list_scenarios >&2
    exit 2
    ;;
esac
