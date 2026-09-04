#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT_DIR=${1:-${RUNNER_TEMP:-/tmp}/p2wlan-dplpmtud-live}
SOURCE_HEAD_SHA=${DPLPMTUD_SOURCE_HEAD_SHA:-$(git -C "$ROOT_DIR" rev-parse HEAD)}
WORKFLOW_SHA=${DPLPMTUD_WORKFLOW_SHA:-$(git -C "$ROOT_DIR" rev-parse "$SOURCE_HEAD_SHA:.github/workflows/dplpmtud-required.yml")}

if [[ ! "$SOURCE_HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "invalid source head SHA: $SOURCE_HEAD_SHA" >&2
  exit 2
fi
if [[ ! "$WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "invalid workflow SHA: $WORKFLOW_SHA" >&2
  exit 2
fi
if [[ -e "$OUT_DIR" ]]; then
  echo "refusing to reuse evidence directory: $OUT_DIR" >&2
  exit 2
fi
mkdir -p "$OUT_DIR/logs"

export CARGO_TERM_COLOR=never

run_exact() {
  local log_file=$1
  local test_id=$2
  (
    cd "$ROOT_DIR"
    cargo test -p p2wlan-daemon --lib "$test_id" -- \
      --exact --nocapture --test-threads=1
  ) 2>&1 | tee "$OUT_DIR/logs/$log_file"
}

run_exact dp-01-boundary.log \
  tests::dplpmtud_final_boundary_matrix_ipv4_ipv6
run_exact dp-02-identity.log \
  tests::dplpmtud_final_epoch_and_socket_identity_isolation
run_exact dp-03-loss-reorder.log \
  tests::dplpmtud_final_loss_reorder_duplicate_are_fenced
run_exact dp-04-path-switch.log \
  tests::dplpmtud_final_direct_relay_switch_and_recovery
run_exact dp-05-counters.log \
  tests::dplpmtud_final_typed_counters_use_bounded_labels
run_exact dp-06-blackhole.log \
  dplpmtud::tests::encrypted_udp_blackhole_converges_without_path_failure_or_worker_leak
run_exact dp-07-business-e2e.log \
  tests::direct_business_budget_production_path_e2e
run_exact dp-08-downward.log \
  dplpmtud::tests::runtime_downward_recovery_withholds_budget_until_fresh_base_ack
run_exact dp-09-cancellation.log \
  dplpmtud::tests::cancel_close_generation_and_relay_budget_invalidation_acceptance
run_exact dp-10-revision.log \
  dplpmtud::tests::budget_revision_is_monotonic_and_closes_identity_aba

python3 "$ROOT_DIR/scripts/dplpmtud/collect_evidence.py" \
  --contract "$ROOT_DIR/contracts/dplpmtud_acceptance.json" \
  --log-root "$OUT_DIR/logs" \
  --source-head-sha "$SOURCE_HEAD_SHA" \
  --workflow-sha "$WORKFLOW_SHA" \
  --output "$OUT_DIR/dplpmtud-live-component.json"

python3 - "$OUT_DIR/dplpmtud-live-component.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    report = json.load(handle)
if report.get("result") != "pass":
    raise SystemExit("component_report_not_pass")
if report.get("scenario_count") != 10:
    raise SystemExit("component_scenario_count_mismatch")
print(
    "DPLPMTUD live component PASS "
    f"scenarios={report['scenario_count']} digest={report['report_digest']}"
)
PY
