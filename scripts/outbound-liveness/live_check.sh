#!/usr/bin/env bash
# live_check.sh — Outbound-UDP liveness live verification harness (Gate format)
#
# Records / verifies the "ScatterExtended 0-ACK → firewall diagnosis" feature on
# REAL networks.  It does NOT fabricate a firewall; it parses the evidence a
# running daemon emits (its structured log + /status JSON) and renders a
# Gate-report table (matching scripts/punch-research/TEST_REPORT_P2.md §9/§10).
#
# The feature logs these markers (daemon, RUST_LOG=info):
#   outbound_liveness            verdict=<ok|blocked|unknown> total_elapsed_ms=<N>
#   outbound_liveness_applied    (next admission tick consumed a fresh Blocked)
#   recovery_stage_relay_backoff reason=outbound_liveness_blocked
#   firewall_blocked             (direct_health.last_error_code, via /status)
# and the CLI renders per-peer `direct.last_liveness` from /status.
#
# Two scenarios (run each on the appropriate real network, then pass the
# captured artifacts here):
#
#   A. BLOCKED  (egress UDP firewalled):  point udp_liveness_targets at an
#      unreachable / egress-blocked endpoint (e.g. a TEST-NET 192.0.2.1:53, or
#      a real host whose outbound UDP 53 is denied), force a ScatterExtended
#      wide scan with 0 ACKs.  EXPECT:
#        - liveness verdict=blocked
#        - probe total_elapsed_ms <= retries*timeout + eps  (default 2*1500+eps)
#        - outbound_liveness_applied + recovery_stage_relay_backoff (scan stops)
#        - direct.last_error_code == firewall_blocked in /status
#   B. NORMAL   (clean egress):           default targets.  EXPECT:
#        - liveness verdict=ok
#        - Direct promotes normally, ZERO false verdict=blocked
#
# Usage:
#   live_check.sh <scenario> --log <daemon.log> [--status <status.json>] [--peer <node_id>]
#                 [--timeout-ms 1500] [--retries 2] [--eps-ms 500]
#
#   live_check.sh blocked --log /tmp/node-a.log --status /tmp/a.json --peer air-mini
#   live_check.sh normal  --log /tmp/node-b.log --status /tmp/b.json --peer air-mini
#
# Exit 0 = scenario's expectations met; 1 = not met (or artifacts missing).
# Output: a Gate-format per-round table + PASS/FAIL, ready to paste into
# RESULT_TEMPLATE.md.
set -uo pipefail

SCENARIO="${1:?usage: live_check.sh <blocked|normal> --log <f> [--status <f>] [--peer <id>]}"
LOG=""
STATUS=""
PEER=""
TIMEOUT_MS=1500
RETRIES=2
EPS_MS=500
shift

while [ $# -gt 0 ]; do
  case "$1" in
    --log)      LOG="${2:?--log needs a file}"; shift 2 ;;
    --status)   STATUS="${2:?--status needs a file}"; shift 2 ;;
    --peer)     PEER="${2:-}"; shift 2 ;;
    --timeout-ms) TIMEOUT_MS="${2:?}"; shift 2 ;;
    --retries)  RETRIES="${2:?}"; shift 2 ;;
    --eps-ms)   EPS_MS="${2:?}"; shift 2 ;;
    -h|--help)  grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "[live_check] unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -n "$LOG" ] || { echo "[live_check] --log <daemon.log> is required" >&2; exit 2; }
[ -f "$LOG" ] || { echo "[live_check] log not found: $LOG" >&2; exit 2; }

BUDGET_MS=$(( (RETRIES * TIMEOUT_MS) + EPS_MS ))
echo "==================================================================="
echo " Outbound-UDP liveness live check — scenario: $SCENARIO"
echo " budget: $BUDGET_MS ms (retries=$RETRIES x timeout=$TIMEOUT_MS ms + eps=$EPS_MS ms)"
echo " log:    $LOG"
echo " status: ${STATUS:-<not provided>}"
echo "==================================================================="
echo

# Restrict to the peer of interest if given (log lines carry peer_id=<...>).
pick() { # pick <grep-pattern> -> filtered log lines
  if [ -n "$PEER" ]; then
    grep -E "$1" "$LOG" | grep -E "peer_id=.*$PEER|peer=$PEER|$PEER" || true
  else
    grep -E "$1" "$LOG" || true
  fi
}

# ---- gather the raw evidence -------------------------------------------------
LIVENESS_LINES=$(pick "event *= *\"outbound_liveness\"|outbound_liveness verdict|outbound UDP liveness verdict")
APPLIED_LINES=$(pick "outbound_liveness_applied")
BACKOFF_LINES=$(pick "recovery_stage_relay_backoff.*outbound_liveness|outbound_liveness_blocked")
PREFLIGHT_LINES=$(pick "outbound_liveness_pre_flight_skip")

echo "[evidence] outbound_liveness verdict lines:      $(echo "$LIVENESS_LINES" | grep -c . || true)"
echo "[evidence] outbound_liveness_applied lines:      $(echo "$APPLIED_LINES" | grep -c . || true)"
echo "[evidence] relay_backoff(liveness) lines:        $(echo "$BACKOFF_LINES" | grep -c . || true)"
echo "[evidence] pre_flight_skip lines:                $(echo "$PREFLIGHT_LINES" | grep -c . || true)"
echo

# Extract the last total_elapsed_ms seen on an outbound_liveness line.
last_total_ms() {
  echo "$LIVENESS_LINES" | grep -oE "total_elapsed_ms *[=: ]*[0-9]+" \
    | grep -oE "[0-9]+" | tail -1
}

# Per-target detail (from the `detail=` / `targets=[...]` on the verdict line).
per_target() {
  echo "$LIVENESS_LINES" | grep -oE "targets=\[[^]]*\]" | tail -1
}

# /status peer slice (direct.last_liveness / direct.last_error_code).
status_verdict() {
  [ -n "$STATUS" ] && [ -f "$STATUS" ] || return 0
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg p "$PEER" '
      (.peers // {}) | to_entries[]
      | select(($p=="" ) or (.key== $p) or (.value.node_id==$p))
      | "direct_liveness=\(.value.direct.last_liveness // "null") last_error_code=\(.value.direct.last_error_code // "null")"
    ' "$STATUS" 2>/dev/null
  else
    grep -oE '"last_liveness"[^,]*' "$STATUS" | head
  fi
}

VERDICT_MS=$(last_total_ms)
VERDICT_MS="${VERDICT_MS:-0}"

# ---- render the Gate table ---------------------------------------------------
echo "| round | verdict | per-target (ip:port,responded,ms) | total_ms | changed path? | fail_reason |"
echo "|---|---|---|---|---|---|"
if [ -n "$LIVENESS_LINES" ]; then
  n=0
  while IFS= read -r line; do
    n=$((n+1))
    v=$(echo "$line" | grep -oE "verdict *= *\"?(ok|blocked|unknown)" | grep -oE "(ok|blocked|unknown)" | head -1)
    pt=$(echo "$line" | grep -oE "targets=\[[^]]*\]" | head -1)
    tm=$(echo "$line" | grep -oE "total_elapsed_ms *[=: ]*[0-9]+" | grep -oE "[0-9]+" | head -1)
    changed="no"
    if [ -n "$APPLIED_LINES" ] || [ -n "$BACKOFF_LINES" ]; then changed="yes (relay)"; fi
    fr="—"
    if echo "$line" | grep -q "blocked"; then fr="firewall_blocked"; fi
    echo "| $n | ${v:-?} | ${pt:-—} | ${tm:-?} | $changed | $fr |"
  done <<< "$LIVENESS_LINES"
else
  echo "| — | (no outbound_liveness lines captured) | — | — | — | — |"
fi
echo
[ -n "$PEER" ] && { echo "[status] $(status_verdict)"; echo; }

# ---- verdict: PASS / FAIL ----------------------------------------------------
fail=0
note() { echo "  $1"; }

if [ "$SCENARIO" = "blocked" ]; then
  echo "--- expectations (blocked scenario) ---"
  if echo "$LIVENESS_LINES" | grep -q "blocked"; then
    note "OK: at least one verdict=blocked"
  else
    note "MISS: no verdict=blocked in log"; fail=1
  fi
  if [ "$VERDICT_MS" -gt 0 ] && [ "$VERDICT_MS" -le "$BUDGET_MS" ]; then
    note "OK: probe total_elapsed_ms=$VERDICT_MS <= budget $BUDGET_MS (not a full extra epoch)"
  elif [ "$VERDICT_MS" -gt 0 ]; then
    note "MISS: probe total_elapsed_ms=$VERDICT_MS > budget $BUDGET_MS"; fail=1
  else
    note "WARN: could not parse total_elapsed_ms"; fail=1
  fi
  if [ -n "$APPLIED_LINES" ]; then
    note "OK: outbound_liveness_applied present (next-tick consumption)"
  else
    note "WARN: no outbound_liveness_applied (may not have reached an admit tick yet)";
  fi
  if [ -n "$BACKOFF_LINES" ]; then
    note "OK: recovery_stage_relay_backoff(liveness) present (wide scatter stopped)"
  else
    note "WARN: no liveness-driven relay_backoff line"; fail=1
  fi
  if [ -n "$STATUS" ] && [ -f "$STATUS" ]; then
    if grep -q "firewall_blocked" "$STATUS"; then
      note "OK: /status shows direct.last_error_code=firewall_blocked"
    else
      note "WARN: /status does not show firewall_blocked"; fail=1
    fi
  fi
elif [ "$SCENARIO" = "normal" ]; then
  echo "--- expectations (normal scenario) ---"
  if echo "$LIVENESS_LINES" | grep -q "blocked"; then
    note "FAIL: false verdict=blocked on a clean network"; fail=1
  else
    note "OK: zero false verdict=blocked"
  fi
  if echo "$LIVENESS_LINES" | grep -q "verdict *= *\"ok\|verdict=ok"; then
    note "OK: verdict=ok observed (outbound reachable)"
  else
    note "WARN: no verdict=ok line (liveness may not have been triggered)";
  fi
  if [ -n "$STATUS" ] && [ -f "$STATUS" ]; then
    if grep -q "firewall_blocked" "$STATUS"; then
      note "FAIL: firewall_blocked attributed on a clean network (false positive)"; fail=1
    else
      note "OK: no firewall_blocked misattribution"
    fi
  fi
else
  echo "unknown scenario: $SCENARIO (expected blocked|normal)" >&2
  exit 2
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "RESULT: PASS ($SCENARIO)"
else
  echo "RESULT: FAIL ($SCENARIO) — see MISS/FAIL lines above"
fi
exit "$fail"
