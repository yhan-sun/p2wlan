#!/usr/bin/env bash

# Round-owned children are authoritative in PIDS. The bounded receipt ledger
# stores observations, not a second collection of live process owners.
# Sourcing this module installs no traps and starts/stops no process.

_round_tool() { python3 "$ROOT_DIR/scripts/nat-sim/round_finalization.py" "$@"; }
# Clock reads share the receipt monotonic domain without loading the publisher.
_round_now() { python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)'; }

_round_context() {
  [[ -n "${ROUND_DIR:-}" && -d "$ROUND_DIR" ]] || return 1
  if [[ "${_ROUND_OWNER_DIR:-}" != "$ROUND_DIR" ]]; then
    _ROUND_OWNER_DIR=$ROUND_DIR
    _ROUND_OWNER_PID=(); _ROUND_OWNER_ROLE=(); _ROUND_OWNER_WAIT=()
    _ROUND_OWNER_STATUS=(); _ROUND_OWNER_FORCED=()
    _ROUND_STARTED=0; _ROUND_WATCHERS=0; _ROUND_WAIT_COMPLETED=0; _ROUND_WAIT_UNKNOWN=0
    _ROUND_STATUS_CAPTURED=0; _ROUND_RESOURCE_END_MS=0
    _ROUND_CAPTURE_END_MS=0; _ROUND_FINALIZER_START_MS=0
    _ROUND_ORIGINAL_COLLECTOR_STARTED=0; _ROUND_ORIGINAL_COLLECTOR_STATUS=1
    _ROUND_NORMAL_TAIL_READY=0; _ROUND_NORMAL_TAIL_ENTERED=0
    _ROUND_SIGNAL_EXIT=0
    _ROUND_HTTP_PAIR_SEQUENCE=0; _ROUND_HTTP_CANCEL_PUBLISHED=0; _ROUND_HTTP_CANCEL_ATTEMPTED=0
    _ROUND_STATE=initializing
    CLEANUP_FORCED=${CLEANUP_FORCED:-0}
    ROUND_FINISH_REASON=${ROUND_FINISH_REASON:-}
    ROUND_FINISH_EXIT_CODE=${ROUND_FINISH_EXIT_CODE:-0}
    local pid role index relay
    if (( ${#PIDS[@]} > 0 )); then
      for pid in "${PIDS[@]}"; do
      role=owned
      if [[ "$pid" == "${NODE_A_PID:-}" ]]; then role=node-a
      elif [[ "$pid" == "${NODE_B_PID:-}" ]]; then role=node-b
      elif [[ "$pid" == "${NAT_PID:-}" ]]; then role=nat
      elif [[ "$pid" == "${SERVER_PID:-}" ]]; then role=control
      elif [[ "$pid" == "${HARD_HARD_WATCHER_PID:-}" ]]; then role=watcher
      else
        index=0
        if declare -p RELAY_PIDS >/dev/null 2>&1 && (( ${#RELAY_PIDS[@]} > 0 )); then
          for relay in "${RELAY_PIDS[@]}"; do
            index=$((index + 1))
            if [[ "$pid" == "$relay" ]]; then role="relay-$index"; break; fi
          done
        fi
      fi
      _round_append_owner "$role" "$pid"
      done
    fi
    _ROUND_STATE=open
    if (( ${_ROUND_SIGNAL_EXIT:-0} != 0 )); then exit "$_ROUND_SIGNAL_EXIT"; fi
  fi
}

# Explicit round initialization is for callers before their first spawn.
# Lazy context creation above supports the existing cleanup entry point.
round_init() {
  [[ ${#PIDS[@]} == 0 ]] || return 1
  _ROUND_OWNER_DIR=""
  _ROUND_EXIT_TRAP_STATUS=-1
  ROUND_FINISH_REASON=""; ROUND_FINISH_EXIT_CODE=0; CLEANUP_FORCED=0
  NODE_A_PID=""; NODE_B_PID=""; NAT_PID=""; SERVER_PID=""
  HARD_HARD_WATCHER_PID=""; RELAY_PIDS=()
  _round_context
  if [[ "${1:-}" == business ]]; then
    if _round_clock_origin_present; then
      _round_capture_window "${ROUND_CLOCK_ORIGIN_MONOTONIC_MS:-}" "${ROUND_CLOCK_ORIGIN_SECONDS:-}"
    else
      _round_capture_window
    fi
  fi
}

_round_append_owner() {
  local role="$1" pid="$2" index
  for ((index=0; index < ${#_ROUND_OWNER_PID[@]}; index++)); do
    [[ "${_ROUND_OWNER_PID[$index]}" != "$pid" ]] || return 0
  done
  _ROUND_STARTED=$((_ROUND_STARTED + 1))
  [[ "$role" != watcher ]] || _ROUND_WATCHERS=$((_ROUND_WATCHERS + 1))
  if (( ${#_ROUND_OWNER_PID[@]} < 128 )); then
    _ROUND_OWNER_PID+=("$pid"); _ROUND_OWNER_ROLE+=("$role")
    _ROUND_OWNER_WAIT+=(0); _ROUND_OWNER_STATUS+=(unknown); _ROUND_OWNER_FORCED+=(0)
  fi
}

_round_owned() {
  local candidate
  (( ${#PIDS[@]} > 0 )) || return 1
  for candidate in "${PIDS[@]}"; do [[ "$candidate" != "$1" ]] || return 0; done
  return 1
}

round_register_process() {
  local role="$1" pid="$2"
  [[ "$role" =~ ^[a-zA-Z0-9_.:-]{1,128}$ && "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  _round_context || return 1
  if _round_owned "$pid"; then return 0; fi
  PIDS+=("$pid")
  _round_append_owner "$role" "$pid"
}

# jobs is the current shell's child ownership table. A cached completed job
# is waited without signalling its numeric PID. Include live pipeline members;
# jobs -p alone only returns a pipeline's group leader, not necessarily $!.
_round_running_jobs() {
  LC_ALL=C jobs -l | awk '
    function emit() { if (live) printf "%s", pids; pids=""; live=0 }
    /^\[/ { emit(); if ($2 ~ /^[0-9]+$/ && $0 !~ / Done | Exit /) pids=$2 "\n" }
    !/^\[/ && $1 ~ /^[0-9]+$/ && $0 !~ / Done | Exit / { pids=pids $1 "\n" }
    / Running | Stopped / { live=1 }
    END { emit() }
  '
}

_round_job_live() {
  local candidate
  while IFS= read -r candidate; do [[ "$candidate" != "$1" ]] || return 0; done < <(_round_running_jobs)
  return 1
}

# This API takes the result of an actual wait in the owning shell. Callers
# joining watchers/replaced relays must call it immediately after that wait.
round_record_wait() {
  local pid="$1" status="$2" index candidate
  local remaining=()
  [[ "$status" =~ ^[0-9]{1,3}$ ]] && (( status <= 255 )) || return 1
  _round_owned "$pid" || return 0
  if [[ "$status" == 127 ]]; then
    _ROUND_WAIT_UNKNOWN=$((_ROUND_WAIT_UNKNOWN + 1))
  else
    _ROUND_WAIT_COMPLETED=$((_ROUND_WAIT_COMPLETED + 1))
  fi
  for ((index=0; index < ${#_ROUND_OWNER_PID[@]}; index++)); do
    if [[ "${_ROUND_OWNER_PID[$index]}" == "$pid" ]]; then
      _ROUND_OWNER_STATUS[$index]=$status
      [[ "$status" == 127 ]] || _ROUND_OWNER_WAIT[$index]=1
      break
    fi
  done
  for candidate in "${PIDS[@]}"; do [[ "$candidate" == "$pid" ]] || remaining+=("$candidate"); done
  if (( ${#remaining[@]} > 0 )); then
    PIDS=("${remaining[@]}")
  else
    PIDS=()
  fi
}

_round_wait_finished() {
  local pid="$1" status
  _round_owned "$pid" || return 0
  # Gone numeric PIDs can be waited from the owning shell's cached status
  # without forking a jobs lookup. A live PID remains pending; only the
  # signalling path may authorize it through the current shell job table.
  kill -0 "$pid" 2>/dev/null && return 1
  if wait "$pid" 2>/dev/null; then status=0; else status=$?; fi
  round_record_wait "$pid" "$status"
}

round_fail() {
  # The first local failure wins. overall is aggregate across rounds and must
  # not assign a previous round's failure to a later successful round.
  [[ -n "${ROUND_FINISH_REASON:-}" ]] || ROUND_FINISH_REASON=$1
  if (( ${ROUND_FINISH_EXIT_CODE:-0} == 0 )); then ROUND_FINISH_EXIT_CODE=${2:-1}; fi
  overall=1
}

_round_clock_origin_present() {
  [[ ${ROUND_CLOCK_ORIGIN_MONOTONIC_MS+x}${ROUND_CLOCK_ORIGIN_UNIX_MS+x}${ROUND_CLOCK_ORIGIN_UNIX_S+x}${ROUND_CLOCK_ORIGIN_SECONDS+x} != "" ]]
}

_round_project_deadline_ms() {
  local deadline="$1" cutoff
  # All coordinates belong to one observation at original budget creation.
  # Monotonic floor precedes Unix ceil; a crossed shell second only tightens
  # the projection. Subsequent observations cannot rebase this origin.
  [[ "$deadline" =~ ^(0|[1-9][0-9]{0,9})$ &&
     "${ROUND_CLOCK_ORIGIN_SECONDS:-}" =~ ^(0|[1-9][0-9]{0,9})$ &&
     "${ROUND_CLOCK_ORIGIN_MONOTONIC_MS:-}" =~ ^[1-9][0-9]{0,14}$ &&
     "${ROUND_CLOCK_ORIGIN_UNIX_MS:-}" =~ ^[1-9][0-9]{0,14}$ &&
     "${ROUND_CLOCK_ORIGIN_UNIX_S:-}" =~ ^[1-9][0-9]{0,11}$ ]] || return 1
  (( ROUND_CLOCK_ORIGIN_UNIX_MS >= ROUND_CLOCK_ORIGIN_UNIX_S * 1000 &&
     ROUND_CLOCK_ORIGIN_UNIX_MS <= (ROUND_CLOCK_ORIGIN_UNIX_S + 1) * 1000 )) || return 1
  cutoff=$((ROUND_CLOCK_ORIGIN_MONOTONIC_MS +
    (ROUND_CLOCK_ORIGIN_UNIX_S + deadline - ROUND_CLOCK_ORIGIN_SECONDS) * 1000 -
    ROUND_CLOCK_ORIGIN_UNIX_MS))
  (( cutoff > 0 )) || return 1
  printf '%s\n' "$cutoff"
}

_round_capture_window() {
  local now observed_seconds remaining candidate
  case "$#" in
    0)
      now=$(_round_now) || return $?
      observed_seconds=$SECONDS
      ;;
    2)
      now=$1; observed_seconds=$2
      ;;
    *) return 1 ;;
  esac
  # Validate before arithmetic; a bad clock is a hard error, not a timeout.
  [[ "$now" =~ ^[1-9][0-9]{0,14}$ &&
     "$observed_seconds" =~ ^(0|[1-9][0-9]{0,9})$ &&
     "${ROUND_DEADLINE:-0}" =~ ^(0|[1-9][0-9]{0,9})$ ]] || return 1
  if _round_clock_origin_present; then
    candidate=$(_round_project_deadline_ms "${ROUND_DEADLINE:-0}") || return 1
  else
    remaining=$((${ROUND_DEADLINE:-0} - observed_seconds))
    # Callers without an original clock tuple retain the conservative legacy
    # conversion. The production tuple preserves fractional remaining time.
    (( remaining > 0 )) && candidate=$((now + (remaining - 1) * 1000)) || candidate=$now
  fi
  if (( _ROUND_CAPTURE_END_MS == 0 || candidate < _ROUND_CAPTURE_END_MS )); then
    _ROUND_CAPTURE_END_MS=$candidate
  fi
  return 0
}

_round_fixed_windows() {
  local now cap
  now=$(_round_now) || return $?
  if (( _ROUND_RESOURCE_END_MS == 0 )); then
    _ROUND_FINALIZER_START_MS=$now
    # This private fixture cap may only shrink the existing fixed reserve.
    cap=15000
    if [[ "${FINALIZE_BUDGET_S:-15}" =~ ^[1-9][0-9]?$ ]]; then
      cap=$((${FINALIZE_BUDGET_S:-15} * 1000))
    fi
    (( cap <= 15000 )) || cap=15000
    [[ "${ROUND_CLEANUP_GRACE_MS:-}" =~ ^[1-9][0-9]{0,4}$ ]] && \
      (( ROUND_CLEANUP_GRACE_MS < cap )) && cap=$ROUND_CLEANUP_GRACE_MS
    (( cap > 0 )) || cap=1
    _ROUND_RESOURCE_END_MS=$((now + cap))
  fi
  if _round_clock_origin_present; then
    _round_capture_window "$now" "$SECONDS"
  else
    _round_capture_window
  fi
}

_round_owner_lines() {
  local index
  for ((index=0; index < ${#_ROUND_OWNER_PID[@]}; index++)); do
    printf '%s\t%s\t%s\t%s\t%s\n' "${_ROUND_OWNER_ROLE[$index]}" "${_ROUND_OWNER_PID[$index]}" \
      "${_ROUND_OWNER_WAIT[$index]}" "${_ROUND_OWNER_STATUS[$index]}" "${_ROUND_OWNER_FORCED[$index]}"
  done
}

_round_role() {
  local index
  for ((index=0; index < ${#_ROUND_OWNER_PID[@]}; index++)); do
    if [[ "${_ROUND_OWNER_PID[$index]}" == "$1" ]]; then
      printf '%s\n' "${_ROUND_OWNER_ROLE[$index]}"
      return 0
    fi
  done
  printf '%s\n' unknown
}

_round_recorded_wait_complete() {
  local index
  for ((index=0; index < ${#_ROUND_OWNER_PID[@]}; index++)); do
    if [[ "${_ROUND_OWNER_PID[$index]}" == "$1" && "${_ROUND_OWNER_WAIT[$index]}" == 1 ]]; then
      return 0
    fi
  done
  return 1
}

_round_capture_side() {
  local side="$1" pid="$2" runtime="$3" port="$4"
  local worker_grace_end_ms="${5:-$_ROUND_RESOURCE_END_MS}"
  local owner_role process_observation=unknown
  owner_role=$(_round_role "$pid")
  # A recorded actual wait is checked before touching this numeric PID.
  # It preserves the ended original identity even if the number is reused.
  if [[ "${pid:-0}" == 0 ]]; then
    process_observation=not_started
  elif _round_recorded_wait_complete "$pid"; then
    process_observation=wait_complete
  elif _round_owned "$pid"; then
    if _round_wait_finished "$pid"; then
      if _round_recorded_wait_complete "$pid"; then process_observation=wait_complete; fi
    elif _round_job_live "$pid"; then
      process_observation=live_job
    fi
  fi
  { declare -f fetch_required_json deadline_remaining_s p2wlan_diagnostics_curl p2wlan_read_diagnostics_token || true; } | \
    ROOT_DIR="$ROOT_DIR" BASE_DIR="$BASE_DIR" ROUND_DIR="$ROUND_DIR" \
    NODE_A_RUNTIME="${NODE_A_RUNTIME:-}" NODE_B_RUNTIME="${NODE_B_RUNTIME:-}" \
    STATUS_FAILURE_INJECTION="${STATUS_FAILURE_INJECTION:-0}" \
    STATUS_SCHEMA_INJECTION="${STATUS_SCHEMA_INJECTION:-0}" \
    _round_tool capture --deadline-ms "$_ROUND_CAPTURE_END_MS" --grace-end-ms "$worker_grace_end_ms" \
      --pid "${pid:-0}" --url "http://127.0.0.1:${port:-0}/status" \
      --side "$side" --owner-role "$owner_role" --process-observation "$process_observation" \
      --token-file "$runtime/p2wlan-daemon.diag-auth" --output "$ROUND_DIR/node-$side.status.json" \
      --receipt "$ROUND_DIR/.final-status-$side.json"
}

round_capture_final_statuses() {
  local worker_grace_end_ms
  _round_context || return 1
  (( _ROUND_STATUS_CAPTURED == 0 )) || return 0
  if [[ "${1:-}" == business ]]; then
    _round_capture_window
    worker_grace_end_ms=$_ROUND_CAPTURE_END_MS
  else
    _round_fixed_windows
    worker_grace_end_ms=$_ROUND_RESOURCE_END_MS
  fi
  _ROUND_STATUS_CAPTURED=1
  STATUS_SCHEMA_OK=1
  _round_capture_side a "${NODE_A_PID:-0}" "${NODE_A_RUNTIME:-}" "${DIAG_A_PORT:-0}" "$worker_grace_end_ms" || STATUS_SCHEMA_OK=0
  _round_capture_side b "${NODE_B_PID:-0}" "${NODE_B_RUNTIME:-}" "${DIAG_B_PORT:-0}" "$worker_grace_end_ms" || STATUS_SCHEMA_OK=0
}

# Direct exec keeps the original background shell's PID as its CLI-owned $!.
# Only function declarations travel in argv; diagnostics secrets remain files.
round_http_exec_request() {
  local role="$1" sequence="$2" side="$3" max_time="$4"
  local stage_end="$5" round_end="$6" work_end="$7" parent_remaining="$8" definitions="$9"
  shift 9
  exec python3 "$ROOT_DIR/scripts/nat-sim/round_finalization.py" http-request \
    --round-dir "$ROUND_DIR" --run-id "${ROUND_RUN_ID:-unknown}" --context-pid "$$" \
    --owner-role "$role" --pair-sequence "$sequence" --side "$side" \
    --deadline-ms "$stage_end" --round-end-ms "$round_end" --work-end-ms "$work_end" \
    --parent-round-remaining "$parent_remaining" --max-time "$max_time" --definitions "$definitions" \
    --status-failure-injection "$STATUS_FAILURE_INJECTION" \
    --metrics-failure-injection "$METRICS_FAILURE_INJECTION" --status-schema-injection "$STATUS_SCHEMA_INJECTION" \
    --url "$1" --output "$2" --token-file "$3" --metadata "$4"
}

_round_http_owner_pid() {
  local candidate="$1" index
  for ((index=0; index < ${#_ROUND_OWNER_PID[@]}; index++)); do
    [[ "${_ROUND_OWNER_PID[$index]}" == "$candidate" && "${_ROUND_OWNER_ROLE[$index]}" =~ ^http-barrier-[1-9][0-9]*-[ab]$ ]] && return 0
  done
  return 1
}

_round_http_has_pending() {
  local index role pid
  for ((index=0; index < ${#_ROUND_OWNER_PID[@]}; index++)); do
    role=${_ROUND_OWNER_ROLE[$index]}; pid=${_ROUND_OWNER_PID[$index]}
    [[ "$role" =~ ^http-barrier-[1-9][0-9]*-[ab]$ && "${_ROUND_OWNER_WAIT[$index]}" == 0 ]] || continue
    _round_owned "$pid" && return 0
  done
  return 1
}

_round_http_pending_owner_lines() {
  local index role pid
  for ((index=0; index < ${#_ROUND_OWNER_PID[@]}; index++)); do
    role=${_ROUND_OWNER_ROLE[$index]}; pid=${_ROUND_OWNER_PID[$index]}
    [[ "$role" =~ ^http-barrier-[1-9][0-9]*-[ab]$ && "${_ROUND_OWNER_WAIT[$index]}" == 0 ]] || continue
    _round_owned "$pid" || continue
    printf '%s\t%s\n' "$role" "$pid"
  done
}

_round_http_publish_cancel() {
  if (( _ROUND_HTTP_CANCEL_ATTEMPTED != 0 )); then
    (( _ROUND_HTTP_CANCEL_PUBLISHED == 1 )) && return 0
    round_fail http_cancel_fence_failed 1
    return 1
  fi
  _round_http_has_pending || return 0
  _ROUND_HTTP_CANCEL_ATTEMPTED=1
  _round_http_pending_owner_lines | _round_tool http-cancel \
    --round-dir "$ROUND_DIR" --run-id "${ROUND_RUN_ID:-unknown}" \
    --context-pid "$$" --grace-end-ms "$_ROUND_RESOURCE_END_MS" || {
      round_fail http_cancel_fence_failed 1
      return 1
    }
  _ROUND_HTTP_CANCEL_PUBLISHED=1
}

stop_pid_group_bounded() {
  (( $# > 0 )) || return 0
  _round_context || return 0
  _round_fixed_windows
  _round_http_publish_cancel || true
  local pid now alive index remaining
  local requested=("$@")
  for pid in "${requested[@]}"; do
    _round_owned "$pid" || continue
    _round_wait_finished "$pid" && continue
    if _round_job_live "$pid"; then
      if _round_http_owner_pid "$pid" && (( _ROUND_HTTP_CANCEL_PUBLISHED != 1 )); then
        round_fail http_cancel_fence_failed 1
      else
        kill -TERM "$pid" 2>/dev/null || true
      fi
    fi
  done
  while :; do
    alive=0
    for pid in "${requested[@]}"; do
      _round_owned "$pid" || continue
      if _round_wait_finished "$pid"; then :; else alive=1; fi
    done
    (( alive == 1 )) || break
    now=$(_round_now)
    if (( now >= _ROUND_RESOURCE_END_MS - 100 )); then
      for pid in "${requested[@]}"; do
        _round_owned "$pid" && _round_job_live "$pid" || continue
        if _round_http_owner_pid "$pid" && (( _ROUND_HTTP_CANCEL_PUBLISHED != 1 )); then
          round_fail http_shutdown_incomplete 1
          continue
        fi
        kill -KILL "$pid" 2>/dev/null || true
        CLEANUP_FORCED=1
        round_fail cleanup_forced_kill 1
        for ((index=0; index < ${#_ROUND_OWNER_PID[@]}; index++)); do
          [[ "${_ROUND_OWNER_PID[$index]}" != "$pid" ]] || _ROUND_OWNER_FORCED[$index]=1
        done
      done
    fi
    (( now < _ROUND_RESOURCE_END_MS )) || break
    remaining=$((_ROUND_RESOURCE_END_MS - now))
    (( remaining <= 10 )) || remaining=10
    sleep "$(printf '0.%03d' "$remaining")"
  done
  # Immediate cached waits are still allowed at the end; no new resource
  # grace is created for a later group or PID.
  for pid in "${requested[@]}"; do _round_wait_finished "$pid" || true; done
}

stop_round_processes() {
  if (( ${#PIDS[@]} > 0 )); then stop_pid_group_bounded "${PIDS[@]}"; fi
}

round_run_collector() {
  local label="$1"; shift
  _round_fixed_windows || return $?
  _round_tool run --deadline-ms "$_ROUND_CAPTURE_END_MS" --grace-end-ms "$_ROUND_RESOURCE_END_MS" \
    --round-dir "$ROUND_DIR" --snapshot --label "$label" \
    --receipt "$ROUND_DIR/.$label-result.json" -- "$@"
}

# The normal collector remains at its original business-stage position with
# the original argv. Record real completion and the captured original output;
# this entry neither rewrites that output nor starts the later cleanup grace.
round_run_original_collector() {
  local outcome status
  _round_context || return 1
  if (( _ROUND_ORIGINAL_COLLECTOR_STARTED != 0 )); then return "$_ROUND_ORIGINAL_COLLECTOR_STATUS"; fi
  _ROUND_ORIGINAL_COLLECTOR_STARTED=1
  if _round_capture_window; then :; else round_fail collector_command_failed 1; return 1; fi
  if outcome=$(_round_tool run --deadline-ms "$_ROUND_CAPTURE_END_MS" --grace-end-ms "$_ROUND_CAPTURE_END_MS" \
      --round-dir "$ROUND_DIR" --label collector --record-output nat-evidence.json \
      --entry-source "$ROOT_DIR/scripts/nat-sim/collect_evidence.py" \
      --receipt "$ROUND_DIR/.collector-result.json" -- "$@"); then
    _ROUND_ORIGINAL_COLLECTOR_STATUS=0
  else
    status=$?
    _ROUND_ORIGINAL_COLLECTOR_STATUS=$status
    case "$outcome" in
      deadline_exhausted|resource_grace_exhausted) round_fail collector_deadline_exhausted "$status" ;;
      *) round_fail collector_command_failed "$status" ;;
    esac
  fi
  return "$_ROUND_ORIGINAL_COLLECTOR_STATUS"
}

round_run_live_phase() {
  local label="$1"; shift
  _round_fixed_windows || return $?
  _round_tool run --deadline-ms "$_ROUND_CAPTURE_END_MS" --grace-end-ms "$_ROUND_RESOURCE_END_MS" \
    --round-dir "$ROUND_DIR" --label "$label" --receipt "$ROUND_DIR/.$label-result.json" -- "$@"
}

finish_round() {
  _round_context || { stop_round_processes; return 0; }
  [[ "$_ROUND_STATE" == open ]] || return 0
  _ROUND_STATE=finalizing
  _round_fixed_windows
  # Let pending HTTP owners consume the same cleanup fence concurrently
  # with status capture, before metadata work spends their TERM budget.
  _round_http_publish_cancel || true
  round_capture_final_statuses || true
  (( STATUS_SCHEMA_OK == 1 )) || round_fail final_status_unavailable 1
  # The source/launch receipt hashes captured declarations and binds roles
  # to owned PIDs; it does not assert that exec_requested proves exec success.
  _round_owner_lines | cut -f1,2 | _round_tool identity --base-dir "$BASE_DIR" --round-dir "$ROUND_DIR" \
    --deadline-ms "$_ROUND_CAPTURE_END_MS" --receipt "$ROUND_DIR/.round-source-identity.json" || true
  if (( _ROUND_NORMAL_TAIL_READY == 1 )) && declare -F round_finish_normal_tail >/dev/null; then
    round_finish_normal_tail
    # A failed phase can leave a registered child pending. Close any such
    # owner through the same fixed resource fence, without re-signalling a
    # child whose actual wait was already recorded.
    stop_round_processes
  else
    stop_round_processes
  fi
  _round_tool trace --round-dir "$ROUND_DIR" --deadline-ms "$_ROUND_CAPTURE_END_MS" \
    --receipt "$ROUND_DIR/.trace-summary.json" || true
  if (( ${#PIDS[@]} > 0 || _ROUND_WAIT_UNKNOWN > 0 )); then round_fail cleanup_incomplete 1; fi
  local shell_status=${_ROUND_EXIT_TRAP_STATUS:--1} shell_source=not_observed
  if (( shell_status >= 0 )); then shell_source=exit_trap
  elif (( ${_ROUND_SIGNAL_EXIT:-0} != 0 )); then shell_status=$_ROUND_SIGNAL_EXIT; shell_source=deferred_signal; fi
  local publish_arguments=(publish --round-dir "$ROUND_DIR" --run-id "${ROUND_RUN_ID:-unknown}"
      --context-pid "$$"
      --reason-code "${ROUND_FINISH_REASON:-completed}" --exit-code "${ROUND_FINISH_EXIT_CODE:-0}"
      --start-ms "$_ROUND_FINALIZER_START_MS" --capture-end-ms "$_ROUND_CAPTURE_END_MS"
      --grace-end-ms "$_ROUND_RESOURCE_END_MS" --started "$_ROUND_STARTED"
      --watchers "$_ROUND_WATCHERS"
      --shell-exit-code "$shell_status" --shell-exit-source "$shell_source"
      --wait-completed "$_ROUND_WAIT_COMPLETED" --wait-unknown "$_ROUND_WAIT_UNKNOWN"
      --pending "${#PIDS[@]}")
  if (( ${CLEANUP_FORCED:-0} != 0 )); then publish_arguments+=(--forced); fi
  if _round_owner_lines | _round_tool "${publish_arguments[@]}"; then
    _ROUND_STATE=finalized
  else
    local publish_status=$?
    if (( publish_status == 2 )); then
      _ROUND_STATE=finalized
      round_fail cleanup_incomplete 1
    else
      _ROUND_STATE=failed
      round_fail finalization_receipt_write_failed 1
    fi
  fi
  if (( ${_ROUND_SIGNAL_EXIT:-0} != 0 && ${_ROUND_IN_CLEANUP:-0} == 0 && ${_ROUND_EXIT_TRAP_STATUS:--1} <= 0 )); then
    exit "$_ROUND_SIGNAL_EXIT"
  fi
}

cleanup() {
  local status=$?
  if (( status != 0 )); then round_fail unexpected_exit "$status"; fi
  _ROUND_IN_CLEANUP=1
  finish_round
  if [[ -n "${PORT_LOCK_DIR:-}" ]]; then
    python3 "$ROOT_DIR/scripts/nat-sim/reserve_port_block.py" --release "$PORT_LOCK_DIR" || true
    PORT_LOCK_DIR=""
  fi
  echo "[nat-sim] artifacts retained: ${BASE_DIR:-unknown}" >&2
  _ROUND_IN_CLEANUP=0
  if (( ${_ROUND_SIGNAL_EXIT:-0} != 0 && ${_ROUND_EXIT_TRAP_STATUS:--1} <= 0 )); then exit "$_ROUND_SIGNAL_EXIT"; fi
  return 0
}

round_on_exit() {
  local status="$1"
  _ROUND_EXIT_TRAP_STATUS=$status
  trap - EXIT
  trap '' INT TERM
  (( status == 0 )) || round_fail unexpected_exit "$status"
  cleanup
  if (( status == 0 && ${ROUND_FINISH_EXIT_CODE:-0} != 0 )); then status=$ROUND_FINISH_EXIT_CODE; fi
  exit "$status"
}

round_handle_signal() {
  round_fail "$2" "$1"
  if [[ "${_ROUND_STATE:-}" == finalizing || "${_ROUND_STATE:-}" == initializing ]]; then
    # A signal cannot abandon an in-progress owned shutdown. Record it and
    # exit after this same fixed finalizer, without starting another window.
    (( ${_ROUND_SIGNAL_EXIT:-0} != 0 )) || _ROUND_SIGNAL_EXIT=$1
    return 0
  fi
  # A completed finalizer must not let a later signal replace its pending
  # first exit. An already observed nonzero EXIT status still wins.
  if (( ${_ROUND_EXIT_TRAP_STATUS:--1} > 0 )); then exit "$_ROUND_EXIT_TRAP_STATUS"; fi
  if (( ${_ROUND_SIGNAL_EXIT:-0} != 0 )); then exit "$_ROUND_SIGNAL_EXIT"; fi
  exit "$1"
}
round_install_traps() {
  trap 'round_on_exit $?' EXIT
  trap 'round_handle_signal 130 interrupted' INT
  trap 'round_handle_signal 143 terminated' TERM
}
