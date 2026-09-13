#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/baseline_gate.sh"

sentinel=${1:?verification sentinel path required}
diagnostic=${2:?diagnostic path required}

# Exercise the production shell gate with a failing baseline callback. The
# diagnostic is retained, the gate returns nonzero, and the next verification
# command in the caller's real shell control flow must remain unreachable.
capture_baseline_status() {
  printf '%s\n' '{"result":"http_failure"}' >"$diagnostic"
  return 23
}

if output=$(capture_baseline_pair \
    http://a/status /tmp/a.json /tmp/a.token a 101 \
    http://b/status /tmp/b.json /tmp/b.token b 202 2>&1); then
  touch "$sentinel"
  echo "verification unexpectedly followed a failing baseline" >&2
  exit 1
else
  gate_status=$?
fi

[[ "$gate_status" -eq 23 ]]
[[ -s "$diagnostic" ]]
[[ ! -e "$sentinel" ]]
[[ "$output" == *"reason_code=baseline_status_not_available"* ]]
[[ "$output" != *"STATUS_READY"* ]]
