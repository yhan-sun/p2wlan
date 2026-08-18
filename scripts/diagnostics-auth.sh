#!/usr/bin/env bash

# Read only the daemon's per-process local diagnostics session secret. This is
# intentionally separate from the remote control-plane token.
p2wlan_read_diagnostics_token() {
  local candidates=()
  if [[ -n "${DIAGNOSTICS_AUTH_TOKEN_FILE:-}" ]]; then
    candidates+=("$DIAGNOSTICS_AUTH_TOKEN_FILE")
  fi
  if [[ -n "${HOME:-}" ]]; then
    if [[ "$(uname -s 2>/dev/null || true)" == "Darwin" ]]; then
      candidates+=("$HOME/Library/Logs/p2wlan/p2wlan-daemon.diag-auth")
    fi
    candidates+=("$HOME/.local/state/p2wlan/p2wlan-daemon.diag-auth")
  fi
  local path value
  for path in "${candidates[@]}"; do
    if [[ -r "$path" ]]; then
      value=$(tr -d '\r\n' <"$path")
      if [[ -n "$value" ]]; then
        printf '%s' "$value"
        return 0
      fi
    fi
  done
  return 1
}

p2wlan_diagnostics_curl() {
  local token
  if ! token=$(p2wlan_read_diagnostics_token); then
    echo "diagnostics session token file is missing; daemon session may have changed" >&2
    return 1
  fi
  curl -H "Authorization: Bearer $token" "$@"
}
