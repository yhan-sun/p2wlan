#!/usr/bin/env bash
set -euo pipefail

# Read-only RSS snapshot helper for the P1 Flutter prototype.
# It only reads process metadata via ps; it never starts, stops, terminates, or
# configures p2pnet-daemon or any UI process.

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'USAGE'
Usage:
  apps/flutter_client/scripts/memory_baseline_macos.sh

Optional environment variables:
  SAMPLES              Number of snapshots to collect. Default: 1
  INTERVAL_SEC         Seconds between snapshots. Default: 5
  TAURI_UI_PATTERN     Extended regex for the Tauri UI process.
  FLUTTER_UI_PATTERN   Extended regex for the Flutter UI process.
  DAEMON_PATTERN       Extended regex for p2pnet-daemon.

Defaults are tuned for this repository:
  TAURI_UI_PATTERN='p2wlan.app/Contents/MacOS/p2wlan-desktop|p2wlan-desktop'
  FLUTTER_UI_PATTERN='p2wlan_flutter_client.app|p2wlan_flutter_client'
  DAEMON_PATTERN='(^|/)p2pnet-daemon($| )'

This script prints PID, RSS, and process basename only. It intentionally does
not print command-line arguments, because daemon args may contain tokens.
USAGE
  exit 0
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This helper currently supports macOS only." >&2
  exit 1
fi

samples="${SAMPLES:-1}"
interval_sec="${INTERVAL_SEC:-5}"
tauri_pattern="${TAURI_UI_PATTERN:-p2wlan.app/Contents/MacOS/p2wlan-desktop|p2wlan-desktop}"
flutter_pattern="${FLUTTER_UI_PATTERN:-p2wlan_flutter_client.app|p2wlan_flutter_client}"
daemon_pattern="${DAEMON_PATTERN:-(^|/)p2pnet-daemon($| )}"

if ! [[ "$samples" =~ ^[0-9]+$ ]] || [[ "$samples" -lt 1 ]]; then
  echo "SAMPLES must be a positive integer." >&2
  exit 2
fi

if ! [[ "$interval_sec" =~ ^[0-9]+$ ]]; then
  echo "INTERVAL_SEC must be a non-negative integer." >&2
  exit 2
fi

for ((sample = 1; sample <= samples; sample += 1)); do
  if [[ "$samples" -gt 1 ]]; then
    echo "== RSS sample ${sample}/${samples} =="
  else
    echo "== RSS sample =="
  fi
  date "+%Y-%m-%d %H:%M:%S %z"

  ps -axo pid=,rss=,command= | awk \
    -v tauri_pattern="$tauri_pattern" \
    -v flutter_pattern="$flutter_pattern" \
    -v daemon_pattern="$daemon_pattern" '
function mib(kib) {
  return kib / 1024
}

function basename(path, parts, count) {
  sub(/[[:space:]].*$/, "", path)
  count = split(path, parts, "/")
  if (parts[count] == "") {
    return path
  }
  return parts[count]
}

function add(category, pid, rss, command) {
  process_count += 1
  process_category[process_count] = category
  process_pid[process_count] = pid
  process_rss[process_count] = rss
  process_name[process_count] = basename(command)

  if (category == "tauri-ui") {
    tauri_rss += rss
  } else if (category == "flutter-ui") {
    flutter_rss += rss
  } else if (category == "daemon") {
    daemon_rss += rss
  }
}

{
  pid = $1
  rss = $2
  $1 = ""
  $2 = ""
  command = $0
  sub(/^[[:space:]]+/, "", command)

  if (command ~ /memory_baseline_macos\.sh/) {
    next
  }
  if (command ~ /^awk[[:space:]]/) {
    next
  }

  if (command ~ daemon_pattern) {
    add("daemon", pid, rss, command)
  } else if (command ~ flutter_pattern) {
    add("flutter-ui", pid, rss, command)
  } else if (command ~ tauri_pattern) {
    add("tauri-ui", pid, rss, command)
  }
}

END {
  printf "%-12s %8s %10s %s\n", "category", "pid", "rss_mib", "process"
  printf "%-12s %8s %10s %s\n", "--------", "---", "-------", "-------"

  if (process_count == 0) {
    printf "%-12s %8s %10s %s\n", "none", "-", "0.0", "no matching processes"
  }

  for (i = 1; i <= process_count; i += 1) {
    printf "%-12s %8s %10.1f %s\n", process_category[i], process_pid[i], mib(process_rss[i]), process_name[i]
  }

  printf "\n"
  printf "%-24s %10.1f MiB\n", "Tauri UI RSS", mib(tauri_rss)
  printf "%-24s %10.1f MiB\n", "Flutter UI RSS", mib(flutter_rss)
  printf "%-24s %10.1f MiB\n", "p2pnet-daemon RSS", mib(daemon_rss)
  printf "%-24s %10.1f MiB\n", "Tauri UI + daemon", mib(tauri_rss + daemon_rss)
  printf "%-24s %10.1f MiB\n", "Flutter UI + daemon", mib(flutter_rss + daemon_rss)
  printf "%-24s %10.1f MiB\n", "Flutter minus Tauri", mib((flutter_rss + daemon_rss) - (tauri_rss + daemon_rss))

  if (tauri_rss == 0 || flutter_rss == 0 || daemon_rss == 0) {
    printf "\n"
    if (tauri_rss == 0) {
      printf "note: no Tauri UI process matched TAURI_UI_PATTERN\n"
    }
    if (flutter_rss == 0) {
      printf "note: no Flutter UI process matched FLUTTER_UI_PATTERN\n"
    }
    if (daemon_rss == 0) {
      printf "note: no p2pnet-daemon process matched DAEMON_PATTERN\n"
    }
  }
}'

  if [[ "$sample" -lt "$samples" ]]; then
    echo
    sleep "$interval_sec"
  fi
done
