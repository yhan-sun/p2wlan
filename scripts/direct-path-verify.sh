#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

DIAGNOSTICS_URL=${DIAGNOSTICS_URL:-http://127.0.0.1:39277/status}
PEER=${PEER:-}
OUT_DIR=${OUT_DIR:-$(mktemp -d /tmp/p2wlan-direct-verify.XXXXXX)}
CAPTURE_SECONDS=${CAPTURE_SECONDS:-0}
IFACE=${IFACE:-}
TCPDUMP_FILTER=${TCPDUMP_FILTER:-}
REQUIRE_PUBLIC_UDP=${REQUIRE_PUBLIC_UDP:-0}
REQUIRE_NO_RELAY=${REQUIRE_NO_RELAY:-0}
REQUIRE_NEW_SCHEMA=${REQUIRE_NEW_SCHEMA:-0}
P2WLAN_BIN=${P2WLAN_BIN:-}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[direct-verify] missing required command: $1" >&2
    exit 1
  }
}

resolve_p2wlan_bin() {
  if [[ -n "$P2WLAN_BIN" ]]; then
    printf '%s\n' "$P2WLAN_BIN"
    return
  fi
  if [[ -x "$ROOT_DIR/target/debug/p2wlan" ]]; then
    printf '%s\n' "$ROOT_DIR/target/debug/p2wlan"
    return
  fi
  if command -v p2wlan >/dev/null 2>&1; then
    command -v p2wlan
    return
  fi
  printf '\n'
}

echo "[direct-verify] diagnostics: $DIAGNOSTICS_URL"
echo "[direct-verify] output: $OUT_DIR"

mkdir -p "$OUT_DIR"
require_cmd curl

curl -fsS "$DIAGNOSTICS_URL" -o "$OUT_DIR/status.json"

P2WLAN_BIN=$(resolve_p2wlan_bin)
if [[ -n "$P2WLAN_BIN" && -x "$P2WLAN_BIN" ]]; then
  "$P2WLAN_BIN" doctor >"$OUT_DIR/doctor.txt" 2>"$OUT_DIR/doctor.err" || true
else
  echo "[direct-verify] p2wlan binary not found; skipped doctor" >"$OUT_DIR/doctor.txt"
fi

if command -v lsof >/dev/null 2>&1; then
  lsof -nP -iUDP -iTCP >"$OUT_DIR/lsof-all.txt" 2>"$OUT_DIR/lsof.err" || true
  grep -Ei '(^COMMAND|p2wlan|p2pnet|UURemote)' "$OUT_DIR/lsof-all.txt" >"$OUT_DIR/lsof-p2wlan.txt" || true
fi

if command -v netstat >/dev/null 2>&1; then
  netstat -rn -f inet >"$OUT_DIR/routes-inet.txt" 2>"$OUT_DIR/routes.err" || true
fi

if [[ "$CAPTURE_SECONDS" =~ ^[0-9]+$ && "$CAPTURE_SECONDS" -gt 0 ]]; then
  require_cmd tcpdump
  if [[ -z "$IFACE" ]]; then
    echo "[direct-verify] CAPTURE_SECONDS set but IFACE is empty; set IFACE=en0/en5/utunX" >&2
    exit 2
  fi
  if [[ -z "$TCPDUMP_FILTER" ]]; then
    TCPDUMP_FILTER=$(python3 - "$OUT_DIR/status.json" "$PEER" <<'PY' 2>/dev/null || true
import json, sys
status_path, peer_key = sys.argv[1], sys.argv[2].strip().lower()
status = json.load(open(status_path, encoding="utf-8"))
peers = status.get("peers") or []
if peer_key:
    peers = [
        p for p in peers
        if peer_key in str(p.get("node_id", "")).lower()
        or peer_key in str(p.get("device_name", "")).lower()
        or peer_key in str(p.get("virtual_ip", "")).lower()
    ]
hosts = []
for peer in peers[:4]:
    for key in ("selected_pair", "current_direct_pair"):
        pair = peer.get(key) or {}
        endpoint = pair.get("remote_endpoint")
        if endpoint and ":" in endpoint:
            hosts.append(endpoint.rsplit(":", 1)[0].strip("[]"))
hosts = sorted(set(hosts))
if hosts:
    print("udp and (" + " or ".join(f"host {host}" for host in hosts) + ")")
else:
    print("udp")
PY
)
    TCPDUMP_FILTER=${TCPDUMP_FILTER:-udp}
  fi
  echo "[direct-verify] tcpdump: sudo tcpdump -i $IFACE -n -tttt '$TCPDUMP_FILTER'"
  sudo tcpdump -i "$IFACE" -n -tttt "$TCPDUMP_FILTER" >"$OUT_DIR/tcpdump.txt" 2>"$OUT_DIR/tcpdump.err" &
  TCPDUMP_PID=$!
  sleep "$CAPTURE_SECONDS"
  kill "$TCPDUMP_PID" >/dev/null 2>&1 || true
  wait "$TCPDUMP_PID" >/dev/null 2>&1 || true
fi

if command -v python3 >/dev/null 2>&1; then
  python3 - "$OUT_DIR/status.json" "$PEER" "$REQUIRE_PUBLIC_UDP" "$REQUIRE_NO_RELAY" "$REQUIRE_NEW_SCHEMA" <<'PY' | tee "$OUT_DIR/verdict.txt"
import ipaddress
import json
import sys

status_path, peer_key, require_public_udp, require_no_relay, require_new_schema = sys.argv[1:6]
peer_key = peer_key.strip().lower()
require_public_udp = require_public_udp == "1"
require_no_relay = require_no_relay == "1"
require_new_schema = require_new_schema == "1"
status = json.load(open(status_path, encoding="utf-8"))
peers = status.get("peers") or []
if peer_key:
    peers = [
        p for p in peers
        if peer_key in str(p.get("node_id", "")).lower()
        or peer_key in str(p.get("device_name", "")).lower()
        or peer_key in str(p.get("virtual_ip", "")).lower()
    ]

def endpoint_host(endpoint):
    if not endpoint or ":" not in endpoint:
        return None
    if endpoint.startswith("["):
        return endpoint[1:].split("]", 1)[0]
    return endpoint.rsplit(":", 1)[0]

def endpoint_is_global(endpoint):
    host = endpoint_host(endpoint)
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return False

def pair_text(pair):
    if not pair:
        return "(none)"
    fields = [
        f"local={pair.get('local_endpoint')}",
        f"remote={pair.get('remote_endpoint')}",
        f"remote_type={pair.get('remote_candidate_type') or pair.get('remote_source')}",
        f"state={pair.get('pair_state') or pair.get('state')}",
        f"nominated={pair.get('nominated')}",
        f"selected={pair.get('selected')}",
        f"rtt={pair.get('rtt_ms') or pair.get('rtt_ewma_ms')}ms",
        f"probe_due={pair.get('probe_due')}",
        f"probe_retry_remaining={pair.get('probe_retry_remaining_ms')}ms",
    ]
    if pair.get("warning"):
        fields.append(f"warning={pair.get('warning')}")
    return " ".join(fields)

def event_text(event):
    if not event:
        return "(none)"
    return " ".join([
        f"stage={event.get('stage')}",
        f"age={event.get('age_ms')}ms",
        f"endpoint={event.get('endpoint')}",
        f"detail={event.get('detail')}",
    ])

if not peers:
    print("VERDICT=NO_PEER")
    print("reason=no matching peer in diagnostics")
    sys.exit(1 if (require_public_udp or require_no_relay) else 0)

exit_code = 0

def peer_display_name(peer):
    device_name = str(peer.get("device_name") or "").strip()
    node_id = str(peer.get("node_id") or peer.get("id") or "").strip()
    if device_name and device_name.lower() != "unknown":
        return device_name
    return node_id or device_name or "unknown"

for peer in peers:
    name = peer_display_name(peer)
    vip = peer.get("virtual_ip") or "unknown"
    direct_type = peer.get("direct_type") or "unknown"
    active_path = peer.get("active_path") or "none"
    selected = peer.get("selected_pair")
    current = peer.get("current_direct_pair")
    pair = selected or current or {}
    remote = pair.get("remote_endpoint")
    legacy_schema = "direct_type" not in peer or "selected_pair" not in peer
    false_public = direct_type == "public_udp" and not endpoint_is_global(remote)

    if false_public:
        verdict = "FAIL_FALSE_PUBLIC_UDP"
        exit_code = 1
    elif legacy_schema and active_path == "direct":
        verdict = "LEGACY_DIAGNOSTICS_CANNOT_PROVE_PUBLIC_UDP"
        if require_public_udp or require_new_schema:
            exit_code = 1
    elif peer.get("is_public_udp_direct"):
        verdict = "PASS_PUBLIC_UDP_CONFIRMED"
    elif peer.get("is_overlay_direct"):
        verdict = "OVERLAY_DIRECT_NOT_PUBLIC_NAT"
        if require_public_udp:
            exit_code = 1
    elif peer.get("is_relay") or active_path == "relay":
        verdict = "RELAY_FALLBACK"
        if require_public_udp or require_no_relay:
            exit_code = 1
    elif direct_type == "probing":
        verdict = "PROBING_NOT_CONFIRMED"
        if require_public_udp:
            exit_code = 1
    else:
        verdict = "UNKNOWN_OR_OFFLINE"
        if require_public_udp:
            exit_code = 1
    if legacy_schema and require_new_schema:
        exit_code = 1

    print(f"peer={name} vip={vip}")
    print(f"VERDICT={verdict}")
    schema = "legacy_no_pair_diagnostics" if legacy_schema else "pair_diagnostics"
    print(f"schema={schema}")
    if legacy_schema and require_new_schema:
        print("warning=diagnostics schema is legacy; run a daemon built from this worktree before final public-UDP validation")
    if str(peer.get("device_name", "")).lower() == "this-device":
        print("warning=matched peer appears to be this device; set PEER to the remote virtual IP/node/device for end-to-end validation")
    print(f"active_path={active_path} direct_type={direct_type} probe_key_type={peer.get('probe_key_type')} probe_session_id={peer.get('probe_session_id')} consent_endpoint={peer.get('consent_endpoint')}")
    print(f"selected_pair={pair_text(selected)}")
    print(f"current_direct_pair={pair_text(current)}")
    direct_events = peer.get("direct_events") or []
    if direct_events:
        print("recent_direct_events=")
        for event in direct_events[-5:]:
            print(f"  - {event_text(event)}")
    if peer.get("warning"):
        print(f"warning={peer.get('warning')}")
    print()

sys.exit(exit_code)
PY
else
  echo "[direct-verify] python3 not found; raw diagnostics saved only"
fi

echo "[direct-verify] evidence saved under: $OUT_DIR"
