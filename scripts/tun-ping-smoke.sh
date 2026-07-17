#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PORT=${PORT:-$((18000 + $$ % 1000))}
GO_BIN=${GO_BIN:-go}
DAEMON_BIN=${DAEMON_BIN:-"$ROOT_DIR/target/debug/p2pnet-daemon"}
REQUIRE=${P2WLAN_REQUIRE_TUN_SMOKE:-0}

SUFFIX=$$
BRIDGE="p2wb$SUFFIX"
NS_A="p2wlan-a-$SUFFIX"
NS_B="p2wlan-b-$SUFFIX"
VETH_A_HOST="p2wah$SUFFIX"
VETH_A_NS="p2wan$SUFFIX"
VETH_B_HOST="p2wbh$SUFFIX"
VETH_B_NS="p2wbn$SUFFIX"
TUN_A="p2wta$SUFFIX"
TUN_B="p2wtb$SUFFIX"

BRIDGE_IP=${BRIDGE_IP:-172.28.77.1}
NODE_A_LINK_IP=${NODE_A_LINK_IP:-172.28.77.2}
NODE_B_LINK_IP=${NODE_B_LINK_IP:-172.28.77.3}
NODE_A_VIP=${NODE_A_VIP:-10.20.0.2}
NODE_B_VIP=${NODE_B_VIP:-10.20.0.3}
NODE_A_UDP_PORT=${NODE_A_UDP_PORT:-$((22000 + $$ % 1000))}
NODE_B_UDP_PORT=${NODE_B_UDP_PORT:-$((NODE_A_UDP_PORT + 1))}
DIAG_PORT=${DIAG_PORT:-39277}

skip() {
  echo "[tun-smoke] SKIP: $*" >&2
  if [[ "$REQUIRE" == "1" ]]; then
    exit 1
  fi
  exit 0
}

cleanup() {
  if [[ -n "${NODE_A_PID:-}" ]]; then kill "$NODE_A_PID" 2>/dev/null || true; fi
  if [[ -n "${NODE_B_PID:-}" ]]; then kill "$NODE_B_PID" 2>/dev/null || true; fi
  if [[ -n "${SERVER_PID:-}" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  if [[ "${IPTABLES_BRIDGE_RULE_ADDED:-0}" == "1" ]] && command -v iptables >/dev/null 2>&1; then
    iptables -D FORWARD -i "$BRIDGE" -o "$BRIDGE" -j ACCEPT 2>/dev/null || true
  fi
  if command -v ip >/dev/null 2>&1; then
    ip netns pids "$NS_A" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns pids "$NS_B" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    ip link del "$BRIDGE" 2>/dev/null || true
  fi
  if [[ -n "${TMP_DIR:-}" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

fail() {
  echo "[tun-smoke] FAIL: $*" >&2
  echo "--- server.log ---" >&2
  tail -100 "$TMP_DIR/server.log" >&2 || true
  echo "--- node-a.log ---" >&2
  tail -160 "$TMP_DIR/node-a.log" >&2 || true
  echo "--- node-b.log ---" >&2
  tail -160 "$TMP_DIR/node-b.log" >&2 || true
  echo "--- ping-a.log ---" >&2
  tail -80 "$TMP_DIR/ping-a.log" >&2 || true
  echo "--- ping-b.log ---" >&2
  tail -80 "$TMP_DIR/ping-b.log" >&2 || true
  exit 1
}

if [[ "$(uname -s)" != "Linux" ]]; then
  skip "real TUN ping smoke currently requires Linux network namespaces"
fi
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  skip "real TUN ping smoke requires root; run after building with sudo -E"
fi
for cmd in ip ping curl "$GO_BIN"; do
  command -v "$cmd" >/dev/null 2>&1 || skip "missing required command: $cmd"
done
if [[ ! -x "$DAEMON_BIN" ]]; then
  skip "missing daemon binary at $DAEMON_BIN; run cargo build -p p2pnet-daemon first"
fi
for interface in "$BRIDGE" "$VETH_A_HOST" "$VETH_A_NS" "$VETH_B_HOST" "$VETH_B_NS" "$TUN_A" "$TUN_B"; do
  if [[ ${#interface} -gt 15 ]]; then
    skip "generated Linux interface name is too long: $interface"
  fi
done
if [[ ! -c /dev/net/tun ]]; then
  skip "/dev/net/tun is unavailable"
fi
if ! ip netns list >/dev/null 2>&1; then
  skip "Linux network namespaces are unavailable"
fi

TMP_DIR=$(mktemp -d /tmp/p2wlan-tun-smoke.XXXXXX)

if ip link show "$BRIDGE" >/dev/null 2>&1; then
  skip "generated bridge already exists: $BRIDGE"
fi

echo "[tun-smoke] temp dir: $TMP_DIR"
echo "[tun-smoke] namespaces: $NS_A $NS_B"

ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add "$BRIDGE" type bridge
ip link set "$BRIDGE" type bridge stp_state 0 forward_delay 0
ip addr add "$BRIDGE_IP/24" dev "$BRIDGE"
ip link set "$BRIDGE" up
if command -v iptables >/dev/null 2>&1; then
  iptables -I FORWARD 1 -i "$BRIDGE" -o "$BRIDGE" -j ACCEPT
  IPTABLES_BRIDGE_RULE_ADDED=1
fi

ip link add "$VETH_A_HOST" type veth peer name "$VETH_A_NS"
ip link set "$VETH_A_HOST" master "$BRIDGE"
ip link set "$VETH_A_HOST" up
ip link set "$VETH_A_NS" netns "$NS_A"
ip -n "$NS_A" link set lo up
ip -n "$NS_A" addr add "$NODE_A_LINK_IP/24" dev "$VETH_A_NS"
ip -n "$NS_A" link set "$VETH_A_NS" up
ip -n "$NS_A" route replace default via "$BRIDGE_IP"

ip link add "$VETH_B_HOST" type veth peer name "$VETH_B_NS"
ip link set "$VETH_B_HOST" master "$BRIDGE"
ip link set "$VETH_B_HOST" up
ip link set "$VETH_B_NS" netns "$NS_B"
ip -n "$NS_B" link set lo up
ip -n "$NS_B" addr add "$NODE_B_LINK_IP/24" dev "$VETH_B_NS"
ip -n "$NS_B" link set "$VETH_B_NS" up
ip -n "$NS_B" route replace default via "$BRIDGE_IP"

for _ in {1..40}; do
  if ip netns exec "$NS_A" ping -c1 -W1 "$NODE_B_LINK_IP" >/dev/null 2>&1 && \
     ip netns exec "$NS_B" ping -c1 -W1 "$NODE_A_LINK_IP" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
ip netns exec "$NS_A" ping -c1 -W1 "$NODE_B_LINK_IP" >/dev/null 2>&1 || fail "node A link namespace cannot reach node B link IP"
ip netns exec "$NS_B" ping -c1 -W1 "$NODE_A_LINK_IP" >/dev/null 2>&1 || fail "node B link namespace cannot reach node A link IP"

(
  cd "$ROOT_DIR/server"
  PORT="$PORT" DB_PATH="$TMP_DIR/control.db" JWT_SECRET=smoke "$GO_BIN" run .
) >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

for _ in {1..60}; do
  if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then break; fi
  sleep 0.25
done
curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null || fail "control server did not become healthy"

REGISTER_JSON=$(curl -fsS -X POST "http://127.0.0.1:$PORT/api/v1/register" \
  -H 'Content-Type: application/json' \
  -d '{"email":"tun-smoke@example.com","password":"passw0rd"}')
TOKEN=$(printf '%s' "$REGISTER_JSON" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$TOKEN" ]]; then
  fail "failed to parse auth token"
fi

ip netns exec "$NS_A" env RUST_LOG=info "$DAEMON_BIN" \
  --config "$TMP_DIR/node-a.json" \
  --control "http://$BRIDGE_IP:$PORT" \
  --network default \
  --token "$TOKEN" \
  --device-name node-a \
  --interface "$TUN_A" \
  --address "$NODE_A_VIP" \
  --netmask 255.255.255.255 \
  --udp-bind 0.0.0.0:$NODE_A_UDP_PORT \
  --udp-advertise "$NODE_A_LINK_IP:$NODE_A_UDP_PORT" \
  --diagnostics-bind 127.0.0.1:$DIAG_PORT \
  --heartbeat-interval 5 \
  >"$TMP_DIR/node-a.log" 2>&1 &
NODE_A_PID=$!

for _ in {1..80}; do
  if grep -q "Registered with control server! Virtual IP: $NODE_A_VIP" "$TMP_DIR/node-a.log" 2>/dev/null && \
     ip -n "$NS_A" link show "$TUN_A" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
ip -n "$NS_A" link show "$TUN_A" >/dev/null 2>&1 || fail "node A TUN interface was not created"
grep -q "Registered with control server! Virtual IP: $NODE_A_VIP" "$TMP_DIR/node-a.log" 2>/dev/null || fail "node A did not receive expected virtual IP $NODE_A_VIP"
ip -n "$NS_A" route replace "$NODE_B_VIP/32" dev "$TUN_A" src "$NODE_A_VIP"

ip netns exec "$NS_B" env RUST_LOG=info "$DAEMON_BIN" \
  --config "$TMP_DIR/node-b.json" \
  --control "http://$BRIDGE_IP:$PORT" \
  --network default \
  --token "$TOKEN" \
  --device-name node-b \
  --interface "$TUN_B" \
  --address "$NODE_B_VIP" \
  --netmask 255.255.255.255 \
  --udp-bind 0.0.0.0:$NODE_B_UDP_PORT \
  --udp-advertise "$NODE_B_LINK_IP:$NODE_B_UDP_PORT" \
  --diagnostics-bind 127.0.0.1:$DIAG_PORT \
  --heartbeat-interval 5 \
  >"$TMP_DIR/node-b.log" 2>&1 &
NODE_B_PID=$!

for _ in {1..120}; do
  if grep -q "Registered with control server! Virtual IP: $NODE_B_VIP" "$TMP_DIR/node-b.log" 2>/dev/null && \
     ip -n "$NS_B" link show "$TUN_B" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
ip -n "$NS_B" link show "$TUN_B" >/dev/null 2>&1 || fail "node B TUN interface was not created"
grep -q "Registered with control server! Virtual IP: $NODE_B_VIP" "$TMP_DIR/node-b.log" 2>/dev/null || fail "node B did not receive expected virtual IP $NODE_B_VIP"
ip -n "$NS_B" route replace "$NODE_A_VIP/32" dev "$TUN_B" src "$NODE_B_VIP"

for _ in {1..120}; do
  if grep -q 'Installed WireGuard .* session for node-' "$TMP_DIR/node-a.log" 2>/dev/null && \
     grep -q 'Installed WireGuard .* session for node-' "$TMP_DIR/node-b.log" 2>/dev/null && \
     grep -Eq 'Sent [1-9][0-9]* UDP punch probes to peer' "$TMP_DIR/node-a.log" 2>/dev/null && \
     grep -Eq 'Sent [1-9][0-9]* UDP punch probes to peer' "$TMP_DIR/node-b.log" 2>/dev/null; then
    break
  fi
  sleep 0.5
done

grep -q 'Installed WireGuard .* session for node-' "$TMP_DIR/node-a.log" 2>/dev/null || fail "node A did not install WireGuard session"
grep -q 'Installed WireGuard .* session for node-' "$TMP_DIR/node-b.log" 2>/dev/null || fail "node B did not install WireGuard session"

for _ in {1..80}; do
  if ip netns exec "$NS_A" curl -fsS "http://127.0.0.1:$DIAG_PORT/health" >/dev/null 2>&1 && \
     ip netns exec "$NS_B" curl -fsS "http://127.0.0.1:$DIAG_PORT/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
ip netns exec "$NS_A" curl -fsS "http://127.0.0.1:$DIAG_PORT/health" >/dev/null 2>&1 || fail "node A diagnostics endpoint did not become healthy"
ip netns exec "$NS_B" curl -fsS "http://127.0.0.1:$DIAG_PORT/health" >/dev/null 2>&1 || fail "node B diagnostics endpoint did not become healthy"

ip netns exec "$NS_A" ping -c 3 -W 2 -I "$NODE_A_VIP" "$NODE_B_VIP" >"$TMP_DIR/ping-a.log" 2>&1 || fail "node A could not ping node B over TUN"
ip netns exec "$NS_B" ping -c 3 -W 2 -I "$NODE_B_VIP" "$NODE_A_VIP" >"$TMP_DIR/ping-b.log" 2>&1 || fail "node B could not ping node A over TUN"

ip netns exec "$NS_A" "$DAEMON_BIN" --status --diagnostics-url "http://127.0.0.1:$DIAG_PORT/status" >"$TMP_DIR/status-a.json" 2>"$TMP_DIR/status-a.log" || fail "node A diagnostics query failed"
ip netns exec "$NS_B" "$DAEMON_BIN" --status --diagnostics-url "http://127.0.0.1:$DIAG_PORT/status" >"$TMP_DIR/status-b.json" 2>"$TMP_DIR/status-b.log" || fail "node B diagnostics query failed"
grep -q '"active_path": "direct"' "$TMP_DIR/status-a.json" || fail "node A did not report direct active path"
grep -q '"active_path": "direct"' "$TMP_DIR/status-b.json" || fail "node B did not report direct active path"

echo "[tun-smoke] PASS: two Linux network namespaces pinged over real TUN via WireGuard/direct UDP"
