#!/usr/bin/env bash
# Real Mini <-> Air dual-end cold-start verification.
#
# Topology:
#   Mini (this machine, macOS M4)  --daemon A-->  real NAT A
#   Air  (<AIR_HOST> via SSH, macOS arm64) --daemon B--> real NAT B
#
# The verification control and relay are external. The two temporary daemons
# connect through their real public NATs; Direct must be proven by both sides
# within the configured strict target.
set -euo pipefail

HARNESS_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
ROOT_DIR=${P2WLAN_ROOT_DIR:-$HARNESS_ROOT}
REMOTE_CONTROL_URL=${REMOTE_CONTROL_URL:-}
ALLOW_STAGING_TEST=${ALLOW_STAGING_TEST:-0}
ALLOW_REAL_DUAL_MACHINE_TEST=${ALLOW_REAL_DUAL_MACHINE_TEST:-0}
ALLOW_REMOTE_RESTART=${ALLOW_REMOTE_RESTART:-0}
ALLOW_LEGACY_PLAINTEXT_RELAY=${ALLOW_LEGACY_PLAINTEXT_RELAY:-0}
# Never relax isolation implicitly. This opt-in permits only a target-scoped
# availability diagnostic on shared staging; it is not strict acceptance.
ALLOW_SHARED_NETWORK=${ALLOW_SHARED_NETWORK:-0}
ROUNDS=${ROUNDS:-}
ACCEPTANCE_MODE=${ACCEPTANCE_MODE:-strict}
STRICT_PHASE=${STRICT_PHASE:-preflight}
DIAG_A_PORT=${DIAG_A_PORT:-49377}
DIAG_B_PORT=${DIAG_B_PORT:-49378}
AIR_HOST=${AIR_HOST:-}
AIR_USER=${AIR_USER:-}
AIR_SSH_PORT=${AIR_SSH_PORT:-22}
AIR_SSH_KEY=${AIR_SSH_KEY:-}
AIR_KNOWN_HOSTS_FILE=${AIR_KNOWN_HOSTS_FILE:-"$HOME/.ssh/known_hosts"}
AIR_DAEMON_BIN=${AIR_DAEMON_BIN:-}
MINI_TAILSCALE_IP=${MINI_TAILSCALE_IP:-}
DIRECT_TIMEOUT_S=${DIRECT_TIMEOUT_S:-30}
DIRECT_SUCCESS_TARGET_MS=${DIRECT_SUCCESS_TARGET_MS:-10000}
# REAL_TUN-only fault injection. This installs a run-scoped macOS pf anchor
# that blocks UDP only to/from the other endpoint's observed public IPv4.
# Control HTTP, relay TCP, TUN and management SSH remain reachable.
DIRECT_UDP_BLACKHOLE=${DIRECT_UDP_BLACKHOLE:-0}
# Availability acceptance target: from the moment BOTH daemons have a relay
# transport connected to the later of the two first-usable events (both sides
# completed a bidirectional encrypted overlay loopback).
AVAILABILITY_FIRST_USABLE_TARGET_MS=${AVAILABILITY_FIRST_USABLE_TARGET_MS:-3000}
VALIDATE_OVERLAY=${VALIDATE_OVERLAY:-0}
REAL_TUN=${REAL_TUN:-0}
OVERLAY_TIMEOUT_S=${OVERLAY_TIMEOUT_S:-12}
AUTHORIZATION_WAIT_S=${AUTHORIZATION_WAIT_S:-180}
# Keep one run-scoped Authorization Services helper alive so repeated
# cold-start rounds do not open a password sheet for every daemon launch or
# teardown.  This does not change the round lifecycle: each round still stops
# the exact daemon and starts a fresh process/config/device.
PRIVILEGED_SUPERVISOR=${PRIVILEGED_SUPERVISOR:-0}
# Optional cross-run mode for unattended staging batches.  The broker remains
# an explicitly opt-in, user-owned FIFO endpoint and is never enabled by
# default.  It survives this harness process (and normal sleep), so a later
# run can reuse the one-time Authorization Services grant without asking the
# operator for another password.  It is intentionally not a production
# service and is not installed into launchd or system configuration.
PERSIST_PRIVILEGED_SUPERVISOR=${PERSIST_PRIVILEGED_SUPERVISOR:-0}
STUN_SERVERS=${STUN_SERVERS:-"stun.cloudflare.com:3478,stun.l.google.com:19302,stun.miwifi.com:3478"}
P2WLAN_NETWORK_OR_TENANT=${P2WLAN_NETWORK_OR_TENANT:-}
NETWORK_ID=${NETWORK_ID:-${P2WLAN_NETWORK_OR_TENANT:-}}
ISOLATION_HELPER="$HARNESS_ROOT/scripts/dual-end/network-isolation.py"
RUN_ID=${RUN_ID:-$(date +%s)-$$}
ARTIFACT_ROOT=${ARTIFACT_ROOT:-}
AB_SEQUENCE_DIR=${AB_SEQUENCE_DIR:-${ARTIFACT_ROOT:-}}
STRICT_PARSER="$HARNESS_ROOT/scripts/dual-end/strict-direct-parser.py"
PRODUCTION_AVAILABILITY_PARSER="$HARNESS_ROOT/scripts/dual-end/production-availability-parser.py"
REMOTE_RUN_DIR="/tmp/p2wlan-direct-$RUN_ID"
LOCAL_RUN_DIR="/tmp/p2wlan-direct-$RUN_ID"
REMOTE_DAEMON_BIN="$REMOTE_RUN_DIR/p2wlan-daemon"
DAEMON_BIN_OVERRIDE=$(printenv DAEMON_BIN_OVERRIDE 2>/dev/null || true)

# Control/relay diagnostics must observe the same host network as UDP.  A
# desktop Clash/http_proxy can otherwise turn a transient proxy 502 into a
# false control failure or report a proxy endpoint unrelated to the daemon's
# candidate source.  The daemon itself defaults to direct proxy mode too; this
# wrapper keeps every local harness curl consistent with that policy.
curl() {
  command curl --noproxy '*' "$@"
}

# This script can upload binaries, restart the Air daemon, delete test
# devices, and run real control-plane requests. Do not infer authorization
# from ACCEPTANCE_MODE: without both explicit opt-ins it is a no-op dry run.
#
# ALLOW_STAGING_TEST is the documented staging opt-in.  The older
# ALLOW_REAL_DUAL_MACHINE_TEST name remains an explicit compatibility alias so
# an already prepared staging command does not silently change behavior, but
# neither name is sufficient without ALLOW_REMOTE_RESTART.
STAGING_TEST_OPT_IN="$ALLOW_STAGING_TEST"
if [[ "$STAGING_TEST_OPT_IN" != "1" && "$ALLOW_REAL_DUAL_MACHINE_TEST" == "1" ]]; then
  STAGING_TEST_OPT_IN=1
fi
if [[ "$STAGING_TEST_OPT_IN" != "1" || "$ALLOW_REMOTE_RESTART" != "1" ]]; then
  echo "[mini-air] DRY-RUN only: set ALLOW_STAGING_TEST=1 and ALLOW_REMOTE_RESTART=1 to authorize real staging actions" >&2
  exit 0
fi

case "$REMOTE_CONTROL_URL" in
  https://*)
    LEGACY_PLAINTEXT_RELAY=0
    ;;
  http://*)
    if [[ "$ALLOW_LEGACY_PLAINTEXT_RELAY" != "1" ]]; then
      echo "[mini-air] REMOTE_CONTROL_URL is HTTP; set ALLOW_LEGACY_PLAINTEXT_RELAY=1 for an explicitly non-secure legacy staging run" >&2
      exit 2
    fi
    LEGACY_PLAINTEXT_RELAY=1
    echo "[mini-air] WARNING: legacy HTTP control/plaintext TCP relay is explicitly enabled; this run cannot prove secure relay staging or release readiness" >&2
    ;;
  *)
    echo "[mini-air] REMOTE_CONTROL_URL must use https://, or http:// with ALLOW_LEGACY_PLAINTEXT_RELAY=1" >&2
    exit 2
    ;;
  esac
case "$ALLOW_SHARED_NETWORK" in
  0|1) ;;
  *)
    echo "[mini-air] ALLOW_SHARED_NETWORK must be 0 or 1" >&2
    exit 2
    ;;
esac
case "$PRIVILEGED_SUPERVISOR" in
  0|1) ;;
  *)
    echo "[mini-air] PRIVILEGED_SUPERVISOR must be 0 or 1" >&2
    exit 2
    ;;
esac
case "$PERSIST_PRIVILEGED_SUPERVISOR" in
  0|1) ;;
  *)
    echo "[mini-air] PERSIST_PRIVILEGED_SUPERVISOR must be 0 or 1" >&2
    exit 2
    ;;
esac
if [[ "$PERSIST_PRIVILEGED_SUPERVISOR" == "1" && "$PRIVILEGED_SUPERVISOR" != "1" ]]; then
  echo "[mini-air] PERSIST_PRIVILEGED_SUPERVISOR=1 requires PRIVILEGED_SUPERVISOR=1" >&2
  exit 2
fi
if [[ -z "$NETWORK_ID" ]]; then
  echo "[mini-air] NETWORK_ID (or P2WLAN_NETWORK_OR_TENANT) is required and must match on Mini and Air" >&2
  exit 2
fi
if [[ -z "$AIR_HOST" || -z "$AIR_USER" || -z "$AIR_SSH_KEY" ]]; then
  echo "[mini-air] AIR_HOST, AIR_USER and AIR_SSH_KEY are required after remote authorization" >&2
  exit 2
fi
if [[ "$AIR_SSH_KEY" != /* || ! -f "$AIR_SSH_KEY" ]]; then
  echo "[mini-air] AIR_SSH_KEY must be an existing absolute path" >&2
  exit 2
fi
if [[ "$AIR_KNOWN_HOSTS_FILE" != /* || ! -f "$AIR_KNOWN_HOSTS_FILE" ]]; then
  echo "[mini-air] AIR_KNOWN_HOSTS_FILE must be an existing absolute path" >&2
  exit 2
fi
MINI_TAILSCALE_IP=${MINI_TAILSCALE_IP:-$(tailscale ip -4 2>/dev/null | head -1 || true)}
if [[ -z "$MINI_TAILSCALE_IP" ]]; then
  echo "[mini-air] MINI_TAILSCALE_IP is required when tailscale is unavailable" >&2
  exit 2
fi

# A root-launched macOS harness cannot necessarily read a user's SSH private
# key (TCC/ACL may reject root even when the file is readable by the owner).
# Run only the SSH client as the key owner; the daemon/test process remains
# root for REAL_TUN.  This does not copy, print, or change the key.
SSH_RUN_PREFIX=""
if [[ "$(id -u)" == "0" ]]; then
  SSH_KEY_OWNER=$(stat -f '%Su' -- "$AIR_SSH_KEY" 2>/dev/null || true)
  if [[ -z "$SSH_KEY_OWNER" || "$SSH_KEY_OWNER" == "root" ]]; then
    echo "[mini-air] could not determine a non-root owner for AIR_SSH_KEY while running as root" >&2
    exit 2
  fi
  SSH_RUN_PREFIX="sudo -u $SSH_KEY_OWNER "
fi

# Do not include the arbitrary run id in the Unix-domain socket path: long,
# auditable run ids exceed macOS's sockaddr_un limit before the first SSH
# command. `%C` is the OpenSSH hash of the connection tuple and keeps runs
# isolated without making the path unbounded.
AIR_SSH="${SSH_RUN_PREFIX}ssh -i $AIR_SSH_KEY -p $AIR_SSH_PORT -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$AIR_KNOWN_HOSTS_FILE -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPersist=120 -o ControlPath=/tmp/p2wlan-direct-%C $AIR_USER@$AIR_HOST"

# An SSH login can belong to the same account as the logged-in Air user while
# still being outside that user's GUI launchd bootstrap.  Authorization
# Services then creates SecurityAgent but may present its password sheet to no
# visible desktop.  Resolve the active console UID once and enter its bootstrap
# explicitly for every remote authorization call.  The value is only a UID;
# credentials and command payloads remain inside the existing base64 fragment.
AIR_LOGIN_UID=$($AIR_SSH 'id -u')
AIR_CONSOLE_UID=$($AIR_SSH 'stat -f "%u" /dev/console' 2>/dev/null || true)
if [[ ! "$AIR_CONSOLE_UID" =~ ^[0-9]+$ ]]; then
  AIR_CONSOLE_UID="$AIR_LOGIN_UID"
fi

# Stable, private locations used only when cross-run supervisor reuse is
# explicitly requested.  /tmp is cleared by a reboot, which is desirable:
# the authorization must be re-established after a machine restart instead of
# silently becoming a long-lived system service.  Directory permissions are
# checked before an existing broker is reused.
LOCAL_PERSISTENT_SUPERVISOR_DIR=${P2WLAN_LOCAL_SUPERVISOR_DIR:-"/tmp/p2wlan-real-tun-supervisor-$(id -u)"}
REMOTE_PERSISTENT_SUPERVISOR_DIR=${P2WLAN_REMOTE_SUPERVISOR_DIR:-"/tmp/p2wlan-real-tun-supervisor-$AIR_LOGIN_UID"}

# Run a remote shell fragment through macOS Authorization Services without
# putting the Air password in a command argument, log, or artifact. The
# fragment is sent as base64 over the already-authenticated SSH channel and is
# decoded only inside the privileged `do shell script` invocation.
remote_osascript_shell() {
  local remote_command=$1
  local encoded
  encoded=$(printf '%s' "$remote_command" | /usr/bin/base64 | tr -d '\n')
  $AIR_SSH "/bin/launchctl asuser '$AIR_CONSOLE_UID' /usr/bin/osascript -e 'do shell script \"printf %s $encoded | /usr/bin/base64 -D | /bin/sh\" with administrator privileges with prompt \"P2WLAN staging REAL_TUN authorization\"'"
}

remote_osascript_shell_launch() {
  local remote_command=$1
  local pid_file=$2
  local encoded
  encoded=$(printf '%s' "$remote_command" | /usr/bin/base64 | tr -d '\n')
  # Do not hold the harness on the SSH/osascript wrapper. Authorization
  # Services can keep that wrapper alive after the privileged daemon has
  # detached. The daemon-owned PID file is the startup acknowledgement;
  # cleanup terminates the local SSH helper if it remains open.
  $AIR_SSH "/bin/launchctl asuser '$AIR_CONSOLE_UID' /usr/bin/osascript -e 'do shell script \"printf %s $encoded | /usr/bin/base64 -D | /bin/sh >/dev/null 2>&1 &\" with administrator privileges with prompt \"P2WLAN staging REAL_TUN authorization\"'" \
    >/dev/null 2>&1 &
  local auth_pid=$!
  REMOTE_AUTH_HELPER_PIDS="$REMOTE_AUTH_HELPER_PIDS $auth_pid"
  echo "[mini-air] waiting up to ${AUTHORIZATION_WAIT_S}s for Air REAL_TUN authorization" >&2
  for _ in $(seq 1 $((AUTHORIZATION_WAIT_S * 10))); do
    if $AIR_SSH "test -s '$pid_file'" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  kill "$auth_pid" 2>/dev/null || true
  return 1
}

# The user-facing harness is intentionally runnable from an ordinary Terminal
# session.  On macOS the local daemon can still get a real utun through the
# same global Authorization Services dialog used by the tray app.
local_osascript_shell() {
  local local_command=$1
  local encoded
  encoded=$(printf '%s' "$local_command" | /usr/bin/base64 | tr -d '\n')
  # Invoke osascript directly from the user's GUI session so Authorization
  # Services presents the global password sheet.  `launchctl asuser` is needed
  # for Air over SSH, but using it locally can leave the sheet detached from
  # the visible console even though osascript eventually returns.  Keep this
  # synchronous so startup/cleanup observe the privileged fragment's status;
  # the password is never put in a shell argument, file, or artifact.
  /usr/bin/osascript \
    -e "do shell script \"printf %s $encoded | /usr/bin/base64 -D | /bin/sh\" with administrator privileges with prompt \"P2WLAN staging REAL_TUN authorization\""
}

local_osascript_shell_launch() {
  local local_command=$1
  local pid_file=$2
  local auth_status_file="${pid_file}.auth-status"
  local auth_log_file="${pid_file}.auth.log"
  local encoded
  encoded=$(printf '%s' "$local_command" | /usr/bin/base64 | tr -d '\n')
  : >"$auth_status_file"
  : >"$auth_log_file"
  # Authorization Services can keep the `do shell script ... &` wrapper alive
  # after the privileged daemon has detached. Run only that wrapper in the
  # background; the daemon-owned PID file is the startup acknowledgement, and
  # cleanup terminates the helper. The user still receives the same global
  # osascript password dialog.
  (
    if local_osascript_shell "printf %s '$encoded' | /usr/bin/base64 -D | /bin/sh >/dev/null 2>&1 &" \
      >"$auth_log_file" 2>&1; then
      printf '%s\n' authorized >"$auth_status_file"
    else
      rc=$?
      printf 'osascript_exit=%s\n' "$rc" >"$auth_status_file"
    fi
  ) &
  local auth_pid=$!
  LOCAL_AUTH_HELPER_PIDS="$LOCAL_AUTH_HELPER_PIDS $auth_pid"
  echo "[mini-air] waiting up to ${AUTHORIZATION_WAIT_S}s for Mini REAL_TUN authorization" >&2
  for _ in $(seq 1 $((AUTHORIZATION_WAIT_S * 10))); do
    if [[ -s "$pid_file" ]]; then
      return 0
    fi
    if [[ -s "$auth_status_file" ]]; then
      echo "[mini-air] Mini REAL_TUN authorization result: $(tr '\n' ' ' <"$auth_status_file")" >&2
      if [[ -s "$auth_log_file" ]]; then
        echo "[mini-air] Mini REAL_TUN authorization diagnostics:" >&2
        sed -E 's/(Authorization:|Bearer[[:space:]]+)[^[:space:]]+/\1<redacted>/g' \
          "$auth_log_file" >&2 || true
      fi
      return 1
    fi
    sleep 0.1
  done
  kill "$auth_pid" 2>/dev/null || true
  printf 'timeout=%ss\n' "$AUTHORIZATION_WAIT_S" >"$auth_status_file"
  return 1
}

# Run-scoped privilege broker.  The only privileged process kept alive is a
# FIFO reader created by Authorization Services once per endpoint.  Daemon
# START/STOP payloads are base64-framed and generated by this script; no
# password, token, ticket, or Authorization header crosses the FIFO.  The
# broker is deliberately opt-in because it is only useful for real-TUN runs.
local_privileged_supervisor_reuse_existing() {
  [[ "$PERSIST_PRIVILEGED_SUPERVISOR" == "1" ]] || return 1
  local owner mode fifo_mode pid_mode ready_mode supervisor_pid
  owner=$(stat -f '%Su' "$LOCAL_PRIVILEGED_SUPERVISOR_DIR" 2>/dev/null || true)
  mode=$(stat -f '%Lp' "$LOCAL_PRIVILEGED_SUPERVISOR_DIR" 2>/dev/null || true)
  fifo_mode=$(stat -f '%Lp' "$LOCAL_PRIVILEGED_SUPERVISOR_FIFO" 2>/dev/null || true)
  pid_mode=$(stat -f '%Lp' "$LOCAL_PRIVILEGED_SUPERVISOR_PID_FILE" 2>/dev/null || true)
  ready_mode=$(stat -f '%Lp' "$LOCAL_PRIVILEGED_SUPERVISOR_READY" 2>/dev/null || true)
  if [[ "$owner" != "$(id -un)" || "$mode" != "700" ||
        ! -p "$LOCAL_PRIVILEGED_SUPERVISOR_FIFO" || "$fifo_mode" != "600" ||
        ! -s "$LOCAL_PRIVILEGED_SUPERVISOR_PID_FILE" || "$pid_mode" != "600" ||
        ! -s "$LOCAL_PRIVILEGED_SUPERVISOR_READY" || "$ready_mode" != "600" ||
        "$(tr -d '\n' <"$LOCAL_PRIVILEGED_SUPERVISOR_READY" 2>/dev/null || true)" != "ready" ]]; then
    echo "[mini-air] refusing to reuse incomplete or unsafe persistent Mini supervisor state: $LOCAL_PRIVILEGED_SUPERVISOR_DIR" >&2
    return 1
  fi
  supervisor_pid=$(tr -d '\n' <"$LOCAL_PRIVILEGED_SUPERVISOR_PID_FILE" 2>/dev/null || true)
  case "$supervisor_pid" in
    ''|*[!0-9]*)
      echo "[mini-air] refusing to reuse persistent Mini supervisor with invalid PID state" >&2
      return 1
      ;;
  esac
  if ! ps -p "$supervisor_pid" -o pid= >/dev/null 2>&1; then
    echo "[mini-air] persistent Mini supervisor state is stale; refusing to delete or replace it: $LOCAL_PRIVILEGED_SUPERVISOR_DIR" >&2
    return 1
  fi
  LOCAL_PRIVILEGED_SUPERVISOR_ACTIVE=1
  echo "[mini-air] reusing persistent Mini REAL_TUN supervisor; no new authorization dialog" >&2
  return 0
}

local_privileged_supervisor_start() {
  [[ "$PRIVILEGED_SUPERVISOR" == "1" && "$LOCAL_DAEMON_NEEDS_OSASCRIPT" == "1" ]] || return 0
  if [[ "$PERSIST_PRIVILEGED_SUPERVISOR" == "1" && -e "$LOCAL_PRIVILEGED_SUPERVISOR_DIR" ]]; then
    local_privileged_supervisor_reuse_existing
    return $?
  fi
  if [[ "$PERSIST_PRIVILEGED_SUPERVISOR" != "1" &&
        ( -e "$LOCAL_PRIVILEGED_SUPERVISOR_FIFO" || -e "$LOCAL_PRIVILEGED_SUPERVISOR_PID_FILE" || -e "$LOCAL_PRIVILEGED_SUPERVISOR_READY" ) ]]; then
    echo "[mini-air] refusing to reuse local privileged supervisor files" >&2
    return 1
  fi
  mkdir -m 700 "$LOCAL_PRIVILEGED_SUPERVISOR_DIR"
  mkfifo -m 600 "$LOCAL_PRIVILEGED_SUPERVISOR_FIFO"
  : >"$LOCAL_PRIVILEGED_SUPERVISOR_PID_FILE"
  : >"$LOCAL_PRIVILEGED_SUPERVISOR_READY"
  chmod 600 "$LOCAL_PRIVILEGED_SUPERVISOR_PID_FILE" "$LOCAL_PRIVILEGED_SUPERVISOR_READY"

  local supervisor_script script_q fifo_q pid_q ready_q start_command
  IFS= read -r -d '' supervisor_script <<'SUPERVISOR' || true
exec 3<> "$P2WLAN_PRIV_FIFO"
printf '%s\n' "$$" > "$P2WLAN_PRIV_PID"
printf 'ready\n' > "$P2WLAN_PRIV_READY"
while IFS= read -r line <&3; do
  case "$line" in
    EXEC:*)
      payload="${line#EXEC:}"
      printf '%s' "$payload" | /usr/bin/base64 -D | /bin/sh >/dev/null 2>&1 &
      ;;
    STOP:*)
      target="${line#STOP:}"
      case "$target" in
        ''|*[!0-9]*) ;;
        *) kill -TERM "$target" 2>/dev/null || true; sleep 1; kill -KILL "$target" 2>/dev/null || true ;;
      esac
      ;;
    EXIT) exit 0 ;;
  esac
done
SUPERVISOR
  printf -v script_q '%q' "$supervisor_script"
  printf -v fifo_q '%q' "$LOCAL_PRIVILEGED_SUPERVISOR_FIFO"
  printf -v pid_q '%q' "$LOCAL_PRIVILEGED_SUPERVISOR_PID_FILE"
  printf -v ready_q '%q' "$LOCAL_PRIVILEGED_SUPERVISOR_READY"
  # Authorization Services rejects nohup here (no controlling TTY), while
  # explicit stdio redirection already gives the detached helper a stable
  # lifetime.
  start_command="P2WLAN_PRIV_FIFO=$fifo_q P2WLAN_PRIV_PID=$pid_q P2WLAN_PRIV_READY=$ready_q /bin/sh -c $script_q </dev/null >/dev/null 2>&1 &"
  echo "[mini-air] requesting one Mini REAL_TUN authorization for this entire run" >&2
  if ! local_osascript_shell "$start_command" >/dev/null 2>&1; then
    echo "[mini-air] Mini privileged supervisor authorization failed" >&2
    return 1
  fi
  for _ in $(seq 1 $((AUTHORIZATION_WAIT_S * 10))); do
    if [[ -s "$LOCAL_PRIVILEGED_SUPERVISOR_PID_FILE" && -s "$LOCAL_PRIVILEGED_SUPERVISOR_READY" ]]; then
      LOCAL_PRIVILEGED_SUPERVISOR_ACTIVE=1
      if [[ "$PERSIST_PRIVILEGED_SUPERVISOR" == "1" ]]; then
        echo "[mini-air] Mini persistent privileged supervisor ready; later runs reuse this authorization" >&2
      else
        echo "[mini-air] Mini privileged supervisor ready; later rounds reuse this authorization" >&2
      fi
      return 0
    fi
    sleep 0.1
  done
  echo "[mini-air] Mini privileged supervisor did not become ready" >&2
  return 1
}

remote_privileged_supervisor_reuse_existing() {
  [[ "$PERSIST_PRIVILEGED_SUPERVISOR" == "1" ]] || return 1
  if $AIR_SSH "dir='$REMOTE_PRIVILEGED_SUPERVISOR_DIR'; fifo='$REMOTE_PRIVILEGED_SUPERVISOR_FIFO'; pid_file='$REMOTE_PRIVILEGED_SUPERVISOR_PID_FILE'; ready='$REMOTE_PRIVILEGED_SUPERVISOR_READY'; test -d \"\$dir\"; test \"\$(stat -f '%Su' \"\$dir\")\" = '$AIR_USER'; test \"\$(stat -f '%Lp' \"\$dir\")\" = 700; test -p \"\$fifo\"; test \"\$(stat -f '%Lp' \"\$fifo\")\" = 600; test -s \"\$pid_file\"; test \"\$(stat -f '%Lp' \"\$pid_file\")\" = 600; test -s \"\$ready\"; test \"\$(stat -f '%Lp' \"\$ready\")\" = 600; test \"\$(tr -d '\\n' < \"\$ready\")\" = ready; pid=\$(tr -d '\\n' < \"\$pid_file\"); case \"\$pid\" in ''|*[!0-9]*) exit 1;; esac; ps -p \"\$pid\" -o pid= >/dev/null 2>&1" >/dev/null 2>&1; then
    REMOTE_PRIVILEGED_SUPERVISOR_ACTIVE=1
    echo "[mini-air] reusing persistent Air REAL_TUN supervisor; no new authorization dialog" >&2
    return 0
  fi
  echo "[mini-air] persistent Air supervisor state is missing, unsafe or stale; refusing to delete or replace it: $REMOTE_PRIVILEGED_SUPERVISOR_DIR" >&2
  return 1
}

remote_privileged_supervisor_start() {
  [[ "$PRIVILEGED_SUPERVISOR" == "1" && "$AIR_REMOTE_NEEDS_OSASCRIPT" == "1" ]] || return 0
  if [[ "$PERSIST_PRIVILEGED_SUPERVISOR" == "1" ]]; then
    if $AIR_SSH "test -e '$REMOTE_PRIVILEGED_SUPERVISOR_DIR'" >/dev/null 2>&1; then
      remote_privileged_supervisor_reuse_existing
      return $?
    fi
  fi
  if [[ "$PERSIST_PRIVILEGED_SUPERVISOR" != "1" ]] && ! $AIR_SSH "if test -e '$REMOTE_PRIVILEGED_SUPERVISOR_FIFO' || test -e '$REMOTE_PRIVILEGED_SUPERVISOR_PID_FILE' || test -e '$REMOTE_PRIVILEGED_SUPERVISOR_READY'; then exit 1; fi"; then
    echo "[mini-air] refusing to reuse or create Air privileged supervisor files" >&2
    return 1
  fi
  if ! $AIR_SSH "umask 077; mkdir -m 700 '$REMOTE_PRIVILEGED_SUPERVISOR_DIR'; mkfifo -m 600 '$REMOTE_PRIVILEGED_SUPERVISOR_FIFO'; : > '$REMOTE_PRIVILEGED_SUPERVISOR_PID_FILE'; : > '$REMOTE_PRIVILEGED_SUPERVISOR_READY'; chmod 600 '$REMOTE_PRIVILEGED_SUPERVISOR_PID_FILE' '$REMOTE_PRIVILEGED_SUPERVISOR_READY'"; then
    echo "[mini-air] could not create Air privileged supervisor state" >&2
    return 1
  fi

  local supervisor_script script_q fifo_q pid_q ready_q start_command
  IFS= read -r -d '' supervisor_script <<'SUPERVISOR' || true
exec 3<> "$P2WLAN_PRIV_FIFO"
printf '%s\n' "$$" > "$P2WLAN_PRIV_PID"
printf 'ready\n' > "$P2WLAN_PRIV_READY"
while IFS= read -r line <&3; do
  case "$line" in
    EXEC:*)
      payload="${line#EXEC:}"
      printf '%s' "$payload" | /usr/bin/base64 -D | /bin/sh >/dev/null 2>&1 &
      ;;
    STOP:*)
      target="${line#STOP:}"
      case "$target" in
        ''|*[!0-9]*) ;;
        *) kill -TERM "$target" 2>/dev/null || true; sleep 1; kill -KILL "$target" 2>/dev/null || true ;;
      esac
      ;;
    EXIT) exit 0 ;;
  esac
done
SUPERVISOR
  printf -v script_q '%q' "$supervisor_script"
  printf -v fifo_q '%q' "$REMOTE_PRIVILEGED_SUPERVISOR_FIFO"
  printf -v pid_q '%q' "$REMOTE_PRIVILEGED_SUPERVISOR_PID_FILE"
  printf -v ready_q '%q' "$REMOTE_PRIVILEGED_SUPERVISOR_READY"
  start_command="P2WLAN_PRIV_FIFO=$fifo_q P2WLAN_PRIV_PID=$pid_q P2WLAN_PRIV_READY=$ready_q /bin/sh -c $script_q </dev/null >/dev/null 2>&1 &"
  echo "[mini-air] requesting one Air REAL_TUN authorization for this entire run" >&2
  if ! remote_osascript_shell "$start_command" >/dev/null 2>&1; then
    echo "[mini-air] Air privileged supervisor authorization failed" >&2
    return 1
  fi
  for _ in $(seq 1 $((AUTHORIZATION_WAIT_S * 10))); do
    if $AIR_SSH "test -s '$REMOTE_PRIVILEGED_SUPERVISOR_PID_FILE' && test -s '$REMOTE_PRIVILEGED_SUPERVISOR_READY'" >/dev/null 2>&1; then
      REMOTE_PRIVILEGED_SUPERVISOR_ACTIVE=1
      if [[ "$PERSIST_PRIVILEGED_SUPERVISOR" == "1" ]]; then
        echo "[mini-air] Air persistent privileged supervisor ready; later runs reuse this authorization" >&2
      else
        echo "[mini-air] Air privileged supervisor ready; later rounds reuse this authorization" >&2
      fi
      return 0
    fi
    sleep 0.1
  done
  echo "[mini-air] Air privileged supervisor did not become ready" >&2
  return 1
}

local_privileged_exec() {
  [[ "$LOCAL_PRIVILEGED_SUPERVISOR_ACTIVE" == "1" ]] || return 1
  local payload
  payload=$(printf '%s' "$1" | /usr/bin/base64 | tr -d '\n')
  printf 'EXEC:%s\n' "$payload" >"$LOCAL_PRIVILEGED_SUPERVISOR_FIFO"
}

remote_privileged_exec() {
  [[ "$REMOTE_PRIVILEGED_SUPERVISOR_ACTIVE" == "1" ]] || return 1
  local payload
  payload=$(printf '%s' "$1" | /usr/bin/base64 | tr -d '\n')
  $AIR_SSH "printf 'EXEC:%s\\n' '$payload' > '$REMOTE_PRIVILEGED_SUPERVISOR_FIFO'"
}

wait_for_local_pid_file() {
  local pid_file=$1
  for _ in $(seq 1 $((AUTHORIZATION_WAIT_S * 10))); do
    [[ -s "$pid_file" ]] && return 0
    sleep 0.1
  done
  return 1
}

wait_for_remote_pid_file() {
  local pid_file=$1
  for _ in $(seq 1 $((AUTHORIZATION_WAIT_S * 10))); do
    $AIR_SSH "test -s '$pid_file'" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

local_privileged_stop_supervisor() {
  [[ "$LOCAL_PRIVILEGED_SUPERVISOR_ACTIVE" == "1" ]] || return 0
  if [[ "$PERSIST_PRIVILEGED_SUPERVISOR" == "1" ]]; then
    echo "[mini-air] keeping persistent Mini REAL_TUN supervisor for the next run" >&2
    LOCAL_PRIVILEGED_SUPERVISOR_ACTIVE=0
    return 0
  fi
  printf 'EXIT\n' >"$LOCAL_PRIVILEGED_SUPERVISOR_FIFO" || true
  for _ in {1..20}; do
    if ! ps -p "$(cat "$LOCAL_PRIVILEGED_SUPERVISOR_PID_FILE" 2>/dev/null || true)" -o pid= >/dev/null 2>&1; then break; fi
    sleep 0.1
  done
  LOCAL_PRIVILEGED_SUPERVISOR_ACTIVE=0
}

remote_privileged_stop_supervisor() {
  [[ "$REMOTE_PRIVILEGED_SUPERVISOR_ACTIVE" == "1" ]] || return 0
  if [[ "$PERSIST_PRIVILEGED_SUPERVISOR" == "1" ]]; then
    echo "[mini-air] keeping persistent Air REAL_TUN supervisor for the next run" >&2
    REMOTE_PRIVILEGED_SUPERVISOR_ACTIVE=0
    return 0
  fi
  $AIR_SSH "printf 'EXIT\\n' > '$REMOTE_PRIVILEGED_SUPERVISOR_FIFO'" >/dev/null 2>&1 || true
  local supervisor_pid
  supervisor_pid=$($AIR_SSH "cat '$REMOTE_PRIVILEGED_SUPERVISOR_PID_FILE' 2>/dev/null || true")
  for _ in {1..20}; do
    if ! $AIR_SSH "test -n '$supervisor_pid' && ps -p '$supervisor_pid' -o pid= >/dev/null 2>&1" >/dev/null 2>&1; then break; fi
    sleep 0.1
  done
  REMOTE_PRIVILEGED_SUPERVISOR_ACTIVE=0
}

stop_privileged_supervisors() {
  remote_privileged_stop_supervisor
  local_privileged_stop_supervisor
}

stop_auth_helpers() {
  local pid
  for pid in $LOCAL_AUTH_HELPER_PIDS $REMOTE_AUTH_HELPER_PIDS; do
    [[ -n "$pid" ]] || continue
    kill "$pid" 2>/dev/null || true
  done
  LOCAL_AUTH_HELPER_PIDS=""
  REMOTE_AUTH_HELPER_PIDS=""
}

AIR_REMOTE_NEEDS_OSASCRIPT=0
LOCAL_DAEMON_NEEDS_OSASCRIPT=0

if [[ "$REAL_TUN" == "1" ]]; then
  if [[ "$(id -u)" != "0" ]]; then
    LOCAL_DAEMON_NEEDS_OSASCRIPT=1
  fi
  if [[ "$AIR_LOGIN_UID" != "0" ]]; then
    if [[ "$PRIVILEGED_SUPERVISOR" == "1" ]]; then
      # The supervisor startup below is the single authorization boundary for
      # this run.  Do not perform a separate root probe here, otherwise the
      # user would receive an unnecessary second Air password dialog.
      AIR_REMOTE_NEEDS_OSASCRIPT=1
    else
      if ! remote_osascript_shell 'test "$(id -u)" = 0' >/dev/null 2>&1; then
        echo "[mini-air] REAL_TUN=1 could not obtain Air root through macOS Authorization Services" >&2
        exit 2
      fi
      AIR_REMOTE_NEEDS_OSASCRIPT=1
    fi
  fi
fi

umask 077
if [[ "$(cd "$ROOT_DIR" && pwd -P)" != "$HARNESS_ROOT" ]]; then
  echo "[mini-air] P2WLAN_ROOT_DIR must resolve to the current harness tree; do not point it at a baseline worktree" >&2
  exit 2
fi
ROOT_DIR=$HARNESS_ROOT
case "$ACCEPTANCE_MODE" in
  compat)
    if [[ -z "$DAEMON_BIN_OVERRIDE" ]]; then
      echo "[mini-air] ACCEPTANCE_MODE=compat requires DAEMON_BIN_OVERRIDE for the legacy binary" >&2
      exit 2
    fi
    if [[ "$STRICT_PHASE" != "preflight" ]]; then
      echo "[mini-air] STRICT_PHASE is only meaningful with ACCEPTANCE_MODE=strict" >&2
      exit 2
    fi
    ACCEPTANCE_STAGE=compat-baseline
    ROUNDS=${ROUNDS:-3}
    ;;
  strict)
    if [[ -n "$DAEMON_BIN_OVERRIDE" ]]; then
      echo "[mini-air] ACCEPTANCE_MODE=strict only permits the current-tree build; unset DAEMON_BIN_OVERRIDE" >&2
      exit 2
    fi
    case "$STRICT_PHASE" in
      preflight)
        ACCEPTANCE_STAGE=strict-preflight
        ROUNDS=${ROUNDS:-3}
        ;;
      acceptance)
        ACCEPTANCE_STAGE=strict-acceptance
        ROUNDS=${ROUNDS:-10}
        ;;
      *)
        echo "[mini-air] STRICT_PHASE must be preflight or acceptance" >&2
        exit 2
        ;;
    esac
    ;;
  availability)
    # First-usable availability is a production dataplane check when REAL_TUN
    # is enabled.  The mock overlay validator is allowed only for local
    # preflight/regression runs and can never be evidence for a real run.
    if [[ -n "$DAEMON_BIN_OVERRIDE" ]]; then
      echo "[mini-air] ACCEPTANCE_MODE=availability only permits the current-tree build; unset DAEMON_BIN_OVERRIDE" >&2
      exit 2
    fi
    case "$STRICT_PHASE" in
      preflight)
        ACCEPTANCE_STAGE=availability-preflight
        ROUNDS=${ROUNDS:-3}
        ;;
      acceptance)
        ACCEPTANCE_STAGE=availability-acceptance
        ROUNDS=${ROUNDS:-10}
        ;;
      *)
        echo "[mini-air] STRICT_PHASE must be preflight or acceptance" >&2
        exit 2
        ;;
    esac
    ;;
  *)
    echo "[mini-air] ACCEPTANCE_MODE must be compat, strict or availability" >&2
    exit 2
    ;;
esac
if [[ "$STRICT_PHASE" == "acceptance" && "$REAL_TUN" != "1" ]]; then
  echo "[mini-air] acceptance requires REAL_TUN=1; mock/--validate-overlay-only evidence is not production dataplane evidence" >&2
  exit 2
fi
if [[ "$REAL_TUN" == "1" ]]; then
  if [[ "$VALIDATE_OVERLAY" == "1" ]]; then
    echo "[mini-air] REAL_TUN=1 cannot be combined with VALIDATE_OVERLAY=1" >&2
    exit 2
  fi
  # The SSH login is normally the unprivileged Air user.  Checking sudo
  # above is not enough: the daemon itself must run as root to create utun.
  # Keep this explicit so REAL_TUN cannot accidentally become a user-mode run.
  if [[ "$AIR_LOGIN_UID" == "0" ]]; then
    TUN_REMOTE_RUN_PREFIX="env -u P2WLAN_DISABLE_TUN"
  else
    TUN_REMOTE_RUN_PREFIX="env -u P2WLAN_DISABLE_TUN"
  fi
else
  TUN_REMOTE_RUN_PREFIX="env P2WLAN_DISABLE_TUN=1"
fi
case "$DIRECT_UDP_BLACKHOLE" in
  0|1) ;;
  *)
    echo "[mini-air] DIRECT_UDP_BLACKHOLE must be 0 or 1" >&2
    exit 2
    ;;
esac
if [[ "$DIRECT_UDP_BLACKHOLE" == "1" && ( "$REAL_TUN" != "1" || "$ACCEPTANCE_MODE" != "availability" || "$STRICT_PHASE" != "acceptance" ) ]]; then
  echo "[mini-air] DIRECT_UDP_BLACKHOLE requires REAL_TUN=1, ACCEPTANCE_MODE=availability and STRICT_PHASE=acceptance" >&2
  exit 2
fi
case "$ACCEPTANCE_STAGE" in
  compat-baseline|strict-preflight|availability-preflight)
    [[ "$ROUNDS" == "3" ]] || { echo "[mini-air] $ACCEPTANCE_STAGE requires ROUNDS=3" >&2; exit 2; }
    ;;
  strict-acceptance|availability-acceptance)
    if [[ "$DIRECT_UDP_BLACKHOLE" == "1" ]]; then
      [[ "$ROUNDS" == "20" ]] || { echo "[mini-air] DIRECT_UDP_BLACKHOLE acceptance requires ROUNDS=20" >&2; exit 2; }
    else
      [[ "$ROUNDS" == "10" ]] || { echo "[mini-air] $ACCEPTANCE_STAGE requires ROUNDS=10" >&2; exit 2; }
    fi
    ;;
esac
if [[ -z "$ARTIFACT_ROOT" || -z "$AB_SEQUENCE_DIR" ]]; then
  echo "[mini-air] ARTIFACT_ROOT and AB_SEQUENCE_DIR are required for auditable A/B runs" >&2
  exit 2
fi
if [[ -n "$ARTIFACT_ROOT" ]]; then
  if [[ ! -d "$ARTIFACT_ROOT" ]]; then
    echo "[mini-air] artifact root does not exist: $ARTIFACT_ROOT" >&2
    exit 2
  fi
  BASE_DIR="$ARTIFACT_ROOT/mini-air-$RUN_ID"
  if [[ -e "$BASE_DIR" ]]; then
    echo "[mini-air] refusing to reuse artifact directory: $BASE_DIR" >&2
    exit 2
  fi
mkdir -m 700 "$BASE_DIR"
else
  BASE_DIR=$(mktemp -d /tmp/p2wlan-direct-final.XXXXXX)
  chmod 700 "$BASE_DIR"
fi
mkdir -p -m 700 "$LOCAL_RUN_DIR"
if [[ ! -d "$AB_SEQUENCE_DIR" ]]; then
  echo "[mini-air] A/B sequence directory does not exist: $AB_SEQUENCE_DIR" >&2
  exit 2
fi
REMOTE_NODE_B_PID_FILE=""
NODE_B_PID=""
LOCAL_NODE_A_PID=""
LOCAL_NODE_A_PID_FILE=""
LOCAL_NODE_A_CONFIG=""
LOCAL_NODE_A_TOKEN_FILE=""
LOCAL_NODE_A_DEVICE=""
REMOTE_NODE_B_LOG=""
REMOTE_NODE_B_DEVICE=""
REMOTE_NODE_B_TOKEN_FILE=""
LOCAL_AUTH_HELPER_PIDS=""
REMOTE_AUTH_HELPER_PIDS=""
LOCAL_PRIVILEGED_SUPERVISOR_ACTIVE=0
REMOTE_PRIVILEGED_SUPERVISOR_ACTIVE=0
if [[ "$PERSIST_PRIVILEGED_SUPERVISOR" == "1" ]]; then
  LOCAL_PRIVILEGED_SUPERVISOR_DIR="$LOCAL_PERSISTENT_SUPERVISOR_DIR"
  REMOTE_PRIVILEGED_SUPERVISOR_DIR="$REMOTE_PERSISTENT_SUPERVISOR_DIR"
else
  LOCAL_PRIVILEGED_SUPERVISOR_DIR="$LOCAL_RUN_DIR/privileged-supervisor"
  REMOTE_PRIVILEGED_SUPERVISOR_DIR="$REMOTE_RUN_DIR/privileged-supervisor"
fi
LOCAL_PRIVILEGED_SUPERVISOR_FIFO="$LOCAL_PRIVILEGED_SUPERVISOR_DIR/commands"
LOCAL_PRIVILEGED_SUPERVISOR_PID_FILE="$LOCAL_PRIVILEGED_SUPERVISOR_DIR/supervisor.pid"
LOCAL_PRIVILEGED_SUPERVISOR_READY="$LOCAL_PRIVILEGED_SUPERVISOR_DIR/ready"
REMOTE_PRIVILEGED_SUPERVISOR_FIFO="$REMOTE_PRIVILEGED_SUPERVISOR_DIR/commands"
REMOTE_PRIVILEGED_SUPERVISOR_PID_FILE="$REMOTE_PRIVILEGED_SUPERVISOR_DIR/supervisor.pid"
REMOTE_PRIVILEGED_SUPERVISOR_READY="$REMOTE_PRIVILEGED_SUPERVISOR_DIR/ready"
DIRECT_BLACKHOLE_ANCHOR="com.apple/p2wlan-${RUN_ID//[^A-Za-z0-9_.-]/-}"
DIRECT_BLACKHOLE_LOCAL_ACTIVE=0
DIRECT_BLACKHOLE_REMOTE_ACTIVE=0
# Do not inherit an ambient application-level RUST_LOG (often `warn`) here:
# this harness needs the bounded dataplane boundary telemetry in both logs.
# Keep the filter targeted: enabling all peer debug logs would include noisy
# candidate churn and legacy validation internals. Callers can override the
# harness-specific variable explicitly for a deeper one-off capture.
HARNESS_RUST_LOG=${HARNESS_RUST_LOG:-info,p2pnet_daemon::transport=debug,p2pnet_daemon::network_outbound=debug,p2pnet_daemon::relay=debug,p2pnet_daemon::relay_runtime=debug,p2pnet_daemon::connection_timeline=debug,p2pnet_daemon::direct_validation=debug,p2pnet_daemon::peer::connection=debug,p2pnet_daemon::peer::connection::events=debug,p2pnet_daemon::peer::manager::relay=debug,p2pnet_relay::client=debug}

if [[ -z "$REMOTE_CONTROL_URL" ]]; then
  echo "[mini-air] REMOTE_CONTROL_URL is required; this harness must not start a local control or relay service" >&2
  exit 2
fi
case "$AUTHORIZATION_WAIT_S" in
  ''|*[!0-9]*|0)
    echo "[mini-air] AUTHORIZATION_WAIT_S must be a positive integer" >&2
    exit 2
    ;;
esac
if [[ ! -f "$ISOLATION_HELPER" ]]; then
  echo "[mini-air] network isolation helper is missing: $ISOLATION_HELPER" >&2
  exit 2
fi
if [[ ! -f "$PRODUCTION_AVAILABILITY_PARSER" ]]; then
  echo "[mini-air] production availability parser is missing: $PRODUCTION_AVAILABILITY_PARSER" >&2
  exit 2
fi
# Isolation is proven live per round (the active roster must be exactly this
# round's two nodes).  REAL_TUN availability is production dataplane evidence;
# allowing an unrelated live device to remain in the roster can make one side
# spend its peer budget on stale nodes and never even instantiate the target
# peer.  Target-scoped cleanup is therefore not sufficient for a real-TUN
# result, including availability mode.
if [[ "$REAL_TUN" == "1" || "$ACCEPTANCE_MODE" == "strict" ]]; then
  echo "[mini-air] real verification requires the per-round isolation proof and device cleanup" >&2
fi
if [[ "$ALLOW_SHARED_NETWORK" == "1" ]]; then
  if [[ "$ACCEPTANCE_MODE" != "availability" || "$REAL_TUN" != "1" ]]; then
    echo "[mini-air] ALLOW_SHARED_NETWORK=1 is only valid for REAL_TUN availability diagnostics" >&2
    exit 2
  fi
  echo "[mini-air] WARNING: target-scoped shared-network diagnostic; strict isolation acceptance is disabled" >&2
fi

count_log_events() {
  local log_file=$1
  local pattern=$2
  grep -E -c -- "$pattern" "$log_file" 2>/dev/null || true
}

count_log_events_insensitive() {
  local log_file=$1
  local pattern=$2
  grep -E -i -c -- "$pattern" "$log_file" 2>/dev/null || true
}

sha256_file() {
  local file=$1
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    echo "[mini-air] neither shasum nor sha256sum is available locally" >&2
    return 1
  fi
}

capture_route_snapshot() {
  local round_dir=$1
  local phase=$2
  local mini_ip=$3
  local air_ip=$4
  {
    printf 'phase=%s\n' "$phase"
    printf 'captured_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'hostname=%s\n' "$(hostname)"
    printf '%s\n' '--- netstat ---'
    netstat -rn 2>&1 || true
    printf '%s\n' '--- route target ---'
    if [[ -n "$air_ip" ]]; then route -n get "$air_ip" 2>&1 || true; fi
    printf '%s\n' '--- ifconfig utun ---'
    ifconfig 2>&1 | awk '/^utun[0-9]+:/{show=1} show{print} show && /^$/{show=0}' || true
  } >"$round_dir/mini-routes-$phase.txt"
  $AIR_SSH "phase='$phase'; air_ip='$mini_ip'; { printf 'phase=%s\\n' \"\$phase\"; printf 'captured_at=%s\\n' \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"; printf 'hostname=%s\\n' \"\$(hostname)\"; printf '%s\\n' '--- netstat ---'; netstat -rn 2>&1 || true; printf '%s\\n' '--- route target ---'; if [ -n \"\$air_ip\" ]; then route -n get \"\$air_ip\" 2>&1 || true; fi; printf '%s\\n' '--- ifconfig utun ---'; ifconfig 2>&1 | awk '/^utun[0-9]+:/{show=1} show{print} show && /^$/{show=0}' || true; }" \
    >"$round_dir/air-routes-$phase.txt" 2>&1 || true
}

dirty_diff_sha256() {
  {
    git -C "$ROOT_DIR" diff --binary
    git -C "$ROOT_DIR" ls-files --others --exclude-standard -z | sort -z | \
      while IFS= read -r -d '' path; do
        printf '\n-- untracked: %s --\n' "$path"
        cat "$ROOT_DIR/$path"
      done
  } | sha256_file /dev/stdin
}

write_sequence_invalid() {
  local reason=$1
  python3 - "$AB_SEQUENCE_DIR/sequence-invalid.json" "$reason" <<'PY'
import json
import os
import sys

path, reason = sys.argv[1:]
tmp = "%s.%s" % (path, os.getpid())
with open(tmp, "w", encoding="utf-8") as stream:
    json.dump({"valid": False, "reason": reason}, stream, indent=2, sort_keys=True)
    stream.write("\n")
os.replace(tmp, path)
PY
}

record_and_lock_fingerprint() {
  local manifest=$1
  local lock_file="$AB_SEQUENCE_DIR/sequence-fingerprints.json"
  local invalid_file="$AB_SEQUENCE_DIR/sequence-invalid.json"
  python3 - "$lock_file" "$invalid_file" "$manifest" \
    "$HARNESS_SHA256" "$STRICT_PARSER_SHA256" "$GIT_HEAD" "$DIRTY_DIFF_SHA256" \
    "$ACCEPTANCE_MODE" "$ACCEPTANCE_STAGE" "$LOCAL_DAEMON_SHA256" "$FIX_DAEMON_SHA256" "$DAEMON_BIN" <<'PY'
import json
import os
import sys

(lock_path, invalid_path, manifest_path, harness_sha, parser_sha, head, dirty_sha,
 mode, stage, daemon_sha, fix_sha, daemon_path) = sys.argv[1:]
invariants = {
    "current_harness_sha256": harness_sha,
    "strict_parser_sha256": parser_sha,
    "head": head,
    "dirty_diff_sha256": dirty_sha,
}

record = dict(invariants)
record.update({
    "acceptance_mode": mode,
    "acceptance_stage": stage,
    "daemon_binary_sha256": daemon_sha,
    "daemon_binary_path": daemon_path,
    "binary_role": "baseline" if mode == "compat" else "fix",
    "fix_binary_sha256": fix_sha,
})

def write(path, value):
    tmp = "%s.%s" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(tmp, path)

if os.path.exists(invalid_path):
    raise SystemExit("A/B sequence is already invalid: %s" % invalid_path)
if os.path.exists(lock_path):
    with open(lock_path, encoding="utf-8") as stream:
        lock = json.load(stream)
    if lock.get("invariants") != invariants:
        write(invalid_path, {
            "valid": False,
            "reason": "harness/parser/HEAD/dirty-diff fingerprint changed",
            "expected": lock.get("invariants"),
            "actual": invariants,
        })
        raise SystemExit("A/B sequence invalidated: invariant fingerprint changed")
else:
    lock = {"invariants": invariants, "modes": {}}

existing_fix = lock.get("fix_binary_sha256")
if existing_fix is not None and existing_fix != fix_sha:
    write(invalid_path, {
        "valid": False,
        "reason": "fix binary fingerprint changed",
        "expected": existing_fix,
        "actual": fix_sha,
    })
    raise SystemExit("A/B sequence invalidated: fix binary fingerprint changed")
lock["fix_binary_sha256"] = fix_sha

mode_record = {"daemon_binary_sha256": daemon_sha, "daemon_binary_path": daemon_path}
existing = lock["modes"].get(mode)
if existing is not None and existing != mode_record:
    write(invalid_path, {
        "valid": False,
        "reason": "%s binary fingerprint changed" % mode,
        "expected": existing,
        "actual": mode_record,
    })
    raise SystemExit("A/B sequence invalidated: %s binary fingerprint changed" % mode)
lock["modes"][mode] = mode_record
baseline = lock["modes"].get("compat", {}).get("daemon_binary_sha256")
if mode == "strict" and baseline is None:
    raise SystemExit("strict acceptance requires a locked compatibility baseline binary")
record["baseline_binary_sha256"] = baseline or daemon_sha
write(lock_path, lock)
write(manifest_path, record)
PY
}

require_sequence_phase() {
  python3 - "$AB_SEQUENCE_DIR/sequence-results.json" "$AB_SEQUENCE_DIR/dirty-diff-freeze.json" \
    "$ACCEPTANCE_STAGE" "$DIRTY_DIFF_SHA256" <<'PY'
import json
import os
import sys

results_path, freeze_path, stage, dirty_sha = sys.argv[1:]
results = []
if os.path.exists(results_path):
    with open(results_path, encoding="utf-8") as stream:
        results = json.load(stream)
if any(row.get("stage") == stage for row in results):
    raise SystemExit("A/B sequence already contains %s results; start a new sequence after an incomplete stage" % stage)

def passed(required_stage, expected):
    rows = [row for row in results if row.get("stage") == required_stage]
    return len(rows) == expected and all(row.get("ok") is True for row in rows)

if stage == "strict-preflight":
    if not passed("compat-baseline", 3):
        raise SystemExit("strict preflight requires exactly 3/3 completed compatibility baseline rounds")
    if not os.path.exists(freeze_path):
        raise SystemExit("strict preflight requires the frozen dirty-diff manifest")
    with open(freeze_path, encoding="utf-8") as stream:
        freeze = json.load(stream)
    if freeze.get("dirty_diff_sha256") != dirty_sha:
        raise SystemExit("strict preflight refuses a dirty diff different from the baseline freeze")
elif stage == "strict-acceptance" and not passed("strict-preflight", 3):
    raise SystemExit("strict acceptance requires 3/3 completed strict preflight rounds")
PY
}

record_sequence_round() {
  local round=$1
  local ok=$2
  local functional_ms=$3
  local strict_ms=$4
  python3 - "$AB_SEQUENCE_DIR/sequence-results.json" "$AB_SEQUENCE_DIR/dirty-diff-freeze.json" \
    "$ACCEPTANCE_STAGE" "$round" "$ok" "$functional_ms" "$strict_ms" "$DIRTY_DIFF_SHA256" <<'PY'
import json
import os
import sys

(results_path, freeze_path, stage, round_number, ok, functional_ms, strict_ms,
 dirty_sha) = sys.argv[1:]
results = []
if os.path.exists(results_path):
    with open(results_path, encoding="utf-8") as stream:
        results = json.load(stream)
results.append({
    "stage": stage,
    "round": int(round_number),
    "ok": ok == "1",
    "functional_direct_ms": int(functional_ms) if functional_ms else None,
    "strict_convergence_ms": int(strict_ms) if strict_ms else None,
})

def write(path, value):
    tmp = "%s.%s" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.replace(tmp, path)

write(results_path, results)
baseline = [row for row in results if row.get("stage") == "compat-baseline"]
if len(baseline) == 3 and all(row.get("ok") is True for row in baseline):
    write(freeze_path, {
        "dirty_diff_sha256": dirty_sha,
        "frozen_after": "3/3 compatibility baseline rounds",
    })
PY
}

# Direct-validation lifecycle stages are retained in the diagnostics snapshot
# and emitted as structured tracing events.  The snapshot is a bounded ring,
# so prefer the durable log count and fall back to the snapshot when a caller
# uses a filter that suppresses those events.
count_status_stage() {
  local status_file=$1
  local peer_id=$2
  local stage=$3
  python3 - "$status_file" "$peer_id" "$stage" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        status = json.load(stream)
except (OSError, ValueError):
    print(0)
    raise SystemExit

peer_id = sys.argv[2]
stage = sys.argv[3]
events = []
for peer in ([status["peer"]] if status.get("peer") else status.get("peers", [])):
    if peer.get("node_id") == peer_id:
        events.extend(peer.get("direct_events", []))
print(sum(1 for event in events if event.get("stage") == stage))
PY
}

count_log_events_for_peer() {
  local log_file=$1
  local peer_id=$2
  local pattern=$3
  grep -F -- "$peer_id" "$log_file" 2>/dev/null | grep -E -c -- "$pattern" || true
}

count_non_target_traversal_activity() {
  local log_file=$1
  local target_peer=$2
  grep -E 'peer_id=.*(offer|probe|direct_validation|punch)|event=.*(offer|probe|direct_validation|punch)' "$log_file" 2>/dev/null | \
    grep -F 'peer_id=' | grep -F -v -- "$target_peer" | wc -l | tr -d ' ' || true
}

count_non_target_peer_events() {
  local log_file=$1
  local target_peer=$2
  local pattern=$3
  grep -E -- "$pattern" "$log_file" 2>/dev/null | grep -F 'peer_id=' | \
    grep -F -v -- "$target_peer" | wc -l | tr -d ' ' || true
}

log_reports_overlay_round_trip() {
  local log_file=$1
  local peer_id=$2
  count_log_events_for_peer "$log_file" "$peer_id" 'overlay_payload_verified'
}

# Epoch milliseconds of the FIRST log line matching a regexp, or empty when the
# log has no match.  Used to compute the availability "first usable after relay
# selected" metric from the daemons' own wall-clock timestamps.
log_first_event_epoch_ms() {
  local log_file=$1
  local pattern=$2
  python3 - "$log_file" "$pattern" <<'PY'
import datetime
import re
import sys

log_file, pattern = sys.argv[1], sys.argv[2]
try:
    with open(log_file, encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if re.search(pattern, line):
                match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)", line)
                if match:
                    ts = datetime.datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
                    print(int(ts.timestamp() * 1000))
                    raise SystemExit(0)
except OSError:
    pass
PY
}

# The `path` field value of the FIRST log line matching a regexp, or empty.
log_first_event_path() {
  local log_file=$1
  local pattern=$2
  grep -E -m1 -- "$pattern" "$log_file" 2>/dev/null | sed -n 's/.*path=Some("\([^"]*\)").*/\1/p'
}

# The value of a `Some(N)` numeric structured field on the FIRST log line
# matching a regexp, or empty.  Used to read a daemon's OWN monotonic
# relay-ready -> usable delta, so availability timing is never computed by
# subtracting wall clocks across the two machines.
log_first_event_field() {
  local log_file=$1
  local pattern=$2
  local field=$3
  grep -E -m1 -- "$pattern" "$log_file" 2>/dev/null | sed -n "s/.*${field}=Some(\([0-9]*\)).*/\1/p"
}

# Read the production TUN dataplane milestone for one target peer.  The daemon
# records this only after a normal decrypted business packet is received, and
# records the actual ingress envelope (relay/direct) rather than the currently
# selected path.  The standalone parser uses one daemon's monotonic t_ms and
# never derives a delta from the other machine's wall clock.
production_first_business_info() {
  local log_file=$1
  local peer_id=$2
  python3 "$PRODUCTION_AVAILABILITY_PARSER" "$log_file" "$peer_id"
}

run_real_tun_business_pair() {
  local round_dir=$1
  local mini_ip=$2
  local air_ip=$3
  local mini_ping_log="$round_dir/overlay-ping-mini-to-air.log"
  local air_ping_log="$round_dir/overlay-ping-air-to-mini.log"
  : >"$mini_ping_log"
  : >"$air_ping_log"
  local successful_mini=0
  local successful_air=0
  # Keep the window short and bounded: these are real ICMP packets through the
  # system TUN, not the mock overlay validator.  Repeated single probes cover
  # the small race between peer registration and relay confirmation without
  # creating a backlog that could later masquerade as RTT.
  for _ in $(seq 1 8); do
    /sbin/ping -S "$mini_ip" -c 1 -W 1000 "$air_ip" >>"$mini_ping_log" 2>&1 &
    local mini_ping_pid=$!
    $AIR_SSH "ping -S '$air_ip' -c 1 -W 1000 '$mini_ip'" >>"$air_ping_log" 2>&1 &
    local air_ping_pid=$!
    wait "$mini_ping_pid" && successful_mini=$((successful_mini + 1)) || true
    wait "$air_ping_pid" && successful_air=$((successful_air + 1)) || true
    sleep 0.25
  done
  REAL_OVERLAY_MINI_REPLIES=$(grep -E -c 'bytes from|[0-9]+ bytes from' "$mini_ping_log" 2>/dev/null || true)
  REAL_OVERLAY_AIR_REPLIES=$(grep -E -c 'bytes from|[0-9]+ bytes from' "$air_ping_log" 2>/dev/null || true)
  REAL_OVERLAY_OK=0
  if [[ "$REAL_OVERLAY_MINI_REPLIES" -gt 0 && "$REAL_OVERLAY_AIR_REPLIES" -gt 0 ]]; then
    REAL_OVERLAY_OK=1
  fi
  printf 'mini_replies=%s air_replies=%s mini_successful_commands=%s air_successful_commands=%s\n' \
    "$REAL_OVERLAY_MINI_REPLIES" "$REAL_OVERLAY_AIR_REPLIES" "$successful_mini" "$successful_air" \
    >"$round_dir/real-overlay-summary.env"
}

# Do not inject the first real TUN packet while one endpoint is still waiting
# for its peer session or relay ACK.  That is a useful queue/failure-injection
# scenario, but it is not a clean relay-first availability measurement: a
# later Direct ACK can consume the queued ciphertext while the relay side is
# still only READY, making the test conflate startup ordering with path
# availability.  The daemon still starts relay and Direct in parallel; this
# barrier only makes the real-business measurement begin after both daemons
# have independently proved the relay peer path.
wait_for_target_relay_pair() {
  local round_dir=$1
  local timeout_s=${RELAY_CONFIRM_WAIT_S:-10}
  local deadline_ms=$(( $(python3 -c 'import time; print(int(time.time()*1000))') + timeout_s * 1000 ))
  local mini_live="$round_dir/relay-confirm-mini-live.json"
  local air_live="$round_dir/relay-confirm-air-live.json"
  : >"$round_dir/relay-confirm-wait.log"
  while :; do
    local now_ms
    now_ms=$(python3 -c 'import time; print(int(time.time()*1000))')
    if [[ "$now_ms" -ge "$deadline_ms" ]]; then
      printf 'timeout_s=%s mini_confirmed=0 air_confirmed=0\n' "$timeout_s" \
        >>"$round_dir/relay-confirm-wait.log"
      return 1
    fi

    local mini_confirmed=0
    local air_confirmed=0
    if curl -fsS --max-time 3 \
      "http://127.0.0.1:$DIAG_A_PORT/status/peer/$AIR_NODE_ID" >"$mini_live" 2>/dev/null; then
      mini_confirmed=$(python3 - "$mini_live" "$AIR_NODE_ID" <<'PY'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        value = json.load(stream)
    peer = value.get("peer") or {}
    print(int(
        peer.get("node_id") == sys.argv[2]
        and peer.get("online") is True
        and peer.get("relay_confirmed_endpoint")
        and peer.get("relay_confirmed_generation") == value.get("network_generation")
    ))
except (OSError, ValueError, TypeError):
    print(0)
PY
      )
    fi
    if $AIR_SSH "curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:$DIAG_B_PORT/status/peer/$MINI_NODE_ID" \
      >"$air_live" 2>/dev/null; then
      air_confirmed=$(python3 - "$air_live" "$MINI_NODE_ID" <<'PY'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        value = json.load(stream)
    peer = value.get("peer") or {}
    print(int(
        peer.get("node_id") == sys.argv[2]
        and peer.get("online") is True
        and peer.get("relay_confirmed_endpoint")
        and peer.get("relay_confirmed_generation") == value.get("network_generation")
    ))
except (OSError, ValueError, TypeError):
    print(0)
PY
      )
    fi
    printf 't_wall_ms=%s mini_confirmed=%s air_confirmed=%s\n' "$now_ms" \
      "$mini_confirmed" "$air_confirmed" >>"$round_dir/relay-confirm-wait.log"
    if [[ "$mini_confirmed" == "1" && "$air_confirmed" == "1" ]]; then
      printf 'result=both_confirmed\n' >>"$round_dir/relay-confirm-wait.log"
      return 0
    fi
    sleep 0.1
  done
}

count_stage() {
  local status_file=$1
  local log_file=$2
  local peer_id=$3
  local stage=$4
  local log_count
  local status_count
  log_count=$(count_log_events_for_peer "$log_file" "$peer_id" "event=\\\"$stage\\\"|$stage")
  status_count=$(count_status_stage "$status_file" "$peer_id" "$stage")
  if [[ "$log_count" -gt 0 ]]; then
    printf '%s\n' "$log_count"
  else
    printf '%s\n' "$status_count"
  fi
}

# The Direct state is authoritative in diagnostics. Log lines are retained as
# evidence and for endpoint extraction, but an ambient filtering change must
# never turn a real Direct path into a harness timeout.
status_reports_direct() {
  local status_url=$1
  local peer_id=$2
  curl -fsS --max-time 5 "$status_url" | python3 -c '
import json
import sys

try:
    status = json.load(sys.stdin)
except ValueError:
    raise SystemExit(1)
peer_id = sys.argv[1]
peers = [status["peer"]] if status.get("peer") else status.get("peers", [])
raise SystemExit(0 if any(
    peer.get("node_id") == peer_id
    and peer.get("state") == "direct"
    and peer.get("active_path") == "direct"
    for peer in peers
) else 1)
' "$peer_id"
}

status_reports_strict_direct() {
  local status_file=$1
  local peer_id=$2
  python3 - "$status_file" "$peer_id" <<'PY'
import ipaddress
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        status = json.load(stream)
except (OSError, ValueError):
    raise SystemExit(1)

peer_id = sys.argv[2]
for peer in ([status["peer"]] if status.get("peer") else status.get("peers", [])):
    if peer.get("node_id") != peer_id:
        continue
    pair = peer.get("selected_pair") or peer.get("current_direct_pair") or {}
    endpoint = pair.get("remote_endpoint") or ""
    try:
        address = ipaddress.ip_address(endpoint.rsplit(":", 1)[0])
    except ValueError:
        raise SystemExit(1)
    if not (
        peer.get("state") == "direct"
        and peer.get("active_path") == "direct"
        and peer.get("is_public_udp_direct") is True
        and address.version == 4
        and address.is_global
    ):
        raise SystemExit(1)
    raise SystemExit(0)
raise SystemExit(1)
PY
}

# The legacy release cannot supply the current owned-validation diagnostics
# schema. Compatibility acceptance deliberately checks only observable
# functional Direct state for this round's two temporary node IDs.
status_reports_compat_direct() {
  local status_file=$1
  local peer_id=$2
  python3 - "$status_file" "$peer_id" <<'PY'
import ipaddress
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        status = json.load(stream)
except (OSError, ValueError):
    raise SystemExit(1)

for peer in ([status["peer"]] if status.get("peer") else status.get("peers", [])):
    if peer.get("node_id") != sys.argv[2]:
        continue
    pair = peer.get("selected_pair") or peer.get("current_direct_pair") or {}
    endpoint = pair.get("remote_endpoint") or ""
    try:
        address = ipaddress.ip_address(endpoint.rsplit(":", 1)[0])
    except ValueError:
        raise SystemExit(1)
    raise SystemExit(0 if (
        peer.get("state") == "direct"
        and peer.get("active_path") == "direct"
        and address.version == 4
        and address.is_global
    ) else 1)
raise SystemExit(1)
PY
}

compatibility_direct_pair() {
  local a_status=$1
  local a_peer=$2
  local b_status=$3
  local b_peer=$4
  status_reports_compat_direct "$a_status" "$a_peer" && \
    status_reports_compat_direct "$b_status" "$b_peer"
}

status_endpoint_from_json() {
  local status_file=$1
  local peer_id=$2
  python3 - "$status_file" "$peer_id" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        status = json.load(stream)
except (OSError, ValueError):
    raise SystemExit(1)
peer_id = sys.argv[2]
for peer in ([status["peer"]] if status.get("peer") else status.get("peers", [])):
    if peer.get("node_id") == peer_id:
        pair = peer.get("selected_pair") or peer.get("current_direct_pair") or {}
        print(pair.get("remote_endpoint") or "")
        raise SystemExit(0)
raise SystemExit(1)
PY
}

strict_validation_session() {
  local status_file=$1
  local peer_id=$2
  python3 "$STRICT_PARSER" "$status_file" "$peer_id"
}

strict_validation_pair() {
  local a_status=$1
  local a_peer=$2
  local b_status=$3
  local b_peer=$4
  python3 "$STRICT_PARSER" --pair "$a_status" "$a_peer" "$b_status" "$b_peer"
}

capture_status_pair() {
  POLL_INDEX=$((POLL_INDEX + 1))
  local poll_id
  poll_id=$(printf '%03d' "$POLL_INDEX")
  CURRENT_A_POLL="$ROUND_DIR/node-a.poll-$poll_id.json"
  CURRENT_B_POLL="$ROUND_DIR/node-b.poll-$poll_id.json"
  CURRENT_RESULT="$ROUND_DIR/strict-result-$poll_id.json"
  local a_tmp="$CURRENT_A_POLL.tmp.$$"
  local b_tmp="$CURRENT_B_POLL.tmp.$$"
  local a_err="$ROUND_DIR/node-a.poll-$poll_id.stderr"
  local b_err="$ROUND_DIR/node-b.poll-$poll_id.stderr"
  local capture_started_ms
  capture_started_ms=$(python3 -c 'import time; print(int(time.time()*1000))')
  # Fetch both endpoint-scoped snapshots concurrently.  ControlMaster keeps
  # the Air SSH transport warm between polls.
  # Acceptance predicates are target-scoped in every mode. The network-wide
  # /status snapshot is useful as a diagnostic artifact, but materializing all
  # stale peers can legitimately time out while this target's dataplane is
  # healthy. Never make a slow unrelated peer part of the target verdict.
  local mini_status_path="/status/peer/$AIR_NODE_ID"
  local air_status_path="/status/peer/$MINI_NODE_ID"
  curl -fsS --max-time 5 "http://127.0.0.1:$DIAG_A_PORT$mini_status_path" >"$a_tmp" 2>"$a_err" &
  local mini_pid=$!
  $AIR_SSH "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:$DIAG_B_PORT$air_status_path" >"$b_tmp" 2>"$b_err" &
  local air_pid=$!
  local mini_rc=0
  local air_rc=0
  wait "$mini_pid" || mini_rc=$?
  local mini_captured_ms
  mini_captured_ms=$(python3 -c 'import time; print(int(time.time()*1000))')
  wait "$air_pid" || air_rc=$?
  local air_captured_ms
  air_captured_ms=$(python3 -c 'import time; print(int(time.time()*1000))')
  if [[ "$mini_rc" -ne 0 || "$air_rc" -ne 0 ]]; then
    : >"$a_tmp"
    : >"$b_tmp"
    printf 'mini_rc=%s air_rc=%s\n' "$mini_rc" "$air_rc" >"$ROUND_DIR/poll-$poll_id.capture-error"
    return 1
  fi
  mv "$a_tmp" "$CURRENT_A_POLL"
  mv "$b_tmp" "$CURRENT_B_POLL"
  local parser_rc
  set +e
  python3 "$STRICT_PARSER" --pair "$CURRENT_A_POLL" "$AIR_NODE_ID" "$CURRENT_B_POLL" "$MINI_NODE_ID" >"$CURRENT_RESULT.tmp.$$"
  parser_rc=$?
  set -e
  mv "$CURRENT_RESULT.tmp.$$" "$CURRENT_RESULT"
  python3 - "$ROUND_DIR/poll-$poll_id.json" "$CURRENT_A_POLL" "$CURRENT_B_POLL" "$CURRENT_RESULT" "$POLL_INDEX" "$parser_rc" "$START_MS" "$capture_started_ms" "$mini_captured_ms" "$air_captured_ms" "$AIR_NODE_ID" "$MINI_NODE_ID" <<'PY'
import hashlib
import json
import sys
import time

out, a_path, b_path, result_path, poll_index, parser_rc, started, capture_started, mini_ms, air_ms, air_peer, mini_peer = sys.argv[1:]
def load(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)
def sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
def target(status, peer_id):
    peer = status.get("peer") or next((p for p in status.get("peers", []) if p.get("node_id") == peer_id), {})
    pair = peer.get("selected_pair") or peer.get("current_direct_pair") or {}
    return {
        "state": peer.get("state"),
        "active_path": peer.get("active_path"),
        "selected_endpoint": pair.get("remote_endpoint"),
    }
a = load(a_path)
b = load(b_path)
result = load(result_path)
meta = {
    "poll_index": int(poll_index),
    "round_started_ms": int(started),
    "capture_started_ms": int(capture_started),
    "mini_status_captured_ms": int(mini_ms),
    "air_status_captured_ms": int(air_ms),
    "mini_file_sha256": sha(a_path),
    "air_file_sha256": sha(b_path),
    "parser_exit_code": int(parser_rc),
    "parser_reason": {
        "mini": result.get("left", {}).get("reason"),
        "air": result.get("right", {}).get("reason"),
    },
    "mini_target_state": target(a, air_peer)["state"],
    "mini_target_active_path": target(a, air_peer)["active_path"],
    "mini_selected_endpoint": target(a, air_peer)["selected_endpoint"],
    "air_target_state": target(b, mini_peer)["state"],
    "air_target_active_path": target(b, mini_peer)["active_path"],
    "air_selected_endpoint": target(b, mini_peer)["selected_endpoint"],
    "strict_result_sha256": sha(result_path),
}
tmp = out + ".tmp"
with open(tmp, "w", encoding="utf-8") as stream:
    json.dump(meta, stream, indent=2, sort_keys=True)
    stream.write("\n")
import os
os.replace(tmp, out)
PY
}

collect_air_log() {
  $AIR_SSH "cat '$REMOTE_NODE_B_LOG'" >"$ROUND_DIR/node-b.log"
}

remote_status_reports_direct() {
  local peer_id=$1
  $AIR_SSH "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:$DIAG_B_PORT/status/peer/$peer_id | python3 -c 'import json,sys; status=json.load(sys.stdin); peer=status.get(\"peer\") or {}; raise SystemExit(0 if peer.get(\"node_id\") == sys.argv[1] and peer.get(\"state\") == \"direct\" and peer.get(\"active_path\") == \"direct\" else 1)' '$peer_id'"
}

direct_endpoint_from_log() {
  local log_file=$1
  local peer_id=$2
  grep -F -- "$peer_id" "$log_file" 2>/dev/null | grep -E 'direct_path_promoted|candidate_pair_selected' \
    | grep -oE 'remote_endpoint=[0-9.]+:[0-9]+' \
    | sed 's/^remote_endpoint=//' \
    | tail -1 || true
}

is_public_ipv4_endpoint() {
  local endpoint=$1
  python3 - "$endpoint" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1].rsplit(":", 1)[0])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if address.version == 4 and address.is_global else 1)
PY
}

delete_round_devices() {
  local round_dir=$1
  local cleanup_ok=1
  local deleted_ids=""
  local names=()
  [[ -n "${LOCAL_NODE_A_DEVICE:-}" ]] && names+=("$LOCAL_NODE_A_DEVICE")
  [[ -n "${REMOTE_NODE_B_DEVICE:-}" ]] && names+=("$REMOTE_NODE_B_DEVICE")
  if ((${#names[@]} == 0)); then
    return 0
  fi

  if python3 "$ISOLATION_HELPER" --delete-by-name "$CONTROL_URL" "$TOKEN" "$NETWORK_ID" \
    "${names[@]}" >"$round_dir/isolation-delete.json" 2>"$round_dir/isolation-delete.err"; then
    deleted_ids=$(python3 - "$round_dir/isolation-delete.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(" ".join(json.load(stream).get("deleted_ids", [])))
PY
    )
  else
    echo "[mini-air] ROUND $round: device cleanup failed; refusing to continue" >&2
    cat "$round_dir/isolation-delete.json" >&2 2>/dev/null || true
    cleanup_ok=0
  fi

  local cleanup_proof_mode="--prove-cleaned"
  if [[ ( "$REAL_TUN" != "1" && "$ACCEPTANCE_MODE" != "strict" ) || "$ISOLATION_MODE" == "target-scoped-shared" ]]; then
    cleanup_proof_mode="--prove-cleaned-scoped"
  fi
  if [[ "$cleanup_ok" -eq 1 && -n "$deleted_ids" ]] && ! python3 "$ISOLATION_HELPER" "$cleanup_proof_mode" \
    "$CONTROL_URL" "$TOKEN" "$NETWORK_ID" $deleted_ids --deadline 15 \
    >"$round_dir/isolation-cleaned.json" 2>>"$round_dir/isolation-delete.err"; then
    echo "[mini-air] ROUND $round: network not clean after device deletion; refusing to continue" >&2
    cat "$round_dir/isolation-cleaned.json" >&2 2>/dev/null || true
    cleanup_ok=0
  fi
  if [[ "$cleanup_ok" -ne 1 ]]; then
    overall=1
    return 1
  fi
  return 0
}

cleanup() {
  stop_auth_helpers
  clear_direct_udp_blackhole
  local_daemon_cleanup || true
  remote_daemon_cleanup || true
  redact_local_config || true
  stop_privileged_supervisors
  if [[ -n "$REMOTE_NODE_B_PID_FILE" ]]; then
    echo "[mini-air] remote PID file retained after cleanup verification failure: $REMOTE_NODE_B_PID_FILE" >&2
  fi
  echo "[mini-air] artifacts retained: $BASE_DIR" >&2
}

redact_local_config() {
  local files=()
  [[ -n "$LOCAL_NODE_A_CONFIG" ]] && files+=("$LOCAL_NODE_A_CONFIG")
  [[ -n "$LOCAL_NODE_A_TOKEN_FILE" ]] && files+=("$LOCAL_NODE_A_TOKEN_FILE")
  ((${#files[@]} > 0)) || return 0
  local cleanup_command=""
  for file in "${files[@]}"; do
    # Keep the no-delete contract for the workspace: generated credential and
    # config files are truncated after the run, never recursively removed.
    cleanup_command+="if [ -e '$file' ]; then : > '$file'; fi; "
  done
  if [[ "$LOCAL_PRIVILEGED_SUPERVISOR_ACTIVE" == "1" ]]; then
    local_privileged_exec "$cleanup_command" >/dev/null 2>&1 || true
  elif [[ "$LOCAL_DAEMON_NEEDS_OSASCRIPT" == "1" ]]; then
    local_osascript_shell "$cleanup_command" >/dev/null 2>&1 || true
  else
    /bin/sh -c "$cleanup_command" || true
  fi
}

local_daemon_cleanup() {
  [[ -n "$LOCAL_NODE_A_PID" ]] || return 0
  if [[ "$LOCAL_DAEMON_NEEDS_OSASCRIPT" == "1" && -n "$LOCAL_NODE_A_PID_FILE" && -r "$LOCAL_NODE_A_PID_FILE" ]]; then
    local privileged_pid privileged_command
    privileged_pid=$(cat "$LOCAL_NODE_A_PID_FILE" 2>/dev/null || true)
    case "$privileged_pid" in
      ''|*[!0-9]*)
        echo "[mini-air] Mini privileged cleanup verification failed; invalid PID file retained: $LOCAL_NODE_A_PID_FILE" >&2
        return 1
        ;;
    esac
    privileged_command=$(ps -ww -p "$privileged_pid" -o command= 2>/dev/null || true)
    if [[ "$privileged_command" != *"$DAEMON_BIN"* ||
          "$privileged_command" != *"$LOCAL_NODE_A_CONFIG"* ||
          "$privileged_command" != *"$LOCAL_NODE_A_DEVICE"* ]]; then
      echo "[mini-air] Mini privileged cleanup verification failed; PID retained: $privileged_pid" >&2
      return 1
    fi
    if [[ "$LOCAL_PRIVILEGED_SUPERVISOR_ACTIVE" == "1" ]]; then
      if ! local_privileged_exec "kill -TERM '$privileged_pid' 2>/dev/null || true; sleep 1; if kill -0 '$privileged_pid' 2>/dev/null; then kill -KILL '$privileged_pid' 2>/dev/null || true; fi" >/dev/null 2>&1; then
        echo "[mini-air] Mini privileged supervisor cleanup failed; PID retained: $privileged_pid" >&2
        return 1
      fi
    elif ! local_osascript_shell "kill -TERM '$privileged_pid' 2>/dev/null || true; sleep 1; if kill -0 '$privileged_pid' 2>/dev/null; then kill -KILL '$privileged_pid' 2>/dev/null || true; fi" >/dev/null 2>&1; then
      echo "[mini-air] Mini privileged cleanup authorization failed; PID retained: $privileged_pid" >&2
      return 1
    fi
    for _ in $(seq 1 20); do
      if ! ps -p "$privileged_pid" -o pid= >/dev/null 2>&1; then
        # The PID file is written by the root daemon into the user-owned
        # artifact directory.  Do not try to truncate it here as the
        # unprivileged harness user: that turns a successful cleanup into a
        # spurious permission failure and destroys useful PID evidence.
        LOCAL_NODE_A_PID=""
        return 0
      fi
      sleep 0.1
    done
    echo "[mini-air] Mini privileged cleanup did not terminate verified PID: $privileged_pid" >&2
    return 1
  fi
  local command
  command=$(ps -ww -p "$LOCAL_NODE_A_PID" -o command= 2>/dev/null || true)
  if [[ "$command" != *"$DAEMON_BIN"* ||
        "$command" != *"$LOCAL_NODE_A_CONFIG"* ||
        "$command" != *"$LOCAL_NODE_A_DEVICE"* ||
        ( "$LOCAL_NODE_A_CONFIG" != *"$RUN_ID"* && "$LOCAL_NODE_A_DEVICE" != *"$RUN_ID"* ) ]]; then
    echo "[mini-air] Mini cleanup verification failed; PID retained: $LOCAL_NODE_A_PID" >&2
    return 1
  fi
  kill "$LOCAL_NODE_A_PID" 2>/dev/null || true
  if ! ps -p "$LOCAL_NODE_A_PID" -o pid= >/dev/null 2>&1; then
    LOCAL_NODE_A_PID=""
    return 0
  fi
  echo "[mini-air] Mini cleanup did not terminate verified PID: $LOCAL_NODE_A_PID" >&2
  return 1
}

local_daemon_is_alive() {
  if [[ "$LOCAL_DAEMON_NEEDS_OSASCRIPT" == "1" && -n "$LOCAL_NODE_A_PID_FILE" && -r "$LOCAL_NODE_A_PID_FILE" ]]; then
    local privileged_pid privileged_command
    privileged_pid=$(cat "$LOCAL_NODE_A_PID_FILE" 2>/dev/null || true)
    case "$privileged_pid" in
      ''|*[!0-9]*) return 1 ;;
    esac
    # kill -0 is not a liveness probe for a root-owned process when this
    # harness runs as the normal desktop user: macOS returns EPERM for a
    # living daemon.  Use read-only process inspection and bind it to this
    # round's binary/config/device identity to avoid accepting a reused PID.
    privileged_command=$(ps -ww -p "$privileged_pid" -o command= 2>/dev/null || true)
    [[ "$privileged_command" == *"$DAEMON_BIN"* &&
       "$privileged_command" == *"$LOCAL_NODE_A_CONFIG"* &&
       "$privileged_command" == *"$LOCAL_NODE_A_DEVICE"* ]]
    return $?
  fi
  kill -0 "$NODE_A_PID" 2>/dev/null
}

remote_daemon_matches() {
  [[ -n "$REMOTE_NODE_B_PID_FILE" ]] || return 1
  $AIR_SSH "pid_file='$REMOTE_NODE_B_PID_FILE'; config='$AIR_CONFIG'; device='$REMOTE_NODE_B_DEVICE'; bin='$REMOTE_DAEMON_BIN'; run_id='$RUN_ID'; case \"\$pid_file:\$config:\$device:\$bin\" in *\"\$run_id\"*) ;; *) exit 1 ;; esac; test -r \"\$pid_file\" || exit 1; pid=\$(cat \"\$pid_file\"); case \"\$pid\" in ''|*[!0-9]*) exit 1 ;; esac; cmd=\$(ps -ww -p \"\$pid\" -o command= 2>/dev/null) || exit 1; case \"\$cmd\" in *\"\$bin\"*\"\$config\"*\"\$device\"*) exit 0 ;; *) exit 1 ;; esac" >/dev/null 2>&1
}

remote_daemon_cleanup() {
  [[ -n "$REMOTE_NODE_B_PID_FILE" ]] || return 0
  local cleanup_command="pid_file='$REMOTE_NODE_B_PID_FILE'; config='$AIR_CONFIG'; token_file='$REMOTE_NODE_B_TOKEN_FILE'; device='$REMOTE_NODE_B_DEVICE'; bin='$REMOTE_DAEMON_BIN'; run_id='$RUN_ID'; case \"\$pid_file:\$config:\$device:\$bin\" in *\"\$run_id\"*) ;; *) exit 3 ;; esac; if [ ! -r \"\$pid_file\" ]; then exit 3; fi; pid=\$(cat \"\$pid_file\"); case \"\$pid\" in ''|*[!0-9]*) exit 3 ;; esac; cmd=\$(ps -ww -p \"\$pid\" -o command= 2>/dev/null) || exit 3; case \"\$cmd\" in *\"\$bin\"*\"\$config\"*\"\$device\"*) kill -TERM \"\$pid\" 2>/dev/null || true; sleep 1; if kill -0 \"\$pid\" 2>/dev/null; then kill -KILL \"\$pid\" 2>/dev/null || true; fi; for n in 1 2 3 4 5 6 7 8 9 10; do kill -0 \"\$pid\" 2>/dev/null || break; sleep 0.1; done; kill -0 \"\$pid\" 2>/dev/null && exit 4; : >\"\$pid_file\"; : >\"\$token_file\"; : >\"\$config\" ;; *) exit 3 ;; esac"
  if { [[ "$REMOTE_PRIVILEGED_SUPERVISOR_ACTIVE" == "1" ]] && remote_privileged_exec "$cleanup_command" >/dev/null 2>&1; } ||
     { [[ "$REMOTE_PRIVILEGED_SUPERVISOR_ACTIVE" != "1" && "$AIR_REMOTE_NEEDS_OSASCRIPT" == "1" ]] && remote_osascript_shell "$cleanup_command" >/dev/null 2>&1; } ||
     { [[ "$AIR_REMOTE_NEEDS_OSASCRIPT" != "1" ]] && $AIR_SSH "$cleanup_command" >/dev/null 2>&1; }; then
    REMOTE_NODE_B_PID_FILE=""
    return 0
  fi
  echo "[mini-air] Air cleanup verification failed; remote PID/config/log retained" >&2
  return 1
}

clear_direct_udp_blackhole() {
  if [[ "$DIRECT_BLACKHOLE_LOCAL_ACTIVE" == "1" ]]; then
    if [[ "$LOCAL_PRIVILEGED_SUPERVISOR_ACTIVE" == "1" ]]; then
      local_privileged_exec "/sbin/pfctl -a '$DIRECT_BLACKHOLE_ANCHOR' -F all >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
    else
      local_osascript_shell "/sbin/pfctl -a '$DIRECT_BLACKHOLE_ANCHOR' -F all >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
    fi
    DIRECT_BLACKHOLE_LOCAL_ACTIVE=0
  fi
  if [[ "$DIRECT_BLACKHOLE_REMOTE_ACTIVE" == "1" ]]; then
    if [[ "$REMOTE_PRIVILEGED_SUPERVISOR_ACTIVE" == "1" ]]; then
      remote_privileged_exec "/sbin/pfctl -a '$DIRECT_BLACKHOLE_ANCHOR' -F all >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
    else
      remote_osascript_shell "/sbin/pfctl -a '$DIRECT_BLACKHOLE_ANCHOR' -F all >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
    fi
    DIRECT_BLACKHOLE_REMOTE_ACTIVE=0
  fi
}

apply_direct_udp_blackhole() {
  [[ "$DIRECT_UDP_BLACKHOLE" == "1" ]] || return 0
  if ! is_public_ipv4_endpoint "$AIR_PUBLIC_IPV4:1" || ! is_public_ipv4_endpoint "$MINI_PUBLIC_IPV4:1"; then
    echo "[mini-air] refusing Direct blackhole: both observed public IPv4 values must be globally routable" >&2
    return 1
  fi

  local mini_rule air_rule
  mini_rule="/sbin/pfctl -e >/dev/null 2>&1 || true; /sbin/pfctl -a '$DIRECT_BLACKHOLE_ANCHOR' -F all >/dev/null 2>&1 || true; { printf '%s\\n' 'block drop quick inet proto udp from any to $AIR_PUBLIC_IPV4'; printf '%s\\n' 'block drop quick inet proto udp from $AIR_PUBLIC_IPV4 to any'; } | /sbin/pfctl -a '$DIRECT_BLACKHOLE_ANCHOR' -f -; /sbin/pfctl -a '$DIRECT_BLACKHOLE_ANCHOR' -sr"
  air_rule="/sbin/pfctl -e >/dev/null 2>&1 || true; /sbin/pfctl -a '$DIRECT_BLACKHOLE_ANCHOR' -F all >/dev/null 2>&1 || true; { printf '%s\\n' 'block drop quick inet proto udp from any to $MINI_PUBLIC_IPV4'; printf '%s\\n' 'block drop quick inet proto udp from $MINI_PUBLIC_IPV4 to any'; } | /sbin/pfctl -a '$DIRECT_BLACKHOLE_ANCHOR' -f -; /sbin/pfctl -a '$DIRECT_BLACKHOLE_ANCHOR' -sr"

  echo "[mini-air] installing Direct UDP blackhole on Mini for peer $AIR_PUBLIC_IPV4"
  if [[ "$LOCAL_PRIVILEGED_SUPERVISOR_ACTIVE" == "1" ]]; then
    if ! local_privileged_exec "$mini_rule" >"$BASE_DIR/direct-blackhole-mini.rules"; then
      echo "[mini-air] failed to install the Mini Direct UDP blackhole" >&2
      return 1
    fi
  elif ! local_osascript_shell "$mini_rule" >"$BASE_DIR/direct-blackhole-mini.rules"; then
    echo "[mini-air] failed to install the Mini Direct UDP blackhole" >&2
    return 1
  fi
  DIRECT_BLACKHOLE_LOCAL_ACTIVE=1

  echo "[mini-air] installing Direct UDP blackhole on Air for peer $MINI_PUBLIC_IPV4"
  if [[ "$REMOTE_PRIVILEGED_SUPERVISOR_ACTIVE" == "1" ]]; then
    if ! remote_privileged_exec "$air_rule" >"$BASE_DIR/direct-blackhole-air.rules"; then
      echo "[mini-air] failed to install the Air Direct UDP blackhole; clearing Mini anchor" >&2
      clear_direct_udp_blackhole
      return 1
    fi
  elif ! remote_osascript_shell "$air_rule" >"$BASE_DIR/direct-blackhole-air.rules"; then
    echo "[mini-air] failed to install the Air Direct UDP blackhole; clearing Mini anchor" >&2
    clear_direct_udp_blackhole
    return 1
  fi
  DIRECT_BLACKHOLE_REMOTE_ACTIVE=1
  printf '%s\n' "anchor=$DIRECT_BLACKHOLE_ANCHOR" "mini_peer_ipv4=$AIR_PUBLIC_IPV4" "air_peer_ipv4=$MINI_PUBLIC_IPV4" >"$BASE_DIR/direct-blackhole.config"
}

kill_remote_wrapper() {
  # In the Authorization Services path the remote daemon is detached and the
  # verified remote PID file is authoritative, so there is no local SSH
  # wrapper to kill.  In the ordinary SSH path this terminates only this
  # round's foreground SSH holder after remote_daemon_cleanup has signalled
  # the exact run-scoped daemon PID.
  if [[ -n "${NODE_B_PID:-}" ]]; then
    kill "$NODE_B_PID" 2>/dev/null || true
    NODE_B_PID=""
  fi
}
trap cleanup EXIT

echo "[mini-air] building temporary daemon (release)..."
echo "[mini-air] verification control/relay: $REMOTE_CONTROL_URL"
# Both sides of the A/B comparison are fingerprinted before the run begins.
# Compatibility executes the override, while the current-tree build remains a
# frozen reference for the later strict phase.
cargo build --release -p p2wlan-daemon --manifest-path "$ROOT_DIR/client/daemon/Cargo.toml" >/dev/null
FIX_DAEMON_BIN="$ROOT_DIR/target/release/p2wlan-daemon"
FIX_DAEMON_SHA256=$(sha256_file "$FIX_DAEMON_BIN")
if [[ -n "$DAEMON_BIN_OVERRIDE" ]]; then
  if [[ ! -x "$DAEMON_BIN_OVERRIDE" ]]; then
    echo "[mini-air] DAEMON_BIN_OVERRIDE is not executable: $DAEMON_BIN_OVERRIDE" >&2
    exit 2
  fi
  DAEMON_BIN="$DAEMON_BIN_OVERRIDE"
else
  DAEMON_BIN="$FIX_DAEMON_BIN"
fi
LOCAL_DAEMON_SHA256=$(sha256_file "$DAEMON_BIN")
HARNESS_SHA256=$(sha256_file "$HARNESS_ROOT/scripts/dual-end/mini-air-smoke.sh")
STRICT_PARSER_SHA256=$(sha256_file "$STRICT_PARSER")
GIT_HEAD=$(git -C "$ROOT_DIR" rev-parse HEAD)
DIRTY_DIFF_SHA256=$(dirty_diff_sha256)
record_and_lock_fingerprint "$BASE_DIR/run-manifest.json"
require_sequence_phase
printf '%s\n' "$LOCAL_DAEMON_SHA256" >"$BASE_DIR/daemon-binary.sha256"
printf '%s\n' "$HARNESS_SHA256" >"$BASE_DIR/current-harness.sha256"
printf '%s\n' "$STRICT_PARSER_SHA256" >"$BASE_DIR/strict-parser.sha256"
printf '%s\n' "$DIRTY_DIFF_SHA256" >"$BASE_DIR/dirty-diff.sha256"

echo "[mini-air] Air reachability check..."
$AIR_SSH 'uname -m' | tail -1
AIR_PUBLIC_IPV4=$($AIR_SSH 'curl --noproxy "*" -s --max-time 8 ifconfig.me || true' | tail -1 | tr -d '[:space:]')
MINI_PUBLIC_IPV4=$(curl -s4 --max-time 8 ifconfig.me || true)
MINI_PUBLIC_IPV4=$(printf '%s\n' "$MINI_PUBLIC_IPV4" | tail -1 | tr -d '[:space:]')
echo "[mini-air] Air public IPv4: $AIR_PUBLIC_IPV4"
echo "[mini-air] Mini public IPv4: $MINI_PUBLIC_IPV4"
if [[ -z "$AIR_PUBLIC_IPV4" || -z "$MINI_PUBLIC_IPV4" ]]; then
  echo "[mini-air] could not determine both public IPv4 addresses" >&2
  exit 2
fi

if lsof -nP -iTCP:"$DIAG_A_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "[mini-air] Mini diagnostics port is already occupied: $DIAG_A_PORT" >&2
  exit 2
fi
if $AIR_SSH "lsof -nP -iTCP:$DIAG_B_PORT -sTCP:LISTEN >/dev/null 2>&1"; then
  echo "[mini-air] Air diagnostics port is already occupied: $DIAG_B_PORT" >&2
  exit 2
fi

# Every run gets an independent Air directory. A pre-positioned binary would
# defeat the required upload SHA audit, so refuse that legacy escape hatch.
if [[ -n "$AIR_DAEMON_BIN" ]]; then
  echo "[mini-air] AIR_DAEMON_BIN is not allowed for audited dual-end runs" >&2
  exit 2
fi
$AIR_SSH "umask 077; mkdir -m 700 '$REMOTE_RUN_DIR'"
# Upload only to the `.new` sibling, verify its digest before it becomes
# executable, then atomically install it inside this run's directory.
$AIR_SSH "cat > '$REMOTE_DAEMON_BIN.new'" < "$DAEMON_BIN"
REMOTE_NEW_SHA256=$($AIR_SSH "if command -v shasum >/dev/null 2>&1; then shasum -a 256 '$REMOTE_DAEMON_BIN.new' | awk '{print \$1}'; elif command -v sha256sum >/dev/null 2>&1; then sha256sum '$REMOTE_DAEMON_BIN.new' | awk '{print \$1}'; else exit 127; fi")
if [[ "$REMOTE_NEW_SHA256" != "$LOCAL_DAEMON_SHA256" ]]; then
  echo "[mini-air] Air uploaded binary SHA-256 mismatch; refusing to install it" >&2
  exit 1
fi
$AIR_SSH "chmod 700 '$REMOTE_DAEMON_BIN.new' && mv '$REMOTE_DAEMON_BIN.new' '$REMOTE_DAEMON_BIN'"

# A matching semantic version is not enough here: a user can correctly upload
# an older release build after the source tree has changed.  Refuse to run a
# two-ended smoke test unless the Air executes the exact local release binary.
REMOTE_DAEMON_SHA256=$($AIR_SSH "if command -v shasum >/dev/null 2>&1; then shasum -a 256 '$REMOTE_DAEMON_BIN' | awk '{print \$1}'; elif command -v sha256sum >/dev/null 2>&1; then sha256sum '$REMOTE_DAEMON_BIN' | awk '{print \$1}'; else exit 127; fi")
if [[ "$REMOTE_DAEMON_SHA256" != "$LOCAL_DAEMON_SHA256" ]]; then
  echo "[mini-air] Air daemon SHA-256 mismatch; refusing to start smoke daemons." >&2
  echo "[mini-air] local release:  $DAEMON_BIN ($LOCAL_DAEMON_SHA256)" >&2
  echo "[mini-air] Air binary:     $REMOTE_DAEMON_BIN (${REMOTE_DAEMON_SHA256:-unavailable})" >&2
  echo "[mini-air] Upload the exact local release binary to AIR_DAEMON_BIN, then rerun." >&2
  exit 1
fi
echo "[mini-air] Air daemon SHA-256 verified: $LOCAL_DAEMON_SHA256"
if [[ "$REAL_TUN" == "1" && "$PRIVILEGED_SUPERVISOR" == "1" ]]; then
  local_privileged_supervisor_start
  remote_privileged_supervisor_start
  echo "[mini-air] privileged authorization scope: one dialog per endpoint for this run" >&2
fi
echo "[mini-air] isolated network id: $NETWORK_ID"
printf '%s\n' "direct_udp_blackhole=$DIRECT_UDP_BLACKHOLE" >"$BASE_DIR/scenario.txt"
if [[ "$DIRECT_UDP_BLACKHOLE" == "1" ]]; then
  apply_direct_udp_blackhole
  echo "[mini-air] Direct UDP blackhole active; relay TCP/control HTTP remain enabled"
fi

overall=0
if [[ "$ACCEPTANCE_MODE" == "compat" ]]; then
  printf 'round\tacceptance_mode\tfunctional_direct_ms\telapsed_ms\ta_endpoint\tb_endpoint\ta_crash_panic\tb_crash_panic\n' >"$BASE_DIR/round-metrics.tsv"
elif [[ "$ACCEPTANCE_MODE" == "availability" ]]; then
  printf 'round\tacceptance_mode\tfirst_usable_after_relay_ms\telapsed_ms\tfirst_usable_path_a\tfirst_usable_path_b\ta_direct\tb_direct\ta_relay_selections\tb_relay_selections\ta_overlay_round_trips\tb_overlay_round_trips\ta_relay_peer_confirmed\tb_relay_peer_confirmed\ta_crash_panic\tb_crash_panic\n' >"$BASE_DIR/round-metrics.tsv"
else
  printf 'round\tacceptance_mode\tfunctional_direct_ms\tstrict_convergence_ms\telapsed_ms\ta_direct\tb_direct\ta_endpoint\tb_endpoint\ta_validation_sessions\tb_validation_sessions\ta_validation_requests\tb_validation_requests\ta_validation_acks\tb_validation_acks\ta_validation_promoted\tb_validation_promoted\ta_strict_validation\tb_strict_validation\ta_matched_acks\tb_matched_acks\ta_overlay_round_trips\tb_overlay_round_trips\ta_http_429\tb_http_429\ta_relay_hedges\tb_relay_hedges\ta_relay_fallbacks\tb_relay_fallbacks\ta_relay_selections\tb_relay_selections\ta_crash_panic\tb_crash_panic\ta_post_direct_traversal\tb_post_direct_traversal\ta_non_target_traversal\tb_non_target_traversal\n' >"$BASE_DIR/round-metrics.tsv"
fi
LOCAL_VALIDATE_OVERLAY_FLAG=""
REMOTE_VALIDATE_OVERLAY_ARG=""
if [[ "$VALIDATE_OVERLAY" == "1" || "$ACCEPTANCE_MODE" == "availability" ]]; then
  if [[ "$REAL_TUN" == "1" ]]; then
    LOCAL_VALIDATE_OVERLAY_FLAG=""
    REMOTE_VALIDATE_OVERLAY_ARG=""
  else
  # Availability mode ALWAYS drives the real encrypted overlay loopback and
  # targets every online peer (relay-usable until Direct is confirmed), so the
  # first-usable standard does not depend on a UDP punch succeeding.
  LOCAL_VALIDATE_OVERLAY_FLAG="--validate-overlay --overlay-any-path"
  REMOTE_VALIDATE_OVERLAY_ARG="--validate-overlay --overlay-any-path"
  fi
fi
PATH_POLICY_FLAG=""
if [[ "$ACCEPTANCE_MODE" == "availability" ]]; then
  # Availability preflight is deliberately relay-first at the DATA decision:
  # the daemon's normal policy keeps business traffic on Relay until a real
  # Direct validation ACK promotes the path, while the Direct probe worker
  # continues in the background.  `--prefer-relay` is a different, explicit
  # relay-only policy in the CLI and would disable Direct probing/promotion;
  # never use it as a relay-first acceptance shortcut.
  PATH_POLICY_FLAG=""
fi
for round in $(seq 1 "$ROUNDS"); do
  ROUND_DIR="$BASE_DIR/round-$round"
  mkdir -p "$ROUND_DIR"
  POLL_INDEX=0
  CURRENT_A_POLL=""
  CURRENT_B_POLL=""
  CURRENT_RESULT=""
  MINI_NODE_ID=""
  AIR_NODE_ID=""
  MINI_VIRTUAL_IP=""
  AIR_VIRTUAL_IP=""
  REAL_OVERLAY_OK=0
  REAL_OVERLAY_MINI_REPLIES=0
  REAL_OVERLAY_AIR_REPLIES=0
  ISOLATION_MODE="strict-exact-two"
  if [[ "$ALLOW_SHARED_NETWORK" == "1" ]]; then
    ISOLATION_MODE="target-scoped-shared"
  fi

  CONTROL_URL="$REMOTE_CONTROL_URL"
  for _ in {1..40}; do
    curl -fsS --max-time 5 "$CONTROL_URL/health" >/dev/null 2>&1 && break
    sleep 0.25
  done
  curl -fsS --max-time 5 "$CONTROL_URL/health" >/dev/null
  # The verification control DB is shared, so every round needs a new account.
  REMOTE_EMAIL="smoke-$(date +%s)-${round}@example.com"
  REGISTER_JSON=$(curl -fsS --max-time 8 -X POST "$CONTROL_URL/api/v1/register" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$REMOTE_EMAIL\",\"password\":\"passw0rd\"}")
  TOKEN=$(printf '%s' "$REGISTER_JSON" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  if [[ -z "$TOKEN" ]]; then
    echo "[mini-air] round $round: failed to parse auth token" >&2
    exit 1
  fi

  LOCAL_NODE_A_TOKEN_FILE="$LOCAL_RUN_DIR/node-a-$RUN_ID-round-$round.token"
  REMOTE_NODE_B_TOKEN_FILE="$REMOTE_RUN_DIR/node-b-$RUN_ID-round-$round.token"
  # Feed credentials over stdin into permission-protected temporary files.
  # The token is never present in a daemon command line, process listing, or
  # artifact directory.
  (umask 077; printf '%s\n' "$TOKEN" >"$LOCAL_NODE_A_TOKEN_FILE")
  $AIR_SSH "umask 077; cat > '$REMOTE_NODE_B_TOKEN_FILE'; chmod 600 '$REMOTE_NODE_B_TOKEN_FILE'" <<<"$TOKEN"

  START_MS=$(python3 -c 'import time; print(int(time.time()*1000))')

  # Daemon A on the Mini.
  LOCAL_NODE_A_CONFIG="$LOCAL_RUN_DIR/node-a-$RUN_ID-round-$round.json"
  LOCAL_NODE_A_DEVICE="mini-a-$RUN_ID-round-$round"
  LOCAL_NODE_A_PID_FILE="$ROUND_DIR/node-a.pid"
  if [[ "$REAL_TUN" == "1" ]]; then
    LOCAL_DAEMON_COMMAND="echo \$\$ > '$LOCAL_NODE_A_PID_FILE'; exec env -u P2WLAN_DISABLE_TUN P2WLAN_TEST_RUN_ID='$RUN_ID' RUST_LOG='$HARNESS_RUST_LOG' '$DAEMON_BIN' --config '$LOCAL_NODE_A_CONFIG' --control '$CONTROL_URL' --network '$NETWORK_ID' --token-file '$LOCAL_NODE_A_TOKEN_FILE' --device-name '$LOCAL_NODE_A_DEVICE' --udp-bind 0.0.0.0:0 --socket-pool 3 --stun '$STUN_SERVERS' --stun-timeout-ms 1000 --diagnostics-bind 127.0.0.1:$DIAG_A_PORT --heartbeat-interval 5 $PATH_POLICY_FLAG $LOCAL_VALIDATE_OVERLAY_FLAG >'$ROUND_DIR/node-a.log' 2>&1"
  else
    LOCAL_DAEMON_COMMAND="echo \$\$ > '$LOCAL_NODE_A_PID_FILE'; exec env P2WLAN_DISABLE_TUN=1 P2WLAN_TEST_RUN_ID='$RUN_ID' RUST_LOG='$HARNESS_RUST_LOG' '$DAEMON_BIN' --config '$LOCAL_NODE_A_CONFIG' --control '$CONTROL_URL' --network '$NETWORK_ID' --token-file '$LOCAL_NODE_A_TOKEN_FILE' --device-name '$LOCAL_NODE_A_DEVICE' --udp-bind 0.0.0.0:0 --socket-pool 3 --stun '$STUN_SERVERS' --stun-timeout-ms 1000 --diagnostics-bind 127.0.0.1:$DIAG_A_PORT --heartbeat-interval 5 $PATH_POLICY_FLAG $LOCAL_VALIDATE_OVERLAY_FLAG >'$ROUND_DIR/node-a.log' 2>&1"
  fi
  if [[ "$REAL_TUN" == "1" && "$LOCAL_PRIVILEGED_SUPERVISOR_ACTIVE" == "1" ]]; then
    if ! local_privileged_exec "$LOCAL_DAEMON_COMMAND" || ! wait_for_local_pid_file "$LOCAL_NODE_A_PID_FILE"; then
      echo "[mini-air] ROUND $round: Mini privileged supervisor launch did not produce this round's PID file" >&2
      overall=1
      local_daemon_cleanup || true
      if ! delete_round_devices "$ROUND_DIR"; then exit 1; fi
      continue
    fi
    NODE_A_WRAPPER_PID=""
    NODE_A_PID=$(cat "$LOCAL_NODE_A_PID_FILE")
    LOCAL_NODE_A_PID="$NODE_A_PID"
  elif [[ "$REAL_TUN" == "1" && "$LOCAL_DAEMON_NEEDS_OSASCRIPT" == "1" ]]; then
    if ! local_osascript_shell_launch "$LOCAL_DAEMON_COMMAND" "$LOCAL_NODE_A_PID_FILE"; then
      echo "[mini-air] ROUND $round: Mini privileged launch did not produce this round's PID file" >&2
      overall=1
      local_daemon_cleanup || true
      if ! delete_round_devices "$ROUND_DIR"; then exit 1; fi
      continue
    fi
    NODE_A_WRAPPER_PID=""
    NODE_A_PID=$(cat "$LOCAL_NODE_A_PID_FILE")
    LOCAL_NODE_A_PID="$NODE_A_PID"
  else
    /bin/sh -c "$LOCAL_DAEMON_COMMAND" >/dev/null 2>&1 &
    NODE_A_WRAPPER_PID=$!
    NODE_A_PID="$NODE_A_WRAPPER_PID"
    LOCAL_NODE_A_PID="$NODE_A_WRAPPER_PID"
  fi

  for _ in {1..60}; do
    grep -q 'Control plane registration confirmed' "$ROUND_DIR/node-a.log" 2>/dev/null && break
    sleep 0.25
  done

  # Registration is logged before TUN and diagnostics startup completes.  A
  # root-launched macOS daemon can therefore have a valid PID and a
  # successful control registration while port 49377 is still not listening.
  # Do not let the later bootstrap curl turn that normal startup window into a
  # set -e harness abort (or leave a detached privileged daemon behind).
  A_READY=0
  for _ in $(seq 1 40); do
    if curl -fsS --max-time 3 "http://127.0.0.1:$DIAG_A_PORT/health" >/dev/null 2>&1; then
      A_READY=1
      break
    fi
    sleep 0.25
  done
  if [[ "$A_READY" -ne 1 ]]; then
    echo "[mini-air] ROUND $round: FAIL (Mini daemon diagnostics never became ready)" >&2
    overall=1
    cp "$ROUND_DIR/node-a.log" "$ROUND_DIR/node-a-startup-failure.log" 2>/dev/null || true
    remote_daemon_cleanup || true
    kill_remote_wrapper
    local_daemon_cleanup || true
    if ! delete_round_devices "$ROUND_DIR"; then exit 1; fi
    continue
  fi

  # Daemon B on the Air (fresh config every round).
  AIR_CONFIG="$REMOTE_RUN_DIR/node-b-$RUN_ID-round-$round.json"
  REMOTE_NODE_B_PID_FILE="$REMOTE_RUN_DIR/node-b-$RUN_ID-round-$round.pid"
  REMOTE_NODE_B_LOG="$REMOTE_RUN_DIR/node-b-$RUN_ID-round-$round.log"
  REMOTE_NODE_B_DEVICE="air-b-$RUN_ID-round-$round"
  REMOTE_NODE_B_TOKEN_FILE="$REMOTE_RUN_DIR/node-b-$RUN_ID-round-$round.token"
  # The ordinary SSH path keeps the remote daemon in the foreground and holds
  # the local SSH wrapper.  The Authorization Services path cannot do that:
  # it detaches the root daemon after the global Air authorization dialog and
  # waits for this round's PID file.  In both paths the remote PID file is the
  # authoritative identity for status ownership and teardown.
  REMOTE_DAEMON_COMMAND="echo \$\$ > '$REMOTE_NODE_B_PID_FILE'; exec $TUN_REMOTE_RUN_PREFIX P2WLAN_TEST_RUN_ID='$RUN_ID' RUST_LOG='$HARNESS_RUST_LOG' '$REMOTE_DAEMON_BIN' \\
    --config '$AIR_CONFIG' \\
    --control '$CONTROL_URL' \\
    --network '$NETWORK_ID' \\
    --token-file '$REMOTE_NODE_B_TOKEN_FILE' \\
    --device-name '$REMOTE_NODE_B_DEVICE' \\
    --udp-bind 0.0.0.0:0 \
    --socket-pool 3 \
    --stun '$STUN_SERVERS' \
    --stun-timeout-ms 1000 \
    --diagnostics-bind 127.0.0.1:$DIAG_B_PORT \
    --heartbeat-interval 5 \
    $PATH_POLICY_FLAG \
    $REMOTE_VALIDATE_OVERLAY_ARG \
     </dev/null >'$REMOTE_NODE_B_LOG' 2>&1"
  if [[ "$REMOTE_PRIVILEGED_SUPERVISOR_ACTIVE" == "1" ]]; then
    if ! remote_privileged_exec "$REMOTE_DAEMON_COMMAND" || ! wait_for_remote_pid_file "$REMOTE_NODE_B_PID_FILE"; then
      echo "[mini-air] ROUND $round: Air privileged supervisor launch did not produce this round's PID file" >&2
      overall=1
      remote_daemon_cleanup || true
      local_daemon_cleanup || true
      if ! delete_round_devices "$ROUND_DIR"; then exit 1; fi
      continue
    fi
    NODE_B_PID=""
    AIR_DAEMON_PID_FOR_ARTIFACT=$($AIR_SSH "cat '$REMOTE_NODE_B_PID_FILE' 2>/dev/null || true")
    printf '%s\n' "$AIR_DAEMON_PID_FOR_ARTIFACT" >"$ROUND_DIR/node-b.pid"
  elif [[ "$AIR_REMOTE_NEEDS_OSASCRIPT" == "1" ]]; then
    if ! remote_osascript_shell_launch "$REMOTE_DAEMON_COMMAND" "$REMOTE_NODE_B_PID_FILE"; then
      echo "[mini-air] ROUND $round: Air privileged launch did not produce this round's PID file" >&2
      overall=1
      remote_daemon_cleanup || true
      local_daemon_cleanup || true
      if ! delete_round_devices "$ROUND_DIR"; then exit 1; fi
      continue
    fi
    NODE_B_PID=""
    AIR_DAEMON_PID_FOR_ARTIFACT=$($AIR_SSH "cat '$REMOTE_NODE_B_PID_FILE' 2>/dev/null || true")
    printf '%s\n' "$AIR_DAEMON_PID_FOR_ARTIFACT" >"$ROUND_DIR/node-b.pid"
  else
    $AIR_SSH "$REMOTE_DAEMON_COMMAND" >/dev/null 2>&1 &
    NODE_B_PID=$!
    printf '%s\n' "$NODE_B_PID" >"$ROUND_DIR/node-b.pid"
  fi
  # The daemon must actually be up before the Direct wait begins (a fresh
  # config is generated on first start, which takes a beat).  Instead of a
  # fixed padding, wait for the daemon's diagnostics endpoint to answer so the
  # measured cold-start window is not inflated by a constant sleep.
  B_READY=0
  for _ in $(seq 1 40); do
    if $AIR_SSH "curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:$DIAG_B_PORT/health >/dev/null 2>&1" 2>/dev/null; then
      B_READY=1
      break
    fi
    sleep 0.25
  done
  if [[ "$B_READY" -ne 1 ]]; then
    echo "[mini-air] ROUND $round: FAIL (Air daemon diagnostics never became ready)" >&2
    overall=1
    collect_air_log || : >"$ROUND_DIR/node-b.log"
    remote_daemon_cleanup || true
    kill_remote_wrapper
    local_daemon_cleanup || true
    if ! delete_round_devices "$ROUND_DIR"; then exit 1; fi
    continue
  fi

  # A stale root daemon can leave the diagnostics port alive after a failed
  # cleanup. Never trust that old endpoint: status.process_id must match the
  # exact PID written by this round before its node identity or virtual IP is
  # used for traffic and verdicts.
  MINI_STATUS_BOOTSTRAP="$ROUND_DIR/mini-status-bootstrap.json"
  AIR_STATUS_BOOTSTRAP="$ROUND_DIR/air-status-bootstrap.json"
  if ! curl -fsS --max-time 5 "http://127.0.0.1:$DIAG_A_PORT/status.runtime" >"$MINI_STATUS_BOOTSTRAP"; then
    echo "[mini-air] ROUND $round: FAIL (Mini diagnostics disappeared before bootstrap)" >&2
    overall=1
    remote_daemon_cleanup || true
    kill_remote_wrapper
    local_daemon_cleanup || true
    if ! delete_round_devices "$ROUND_DIR"; then exit 1; fi
    continue
  fi
  if ! $AIR_SSH "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:$DIAG_B_PORT/status.runtime" >"$AIR_STATUS_BOOTSTRAP"; then
    echo "[mini-air] ROUND $round: FAIL (Air diagnostics disappeared before bootstrap)" >&2
    overall=1
    remote_daemon_cleanup || true
    kill_remote_wrapper
    local_daemon_cleanup || true
    if ! delete_round_devices "$ROUND_DIR"; then exit 1; fi
    continue
  fi
  MINI_EXPECTED_PID=$(cat "$LOCAL_NODE_A_PID_FILE" 2>/dev/null || true)
  AIR_EXPECTED_PID=$($AIR_SSH "cat '$REMOTE_NODE_B_PID_FILE' 2>/dev/null || true")
  MINI_STATUS_PID=$(python3 - "$MINI_STATUS_BOOTSTRAP" <<'PY'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        print(json.load(stream).get("process_id", ""))
except (OSError, ValueError):
    print("")
PY
)
  AIR_STATUS_PID=$(python3 - "$AIR_STATUS_BOOTSTRAP" <<'PY'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        print(json.load(stream).get("process_id", ""))
except (OSError, ValueError):
    print("")
PY
)
  if [[ -z "$MINI_EXPECTED_PID" || -z "$AIR_EXPECTED_PID" ||
        "$MINI_STATUS_PID" != "$MINI_EXPECTED_PID" ||
        "$AIR_STATUS_PID" != "$AIR_EXPECTED_PID" ]]; then
    echo "[mini-air] ROUND $round: FAIL (diagnostics endpoint is not owned by this round's daemon)" >&2
    printf 'mini_expected_pid=%s mini_status_pid=%s air_expected_pid=%s air_status_pid=%s\n' \
      "$MINI_EXPECTED_PID" "$MINI_STATUS_PID" "$AIR_EXPECTED_PID" "$AIR_STATUS_PID" \
      >"$ROUND_DIR/diagnostics-owner-mismatch.txt"
    overall=1
    collect_air_log || true
    remote_daemon_cleanup || true
    kill_remote_wrapper
    local_daemon_cleanup || true
    if ! delete_round_devices "$ROUND_DIR"; then exit 1; fi
    continue
  fi

  # The verification control plane is shared with other test nodes.  Resolve
  # this round's two independently generated identities from their own
  # diagnostics and use those exact peer IDs for every success predicate and
  # evidence counter below.  A third node's Direct path must never make this
  # Mini <-> Air round pass.
  MINI_NODE_ID=$(python3 - "$MINI_STATUS_BOOTSTRAP" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream).get("node_id", ""))
PY
  )
  AIR_NODE_ID=$(python3 - "$AIR_STATUS_BOOTSTRAP" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream).get("node_id", ""))
PY
  )
  if [[ -z "$MINI_NODE_ID" || -z "$AIR_NODE_ID" ]]; then
    echo "[mini-air] ROUND $round: FAIL (could not resolve this round's test node IDs)" >&2
    overall=1
    remote_daemon_cleanup || true
    kill_remote_wrapper
    local_daemon_cleanup || true
    if ! delete_round_devices "$ROUND_DIR"; then exit 1; fi
    continue
  fi
  MINI_VIRTUAL_IP=$(python3 - "$MINI_STATUS_BOOTSTRAP" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream).get("virtual_ip", ""))
PY
  )
  AIR_VIRTUAL_IP=$(python3 - "$AIR_STATUS_BOOTSTRAP" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream).get("virtual_ip", ""))
PY
  )
  if [[ "$REAL_TUN" == "1" && ( -z "$MINI_VIRTUAL_IP" || -z "$AIR_VIRTUAL_IP" ) ]]; then
    echo "[mini-air] ROUND $round: FAIL (real TUN status did not expose both virtual IPs)" >&2
    overall=1
    remote_daemon_cleanup || true
    kill_remote_wrapper
    local_daemon_cleanup || true
    if ! delete_round_devices "$ROUND_DIR"; then exit 1; fi
    continue
  fi
  if [[ "$REAL_TUN" == "1" ]]; then
    capture_route_snapshot "$ROUND_DIR" pre-traffic "$MINI_VIRTUAL_IP" "$AIR_VIRTUAL_IP"
  fi

  # Real-time isolation proof before the traversal window opens: the
  # network's ACTIVE roster must be exactly this round's two nodes.  Any
  # third-party active node, a control-plane listing failure, or a proof
  # timeout aborts the run immediately as isolation-invalid — it is never
  # counted as a product failure or a PASS.
  if [[ "$REAL_TUN" == "1" || "$ACCEPTANCE_MODE" == "strict" ]]; then
    ISOLATION_REPORT="$ROUND_DIR/isolation-prove.json"
    isolation_command=(--prove "$CONTROL_URL" "$TOKEN" "$NETWORK_ID" "$MINI_NODE_ID" "$AIR_NODE_ID")
    if [[ "$ISOLATION_MODE" == "target-scoped-shared" ]]; then
      isolation_command=(--prove-target "$CONTROL_URL" "$TOKEN" "$NETWORK_ID" "$MINI_NODE_ID" "$AIR_NODE_ID")
    fi
    if python3 "$ISOLATION_HELPER" "${isolation_command[@]}" --deadline 25 \
      >"$ISOLATION_REPORT" 2>"$ROUND_DIR/isolation-prove.err"; then
      ISOLATION_OK=1
    else
      ISOLATION_OK=0
      echo "[mini-air] ROUND $round: ISOLATION-INVALID (network isolation proof failed); aborting run" >&2
      cat "$ISOLATION_REPORT" >&2
      record_sequence_round "$round" 0 "" ""
      collect_air_log || true
      remote_daemon_cleanup || true
      kill_remote_wrapper
      local_daemon_cleanup || true
      redact_local_config || true
      if ! delete_round_devices "$ROUND_DIR"; then exit 1; fi
      exit 1
    fi
  else
    ISOLATION_OK=0
  fi

  if [[ "$REAL_TUN" == "1" ]]; then
    if ! wait_for_target_relay_pair "$ROUND_DIR"; then
      echo "[mini-air] ROUND $round: FAIL (both target relay peer ACKs did not arrive before real TUN traffic)" >&2
      overall=1
      collect_air_log || true
      remote_daemon_cleanup || true
      kill_remote_wrapper
      local_daemon_cleanup || true
      if ! delete_round_devices "$ROUND_DIR"; then exit 1; fi
      continue
    fi
    echo "[mini-air] ROUND $round: sending bounded real TUN ICMP probes $MINI_VIRTUAL_IP <-> $AIR_VIRTUAL_IP"
    run_real_tun_business_pair "$ROUND_DIR" "$MINI_VIRTUAL_IP" "$AIR_VIRTUAL_IP"
  fi

  # Capture both snapshots in the same poll. Compatibility accepts observable
  # Direct state only; strict mode additionally requires the owned lifecycle.
  direct_ok=0
  INFRASTRUCTURE_INVALID=0
  FUNCTIONAL_DIRECT_MS=""
  STRICT_CONVERGENCE_MS=""
  POLL_INDEX=0
  CURRENT_A_POLL=""
  CURRENT_B_POLL=""
  CURRENT_RESULT=""
  EVIDENCE_A_STATUS=""
  EVIDENCE_B_STATUS=""
  EVIDENCE_RESULT=""
  CAPTURE_WINDOW_S=$DIRECT_TIMEOUT_S
  if [[ "$ACCEPTANCE_MODE" == "strict" && "$CAPTURE_WINDOW_S" -lt 45 ]]; then
    CAPTURE_WINDOW_S=45
  fi
  if [[ "$ACCEPTANCE_MODE" == "availability" ]]; then
    # Availability does not wait for Direct to converge: the overlay loopback
    # (over relay until Direct is confirmed) is the usability gate, and the
    # status snapshots below only feed the artifacts.
    CAPTURE_WINDOW_S=$OVERLAY_TIMEOUT_S
  fi
  # Bound the capture window by wall time, not by a fixed number of polls.
  # A full status snapshot can be large and an SSH/curl retry may consume
  # several seconds; the old poll-count loop therefore stretched a nominal
  # 12-second availability window to more than 90 seconds without adding
  # evidence.  One slow capture may overrun the deadline, but subsequent
  # polls are never allowed to extend it indefinitely.
  CAPTURE_STARTED_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
  CAPTURE_DEADLINE_MS=$((CAPTURE_STARTED_MS + CAPTURE_WINDOW_S * 1000))
  while :; do
    NOW_CAPTURE_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
    [[ "$NOW_CAPTURE_MS" -ge "$CAPTURE_DEADLINE_MS" ]] && break
    accepted_pair=0
    if capture_status_pair; then
      if [[ "$ACCEPTANCE_MODE" == "compat" ]]; then
        compatibility_direct_pair "$CURRENT_A_POLL" "$AIR_NODE_ID" "$CURRENT_B_POLL" "$MINI_NODE_ID" && accepted_pair=1
      elif [[ "$ACCEPTANCE_MODE" == "strict" ]]; then
        strict_validation_pair "$CURRENT_A_POLL" "$AIR_NODE_ID" "$CURRENT_B_POLL" "$MINI_NODE_ID" >/dev/null && accepted_pair=1
        if [[ "$accepted_pair" -eq 1 ]]; then
          # Strict acceptance is based on the daemon's committed promotion
          # event, reconstructed from the scoped snapshot timestamp and event
          # age. Transport/SSH completion time is not a traversal metric.
          promotion_ms=$(python3 - "$CURRENT_RESULT" "$START_MS" "$DIRECT_SUCCESS_TARGET_MS" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)
values = [
    (side or {}).get("key", {}).get("direct_promotion_at_ms")
    for side in (result.get("left", {}), result.get("right", {}))
]
if any(value is None for value in values):
    raise SystemExit(1)
elapsed = max(values) - int(sys.argv[2])
if elapsed < 0 or elapsed > int(sys.argv[3]):
    raise SystemExit(1)
print(elapsed)
PY
          ) || accepted_pair=0
          if [[ "$accepted_pair" -eq 1 ]]; then
            STRICT_CONVERGENCE_MS="$promotion_ms"
          fi
        fi
      fi
    fi
    if [[ "$accepted_pair" -eq 1 ]]; then
      direct_ok=1
      END_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
      if [[ "$ACCEPTANCE_MODE" == "compat" ]]; then
        FUNCTIONAL_DIRECT_MS=$((END_MS - START_MS))
      fi
      if [[ "$ACCEPTANCE_MODE" == "strict" ]]; then
        cp "$CURRENT_A_POLL" "$ROUND_DIR/strict-success-node-a.json"
        cp "$CURRENT_B_POLL" "$ROUND_DIR/strict-success-node-b.json"
        cp "$CURRENT_RESULT" "$ROUND_DIR/strict-success-result.json"
        EVIDENCE_RESULT="$ROUND_DIR/strict-success-result.json"
      fi
      EVIDENCE_A_STATUS="$CURRENT_A_POLL"
      EVIDENCE_B_STATUS="$CURRENT_B_POLL"
      break
    fi
    sleep 0.5
  done
  END_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
  ELAPSED_MS=$((END_MS - START_MS))

  # Preserve the complete Air log beside the Mini log before teardown.  A
  # failed remote copy is itself test evidence; do not silently collapse a
  # two-ended failure into a single-sided PASS/FAIL line.
  if ! collect_air_log; then
    echo "[mini-air] ROUND $round: FAIL (could not collect complete Air daemon log)" >&2
    : >"$ROUND_DIR/node-b.log"
    INFRASTRUCTURE_INVALID=1
    overall=1
    # Preserve the transport error, remote PID, daemon stderr/log, and the
    # last status attempt as infrastructure evidence rather than product
    # failure evidence.
    $AIR_SSH "printf 'remote_pid=%s\\n' \"\$(cat '$REMOTE_NODE_B_PID_FILE' 2>/dev/null || true)\"; ps -p \"\$(cat '$REMOTE_NODE_B_PID_FILE' 2>/dev/null || true)\" -o pid=,stat=,command= 2>&1; cat '$REMOTE_NODE_B_LOG' 2>&1" \
      >"$ROUND_DIR/air-infrastructure.txt" 2>"$ROUND_DIR/air-ssh-error.txt" || true
  fi

  # Preserve a failed poll separately. A failed snapshot can never replace a
  # strict-success snapshot from an earlier poll.
  STATUS_CAPTURE_OK=1
  if [[ "$direct_ok" -ne 1 ]] && ! capture_status_pair; then
    printf '{}\n' >"$ROUND_DIR/strict-last-failed-node-a.json"
    printf '{}\n' >"$ROUND_DIR/strict-last-failed-node-b.json"
    printf '{"ok":false,"reason":"status_capture_failed"}\n' >"$ROUND_DIR/strict-last-failed-result.json"
    EVIDENCE_A_STATUS="$ROUND_DIR/strict-last-failed-node-a.json"
    EVIDENCE_B_STATUS="$ROUND_DIR/strict-last-failed-node-b.json"
    EVIDENCE_RESULT="$ROUND_DIR/strict-last-failed-result.json"
    echo "[mini-air] round $round: could not collect final paired diagnostics snapshot" >&2
    STATUS_CAPTURE_OK=0
    INFRASTRUCTURE_INVALID=1
    : >"$ROUND_DIR/air-status-last-error.txt"
    cat "$ROUND_DIR/node-b.poll-$POLL_INDEX.stderr" >>"$ROUND_DIR/air-status-last-error.txt" 2>/dev/null || true
  elif [[ "$direct_ok" -ne 1 ]]; then
    cp "$CURRENT_A_POLL" "$ROUND_DIR/strict-last-failed-node-a.json"
    cp "$CURRENT_B_POLL" "$ROUND_DIR/strict-last-failed-node-b.json"
    cp "$CURRENT_RESULT" "$ROUND_DIR/strict-last-failed-result.json"
    EVIDENCE_A_STATUS="$ROUND_DIR/strict-last-failed-node-a.json"
    EVIDENCE_B_STATUS="$ROUND_DIR/strict-last-failed-node-b.json"
    EVIDENCE_RESULT="$ROUND_DIR/strict-last-failed-result.json"
  fi

  if [[ "$direct_ok" -eq 1 && "$ACCEPTANCE_MODE" == "strict" ]]; then
    EVIDENCE_A_STATUS="$ROUND_DIR/strict-success-node-a.json"
    EVIDENCE_B_STATUS="$ROUND_DIR/strict-success-node-b.json"
  fi
  if [[ -z "$EVIDENCE_RESULT" ]]; then
    EVIDENCE_RESULT="$CURRENT_RESULT"
  fi
  SNAPSHOT_POLL_INDEX="$POLL_INDEX"
  SNAPSHOT_ID=$(printf 'poll-%03d' "$SNAPSHOT_POLL_INDEX")
  SNAPSHOT_A_SHA256=$(sha256_file "$EVIDENCE_A_STATUS")
  SNAPSHOT_B_SHA256=$(sha256_file "$EVIDENCE_B_STATUS")
  SNAPSHOT_RESULT_SHA256=$(sha256_file "$EVIDENCE_RESULT")

  A_POST_DIRECT_TRAVERSAL=0
  B_POST_DIRECT_TRAVERSAL=0
  A_STRICT_VALIDATION=""
  B_STRICT_VALIDATION=""
  if [[ "$ACCEPTANCE_MODE" == "strict" ]]; then
    # Materialize the strict predicate and audit independently from the poll.
    python3 "$STRICT_PARSER" --summary "$EVIDENCE_A_STATUS" "$AIR_NODE_ID" >"$ROUND_DIR/node-a.audit.json"
    python3 "$STRICT_PARSER" --summary "$EVIDENCE_B_STATUS" "$MINI_NODE_ID" >"$ROUND_DIR/node-b.audit.json"
    python3 - "$ROUND_DIR/node-a.audit.json" "$ROUND_DIR/node-b.audit.json" "$EVIDENCE_RESULT" "$SNAPSHOT_ID" "$SNAPSHOT_POLL_INDEX" "$SNAPSHOT_A_SHA256" "$SNAPSHOT_B_SHA256" "$SNAPSHOT_RESULT_SHA256" <<'PY' >"$ROUND_DIR/round-audit.json"
import json
import sys

def load(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)

print(json.dumps({
    "mini": load(sys.argv[1]),
    "air": load(sys.argv[2]),
    "strict_pair": load(sys.argv[3]),
    "snapshot_id": sys.argv[4],
    "poll_index": int(sys.argv[5]),
    "snapshot_sha256": {
        "mini": sys.argv[6],
        "air": sys.argv[7],
        "result": sys.argv[8],
    },
}, indent=2, sort_keys=True))
PY
    A_POST_DIRECT_TRAVERSAL=$(python3 - "$ROUND_DIR/node-a.audit.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(len(json.load(stream).get("post_direct_traversal_starts", [])))
PY
)
    B_POST_DIRECT_TRAVERSAL=$(python3 - "$ROUND_DIR/node-b.audit.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(len(json.load(stream).get("post_direct_traversal_starts", [])))
PY
)
  fi

  A_DIRECT=$(count_log_events_for_peer "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" '→ direct')
  B_DIRECT=$(count_log_events_for_peer "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" '→ direct')
  A_EP=$(direct_endpoint_from_log "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" || true)
  B_EP=$(direct_endpoint_from_log "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" || true)
  A_VALIDATION_SESSIONS=$(count_stage "$EVIDENCE_A_STATUS" "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'encrypted_trial_started')
  B_VALIDATION_SESSIONS=$(count_stage "$EVIDENCE_B_STATUS" "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'encrypted_trial_started')
  A_VALIDATION_REQUESTS=$(count_stage "$EVIDENCE_A_STATUS" "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'direct_validation_request_sent')
  B_VALIDATION_REQUESTS=$(count_stage "$EVIDENCE_B_STATUS" "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'direct_validation_request_sent')
  A_VALIDATION_ACKS=$(count_stage "$EVIDENCE_A_STATUS" "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'direct_validation_ack_received')
  B_VALIDATION_ACKS=$(count_stage "$EVIDENCE_B_STATUS" "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'direct_validation_ack_received')
  A_VALIDATION_PROMOTED=$(count_stage "$EVIDENCE_A_STATUS" "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'direct_validation_promoted')
  B_VALIDATION_PROMOTED=$(count_stage "$EVIDENCE_B_STATUS" "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'direct_validation_promoted')
  A_PATH_PROMOTIONS=$(count_log_events_for_peer "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'event=\\"direct_path_promoted\\"|direct_path_promoted')
  B_PATH_PROMOTIONS=$(count_log_events_for_peer "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'event=\\"direct_path_promoted\\"|direct_path_promoted')
  A_NON_TARGET_TRAVERSAL=$(count_non_target_traversal_activity "$ROUND_DIR/node-a.log" "$AIR_NODE_ID")
  B_NON_TARGET_TRAVERSAL=$(count_non_target_traversal_activity "$ROUND_DIR/node-b.log" "$MINI_NODE_ID")
  A_NON_TARGET_OFFERS=$(count_non_target_peer_events "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'offer')
  B_NON_TARGET_OFFERS=$(count_non_target_peer_events "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'offer')
  A_NON_TARGET_PROBES=$(count_non_target_peer_events "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'probe|punch')
  B_NON_TARGET_PROBES=$(count_non_target_peer_events "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'probe|punch')
  A_NON_TARGET_VALIDATIONS=$(count_non_target_peer_events "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'direct_validation|encrypted_trial')
  B_NON_TARGET_VALIDATIONS=$(count_non_target_peer_events "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'direct_validation|encrypted_trial')
  if [[ "$ACCEPTANCE_MODE" == "strict" ]]; then
    A_STRICT_VALIDATION=0
    B_STRICT_VALIDATION=0
    if [[ "$direct_ok" -eq 1 && -f "$ROUND_DIR/strict-success-result.json" ]]; then
      strict_validation_session "$EVIDENCE_A_STATUS" "$AIR_NODE_ID" >"$ROUND_DIR/node-a.strict.json" && A_STRICT_VALIDATION=1 || true
      strict_validation_session "$EVIDENCE_B_STATUS" "$MINI_NODE_ID" >"$ROUND_DIR/node-b.strict.json" && B_STRICT_VALIDATION=1 || true
    else
      printf '{"ok":false,"reason":"no_strict_success_snapshot"}\n' >"$ROUND_DIR/node-a.strict.json"
      printf '{"ok":false,"reason":"no_strict_success_snapshot"}\n' >"$ROUND_DIR/node-b.strict.json"
    fi
  else
    python3 - "$EVIDENCE_A_STATUS" "$AIR_NODE_ID" "$EVIDENCE_B_STATUS" "$MINI_NODE_ID" <<'PY' >"$ROUND_DIR/round-audit.json"
import json
import os
import sys

def endpoint_of(status_path, peer_id):
    with open(status_path, encoding="utf-8") as stream:
        status = json.load(stream)
    for peer in status.get("peers", []) or []:
        if not isinstance(peer, dict):
            continue
        if peer.get("node_id") != peer_id:
            continue
        pair = peer.get("selected_pair") or peer.get("current_direct_pair") or {}
        if isinstance(pair, dict):
            return pair.get("remote_endpoint") or ""
        return ""
    return ""

mode = os.environ.get("ACCEPTANCE_MODE", "unknown")
classification = {
    "availability": "relay_first_availability",
    "compat": "functional_direct_baseline",
}.get(mode, "unclassified")

print(json.dumps({
    "acceptance_mode": mode,
    "classification": classification,
    "mini_peer_id": sys.argv[2],
    "air_peer_id": sys.argv[4],
    "mini_endpoint": endpoint_of(sys.argv[1], sys.argv[2]),
    "air_endpoint": endpoint_of(sys.argv[3], sys.argv[4]),
}, indent=2, sort_keys=True))
PY
  fi
  A_EP=$(status_endpoint_from_json "$EVIDENCE_A_STATUS" "$AIR_NODE_ID" 2>/dev/null || true)
  B_EP=$(status_endpoint_from_json "$EVIDENCE_B_STATUS" "$MINI_NODE_ID" 2>/dev/null || true)
  SNAPSHOT_POLL_INDEX="$POLL_INDEX"
  SNAPSHOT_A_SHA256=$(sha256_file "$EVIDENCE_A_STATUS")
  SNAPSHOT_B_SHA256=$(sha256_file "$EVIDENCE_B_STATUS")
  SNAPSHOT_RESULT_SHA256=$(sha256_file "$EVIDENCE_RESULT")
  if [[ "$ACCEPTANCE_MODE" == "strict" ]]; then
    python3 - "$EVIDENCE_RESULT" "$ROUND_DIR/strict-validation-final.json" "$SNAPSHOT_ID" "$SNAPSHOT_POLL_INDEX" "$SNAPSHOT_A_SHA256" "$SNAPSHOT_B_SHA256" "$SNAPSHOT_RESULT_SHA256" <<'PY'
import json
import os
import sys

source, destination, snapshot_id, poll_index, mini_sha, air_sha, result_sha = sys.argv[1:]
with open(source, encoding="utf-8") as stream:
    value = json.load(stream)
value["snapshot_id"] = snapshot_id
value["poll_index"] = int(poll_index)
value["snapshot_sha256"] = {
    "mini": mini_sha,
    "air": air_sha,
    "result": result_sha,
}
tmp = destination + ".tmp"
with open(tmp, "w", encoding="utf-8") as stream:
    json.dump(value, stream, indent=2, sort_keys=True)
    stream.write("\n")
os.replace(tmp, destination)
PY
  fi
  A_MATCHED_ACKS=$(count_log_events_for_peer "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'candidate_pair_probe_succeeded|received authenticated UDP punch ACK|received UDP punch ACK')
  B_MATCHED_ACKS=$(count_log_events_for_peer "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'candidate_pair_probe_succeeded|received authenticated UDP punch ACK|received UDP punch ACK')
  A_OVERLAY_ROUND_TRIPS=0
  B_OVERLAY_ROUND_TRIPS=0
  overlay_ok=1
  if [[ "$REAL_TUN" == "1" ]]; then
    A_OVERLAY_ROUND_TRIPS="$REAL_OVERLAY_MINI_REPLIES"
    B_OVERLAY_ROUND_TRIPS="$REAL_OVERLAY_AIR_REPLIES"
    overlay_ok="$REAL_OVERLAY_OK"
  elif [[ "$VALIDATE_OVERLAY" == "1" || "$ACCEPTANCE_MODE" == "availability" ]]; then
    overlay_ok=0
    for _ in $(seq 1 $((OVERLAY_TIMEOUT_S * 2))); do
      A_OVERLAY_ROUND_TRIPS=$(log_reports_overlay_round_trip "$ROUND_DIR/node-a.log" "$AIR_NODE_ID")
      if ! $AIR_SSH "cat '$REMOTE_NODE_B_LOG'" >"$ROUND_DIR/node-b.log"; then
        break
      fi
      B_OVERLAY_ROUND_TRIPS=$(log_reports_overlay_round_trip "$ROUND_DIR/node-b.log" "$MINI_NODE_ID")
      if [[ "$A_OVERLAY_ROUND_TRIPS" -gt 0 && "$B_OVERLAY_ROUND_TRIPS" -gt 0 ]]; then
        overlay_ok=1
        break
      fi
      sleep 0.5
    done
  fi
  # Availability first-usable metric: from the moment BOTH daemons have a relay
  # transport connected to the later of the two first-usable events (both sides
  # completed a bidirectional encrypted overlay loopback).
  A_FIRST_USABLE_TS=""
  B_FIRST_USABLE_TS=""
  A_RELAY_READY_TS=""
  B_RELAY_READY_TS=""
  A_FIRST_USABLE_PATH=""
  B_FIRST_USABLE_PATH=""
  FIRST_USABLE_AFTER_RELAY_MS=""
  A_PRODUCTION_REASON=""
  B_PRODUCTION_REASON=""
  if [[ "$ACCEPTANCE_MODE" == "availability" ]]; then
    # REAL_TUN uses the production `first_real_business_ingress` milestone:
    # it is emitted only after a normal decrypted packet arrives from the
    # target peer.  The mock validator's nonce/echo milestone is retained for
    # non-production local runs only.  Each side computes its own monotonic
    # relay-transport-ready -> business-ingress delta; the harness takes
    # max(side A, side B) and never subtracts cross-machine wall clocks.  The
    # receiver may see the peer's real relay business packet before consuming
    # its own locally initiated probe ACK; that is valid ingress evidence, not
    # a Direct bypass.  `relay_peer_confirmed` remains a separate admission
    # gate below.
    if [[ "$REAL_TUN" == "1" ]]; then
      A_PRODUCTION_INFO=$(production_first_business_info "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" || true)
      B_PRODUCTION_INFO=$(production_first_business_info "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" || true)
      A_FIRST_USABLE_PATH=$(printf '%s' "$A_PRODUCTION_INFO" | cut -d'|' -f1)
      B_FIRST_USABLE_PATH=$(printf '%s' "$B_PRODUCTION_INFO" | cut -d'|' -f1)
      A_RELAY_READY_TO_USABLE_MS=$(printf '%s' "$A_PRODUCTION_INFO" | cut -d'|' -f2)
      B_RELAY_READY_TO_USABLE_MS=$(printf '%s' "$B_PRODUCTION_INFO" | cut -d'|' -f2)
      A_PRODUCTION_REASON=$(printf '%s' "$A_PRODUCTION_INFO" | cut -d'|' -f4)
      B_PRODUCTION_REASON=$(printf '%s' "$B_PRODUCTION_INFO" | cut -d'|' -f4)
    else
      A_FIRST_USABLE_PATH=$(log_first_event_path "$ROUND_DIR/node-a.log" 'first_usable_bidirectional_overlay_ms')
      B_FIRST_USABLE_PATH=$(log_first_event_path "$ROUND_DIR/node-b.log" 'first_usable_bidirectional_overlay_ms')
      A_RELAY_READY_TO_USABLE_MS=$(log_first_event_field "$ROUND_DIR/node-a.log" 'first_usable_confirmed' 'relay_ready_to_usable_ms')
      B_RELAY_READY_TO_USABLE_MS=$(log_first_event_field "$ROUND_DIR/node-b.log" 'first_usable_confirmed' 'relay_ready_to_usable_ms')
    fi
    if [[ "$A_RELAY_READY_TO_USABLE_MS" =~ ^[0-9]+$ &&
          "$B_RELAY_READY_TO_USABLE_MS" =~ ^[0-9]+$ ]]; then
      FIRST_USABLE_AFTER_RELAY_MS=$((A_RELAY_READY_TO_USABLE_MS > B_RELAY_READY_TO_USABLE_MS ? A_RELAY_READY_TO_USABLE_MS : B_RELAY_READY_TO_USABLE_MS))
    else
      FIRST_USABLE_AFTER_RELAY_MS=""
    fi
    # The first-usable evidence must be for the TARGET peer (the other node),
    # not a stale/third-party peer.  first_usable_confirmed already required a
    # locally-sent matching nonce echo; this additionally pins the peer.
    A_TARGET_PEER_OK=0
    B_TARGET_PEER_OK=0
    if [[ -n "$AIR_NODE_ID" ]]; then
      if [[ "$REAL_TUN" == "1" ]]; then
      A_TARGET_PEER_OK=$(grep 'event="first_real_business_ingress"' "$ROUND_DIR/node-a.log" 2>/dev/null | grep -F -m1 -- "$AIR_NODE_ID" | wc -l | tr -d ' ' || true)
      else
        A_TARGET_PEER_OK=$(grep -m1 'event="first_usable_confirmed"' "$ROUND_DIR/node-a.log" 2>/dev/null | grep -c "$AIR_NODE_ID" || true)
      fi
    fi
    if [[ -n "$MINI_NODE_ID" ]]; then
      if [[ "$REAL_TUN" == "1" ]]; then
      B_TARGET_PEER_OK=$(grep 'event="first_real_business_ingress"' "$ROUND_DIR/node-b.log" 2>/dev/null | grep -F -m1 -- "$MINI_NODE_ID" | wc -l | tr -d ' ' || true)
      else
        B_TARGET_PEER_OK=$(grep -m1 'event="first_usable_confirmed"' "$ROUND_DIR/node-b.log" 2>/dev/null | grep -c "$MINI_NODE_ID" || true)
      fi
    fi
  fi
  A_HTTP_429=$(count_log_events "$ROUND_DIR/node-a.log" 'HTTP 429|status.?429|429 Too Many')
  B_HTTP_429=$(count_log_events "$ROUND_DIR/node-b.log" 'HTTP 429|status.?429|429 Too Many')
  A_RELAY_HEDGES=$(count_log_events "$ROUND_DIR/node-a.log" 'relay_hedged=true')
  B_RELAY_HEDGES=$(count_log_events "$ROUND_DIR/node-b.log" 'relay_hedged=true')
  A_RELAY_FALLBACKS=$(count_log_events "$ROUND_DIR/node-a.log" 'relay_fallback_selected')
  B_RELAY_FALLBACKS=$(count_log_events "$ROUND_DIR/node-b.log" 'relay_fallback_selected')
  A_RELAY_SELECTIONS=$(count_log_events_insensitive "$ROUND_DIR/node-a.log" 'selected relay region')
  B_RELAY_SELECTIONS=$(count_log_events_insensitive "$ROUND_DIR/node-b.log" 'selected relay region')
  A_CRASH_PANIC=$(count_log_events_insensitive "$ROUND_DIR/node-a.log" 'panic|fatal runtime error|thread .* panicked')
  B_CRASH_PANIC=$(count_log_events_insensitive "$ROUND_DIR/node-b.log" 'panic|fatal runtime error|thread .* panicked')
  if [[ "$ACCEPTANCE_MODE" == "compat" ]]; then
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$round" "$ACCEPTANCE_MODE" "$FUNCTIONAL_DIRECT_MS" "$ELAPSED_MS" "$A_EP" "$B_EP" "$A_CRASH_PANIC" "$B_CRASH_PANIC" \
      >>"$BASE_DIR/round-metrics.tsv"
    {
      echo "round=$round acceptance_mode=compat classification=functional_direct_baseline functional_direct_ms=$FUNCTIONAL_DIRECT_MS elapsed_ms=$ELAPSED_MS"
      echo "network_id=$NETWORK_ID"
      echo "mini_node_id=$MINI_NODE_ID air_node_id=$AIR_NODE_ID"
      echo "a_endpoint=$A_EP b_endpoint=$B_EP"
      echo "a_crash_panic=$A_CRASH_PANIC b_crash_panic=$B_CRASH_PANIC"
      echo "isolation_prove=$ROUND_DIR/isolation-prove.json isolation_delete=$ROUND_DIR/isolation-delete.json isolation_cleaned=$ROUND_DIR/isolation-cleaned.json"
      echo "round_audit=$ROUND_DIR/round-audit.json"
      echo "snapshot_id=$SNAPSHOT_ID snapshot_poll_index=$SNAPSHOT_POLL_INDEX"
      echo "snapshot_a_sha256=$SNAPSHOT_A_SHA256 snapshot_b_sha256=$SNAPSHOT_B_SHA256 snapshot_result_sha256=$SNAPSHOT_RESULT_SHA256"
    } >"$ROUND_DIR/metrics.env"
  elif [[ "$ACCEPTANCE_MODE" == "availability" ]]; then
    A_RELAY_PEER_CONFIRMED=$(count_log_events_for_peer "$ROUND_DIR/node-a.log" "$AIR_NODE_ID" 'event="relay_peer_confirmed"|relay_peer_confirmed')
    B_RELAY_PEER_CONFIRMED=$(count_log_events_for_peer "$ROUND_DIR/node-b.log" "$MINI_NODE_ID" 'event="relay_peer_confirmed"|relay_peer_confirmed')
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$round" "$ACCEPTANCE_MODE" "$FIRST_USABLE_AFTER_RELAY_MS" "$ELAPSED_MS" \
      "$A_FIRST_USABLE_PATH" "$B_FIRST_USABLE_PATH" "$A_DIRECT" "$B_DIRECT" \
      "$A_RELAY_SELECTIONS" "$B_RELAY_SELECTIONS" \
      "$A_OVERLAY_ROUND_TRIPS" "$B_OVERLAY_ROUND_TRIPS" \
      "$A_RELAY_PEER_CONFIRMED" "$B_RELAY_PEER_CONFIRMED" \
      "$A_CRASH_PANIC" "$B_CRASH_PANIC" >>"$BASE_DIR/round-metrics.tsv"
    {
      echo "round=$round acceptance_mode=availability first_usable_after_relay_ms=$FIRST_USABLE_AFTER_RELAY_MS elapsed_ms=$ELAPSED_MS"
      echo "first_usable_path_a=$A_FIRST_USABLE_PATH first_usable_path_b=$B_FIRST_USABLE_PATH"
      echo "production_reason_a=${A_PRODUCTION_REASON:-not_applicable} production_reason_b=${B_PRODUCTION_REASON:-not_applicable}"
      echo "network_id=$NETWORK_ID"
      echo "mini_node_id=$MINI_NODE_ID air_node_id=$AIR_NODE_ID"
      echo "a_direct=$A_DIRECT b_direct=$B_DIRECT (informational; direct is not a usability gate)"
      echo "a_relay_selections=$A_RELAY_SELECTIONS b_relay_selections=$B_RELAY_SELECTIONS"
      echo "a_relay_peer_confirmed=$A_RELAY_PEER_CONFIRMED b_relay_peer_confirmed=$B_RELAY_PEER_CONFIRMED"
      echo "a_overlay_round_trips=$A_OVERLAY_ROUND_TRIPS b_overlay_round_trips=$B_OVERLAY_ROUND_TRIPS"
      echo "a_crash_panic=$A_CRASH_PANIC b_crash_panic=$B_CRASH_PANIC"
      echo "timeline_a=$ROUND_DIR/node-a.log timeline_b=$ROUND_DIR/node-b.log"
      echo "status_a=$ROUND_DIR/node-a.status.json status_b=$ROUND_DIR/node-b.status.json"
      echo "isolation_prove=$ROUND_DIR/isolation-prove.json isolation_delete=$ROUND_DIR/isolation-delete.json isolation_cleaned=$ROUND_DIR/isolation-cleaned.json"
      echo "round_audit=$ROUND_DIR/round-audit.json"
    } >"$ROUND_DIR/metrics.env"
  else
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$round" "$ACCEPTANCE_MODE" "$FUNCTIONAL_DIRECT_MS" "$STRICT_CONVERGENCE_MS" "$ELAPSED_MS" "$A_DIRECT" "$B_DIRECT" "$A_EP" "$B_EP" \
      "$A_VALIDATION_SESSIONS" "$B_VALIDATION_SESSIONS" \
      "$A_VALIDATION_REQUESTS" "$B_VALIDATION_REQUESTS" \
      "$A_VALIDATION_ACKS" "$B_VALIDATION_ACKS" \
      "$A_VALIDATION_PROMOTED" "$B_VALIDATION_PROMOTED" \
      "$A_STRICT_VALIDATION" "$B_STRICT_VALIDATION" \
      "$A_MATCHED_ACKS" "$B_MATCHED_ACKS" "$A_OVERLAY_ROUND_TRIPS" "$B_OVERLAY_ROUND_TRIPS" "$A_HTTP_429" "$B_HTTP_429" \
      "$A_RELAY_HEDGES" "$B_RELAY_HEDGES" \
      "$A_RELAY_FALLBACKS" "$B_RELAY_FALLBACKS" \
      "$A_RELAY_SELECTIONS" "$B_RELAY_SELECTIONS" "$A_CRASH_PANIC" "$B_CRASH_PANIC" \
      "$A_POST_DIRECT_TRAVERSAL" "$B_POST_DIRECT_TRAVERSAL" \
      "$A_NON_TARGET_TRAVERSAL" "$B_NON_TARGET_TRAVERSAL" >>"$BASE_DIR/round-metrics.tsv"
    {
      echo "round=$round acceptance_mode=strict strict_convergence_ms=$STRICT_CONVERGENCE_MS elapsed_ms=$ELAPSED_MS"
    echo "network_id=$NETWORK_ID"
    echo "mini_node_id=$MINI_NODE_ID air_node_id=$AIR_NODE_ID"
    echo "a_endpoint=$A_EP b_endpoint=$B_EP"
    echo "a_validation_sessions=$A_VALIDATION_SESSIONS b_validation_sessions=$B_VALIDATION_SESSIONS"
    echo "a_validation_requests=$A_VALIDATION_REQUESTS b_validation_requests=$B_VALIDATION_REQUESTS"
    echo "a_validation_acks=$A_VALIDATION_ACKS b_validation_acks=$B_VALIDATION_ACKS"
    echo "a_validation_promoted=$A_VALIDATION_PROMOTED b_validation_promoted=$B_VALIDATION_PROMOTED"
    echo "a_strict_validation=$A_STRICT_VALIDATION b_strict_validation=$B_STRICT_VALIDATION"
    echo "a_matched_acks=$A_MATCHED_ACKS b_matched_acks=$B_MATCHED_ACKS"
    echo "a_overlay_round_trips=$A_OVERLAY_ROUND_TRIPS b_overlay_round_trips=$B_OVERLAY_ROUND_TRIPS"
    echo "a_http_429=$A_HTTP_429 b_http_429=$B_HTTP_429"
    echo "a_relay_hedges=$A_RELAY_HEDGES b_relay_hedges=$B_RELAY_HEDGES"
    echo "a_relay_fallbacks=$A_RELAY_FALLBACKS b_relay_fallbacks=$B_RELAY_FALLBACKS"
    echo "a_relay_selections=$A_RELAY_SELECTIONS b_relay_selections=$B_RELAY_SELECTIONS"
    echo "a_crash_panic=$A_CRASH_PANIC b_crash_panic=$B_CRASH_PANIC"
    echo "a_post_direct_traversal=$A_POST_DIRECT_TRAVERSAL b_post_direct_traversal=$B_POST_DIRECT_TRAVERSAL"
    echo "a_non_target_traversal=$A_NON_TARGET_TRAVERSAL b_non_target_traversal=$B_NON_TARGET_TRAVERSAL"
    echo "a_non_target_offers=$A_NON_TARGET_OFFERS b_non_target_offers=$B_NON_TARGET_OFFERS"
    echo "a_non_target_probes=$A_NON_TARGET_PROBES b_non_target_probes=$B_NON_TARGET_PROBES"
    echo "a_non_target_validations=$A_NON_TARGET_VALIDATIONS b_non_target_validations=$B_NON_TARGET_VALIDATIONS"
    echo "isolation_prove=$ROUND_DIR/isolation-prove.json isolation_delete=$ROUND_DIR/isolation-delete.json isolation_cleaned=$ROUND_DIR/isolation-cleaned.json"
    echo "round_audit=$ROUND_DIR/round-audit.json"
    echo "snapshot_id=$SNAPSHOT_ID snapshot_poll_index=$SNAPSHOT_POLL_INDEX"
    echo "snapshot_a_sha256=$SNAPSHOT_A_SHA256 snapshot_b_sha256=$SNAPSHOT_B_SHA256 snapshot_result_sha256=$SNAPSHOT_RESULT_SHA256"
    } >"$ROUND_DIR/metrics.env"
  fi

  # Record evidence.
  {
    echo "== Mini public IPv4 =="
    curl -s4 --max-time 8 ifconfig.me || true
    echo
    echo "== Air public IPv4 =="
    $AIR_SSH 'curl --noproxy "*" -s --max-time 8 ifconfig.me || true'
    echo
    echo "== A: STUN order / profile =="
    grep -h 'Local NAT profile\|fresh_mapping_observer' "$ROUND_DIR/node-a.log" | head -8
    echo "== B: STUN order / profile =="
    grep -h 'Local NAT profile\|fresh_mapping_observer' "$ROUND_DIR/node-b.log" | head -8
    echo "== A: fresh model + prediction =="
    grep -h 'fresh_mapping_model\|fresh_mapping_prediction_signaled' "$ROUND_DIR/node-a.log" | head -3
    echo "== B: fresh model + prediction =="
    grep -h 'fresh_mapping_model\|fresh_mapping_prediction_signaled' "$ROUND_DIR/node-b.log" | head -3
    echo "== A: matched ACKs / peer-reflexive / validation =="
    grep -F -- "$AIR_NODE_ID" "$ROUND_DIR/node-a.log" | grep -E 'candidate_pair_probe_succeeded|direct_validation|peer_reflexive' | grep -v Aborting | head -6
    echo "== B: matched ACKs / peer-reflexive / validation =="
    grep -F -- "$MINI_NODE_ID" "$ROUND_DIR/node-b.log" | grep -E 'candidate_pair_probe_succeeded|direct_validation|peer_reflexive' | grep -v Aborting | head -6
    echo "== A promotion =="
    grep -F -- "$AIR_NODE_ID" "$ROUND_DIR/node-a.log" | grep -E 'direct_path_promoted|candidate_pair_selected' | head -2
    echo "== B promotion =="
    grep -F -- "$MINI_NODE_ID" "$ROUND_DIR/node-b.log" | grep -E 'direct_path_promoted|candidate_pair_selected' | head -2
    if [[ "$VALIDATE_OVERLAY" == "1" || "$ACCEPTANCE_MODE" == "availability" ]]; then
      echo "== A encrypted overlay payload =="
      grep -F -- "$AIR_NODE_ID" "$ROUND_DIR/node-a.log" | grep 'overlay_payload_verified' | head -2
      echo "== B encrypted overlay payload =="
      grep -F -- "$MINI_NODE_ID" "$ROUND_DIR/node-b.log" | grep 'overlay_payload_verified' | head -2
    fi
    if [[ "$REAL_TUN" == "1" ]]; then
      echo "== real TUN overlay ping Mini -> Air =="
      cat "$ROUND_DIR/overlay-ping-mini-to-air.log" 2>/dev/null || true
      echo "== real TUN overlay ping Air -> Mini =="
      cat "$ROUND_DIR/overlay-ping-air-to-mini.log" 2>/dev/null || true
      echo "== real TUN overlay summary =="
      cat "$ROUND_DIR/real-overlay-summary.env" 2>/dev/null || true
    fi
    echo "== per-round metrics =="
    cat "$ROUND_DIR/metrics.env"
    echo "== A relay hedge/fallback/selection =="
    grep -h -i -E 'relay_hedged=true|relay_fallback_selected|selected relay region' "$ROUND_DIR/node-a.log" | head -4
    echo "== B relay hedge/fallback/selection =="
    grep -h -i -E 'relay_hedged=true|relay_fallback_selected|selected relay region' "$ROUND_DIR/node-b.log" | head -4
    echo "== relay proof boundaries (queue -> write -> encrypted peer ACK) =="
    grep -h -E 'relay_writer_queue_accepted|relay_writer_queue_rejected|relay_writer_completion_received|relay_writer_completion_missing|relay_write_started|relay_write_completed|relay_write_failed|relay_probe_sent|relay_probe_send_failed|relay_probe_send_timeout|relay_probe_ack_consumed|relay_peer_confirmed|relay_probe_ack_stale' \
      "$ROUND_DIR"/node-*.log | head -40
    echo "== Direct validation lifecycle (request -> ACK/timeout/cancel) =="
    grep -h -E 'direct_validation_(queued|started|waiting_for_session|session_ready|request_sent|request_received|request_dropped|ack_sent|ack_received|ack_wait_timeout|ack_unmatched|ack_not_promoted|ack_send_failed|emit_lock_timeout|timed_out|failed|cancelled|completed|promoted|suppressed)|direct_path_promoted' \
      "$ROUND_DIR"/node-*.log | head -120
    echo "== Direct traversal plan lifecycle (candidate -> fast probe -> retry) =="
    grep -h -E 'direct_punch_(started|completed|failed|cancelled)|direct_fast_probe_(started|sent|failed|confirmed)|direct_probe_(ack_timeout|budget_exhausted)|direct_candidates_ready|candidate_pair_probe_succeeded|retry_(punch_started|probes_sent|ack_timeout|probe_succeeded|send_error)|direct_reclaim_(punch_started|probes_sent|ack_timeout|probe_succeeded|send_error)|fresh_mapping_(generation_started|generation_completed|generation_failed|prediction_signaled)' \
      "$ROUND_DIR"/node-*.log | head -160
    echo "== path selector state snapshots =="
    grep -h -E 'path_state_snapshot|outbound_path_decision' \
      "$ROUND_DIR"/node-*.log | head -40
    echo "== first real business ingress vs first usable =="
    grep -h -E 'first_real_business_ingress|first_usable_(path|rejected|fallback)|relay_first_business_(sent|received|exchange)' \
      "$ROUND_DIR"/node-*.log | head -40
    echo "== queue/loss/generation terminal evidence =="
    grep -h -E 'outbound_packet_dropped|outbound_send_failure|relay_unavailable_or_first_packet_expired|stale_network_generation_packet|stale_session_evidence|generation_cancel' \
      "$ROUND_DIR"/node-*.log | head -40
    echo "== per-packet dataplane boundaries (counter -> handoff -> peer decrypt) =="
    grep -h -E 'wireguard_outbound_counter_allocated|outbound_business_emit_lock_acquired|outbound_counter_allocation_rejected|outbound_transport_handoff_started|control_transport_handoff_started|control_transport_handoff_completed|relay_data_send_started|relay_data_write_started|relay_data_write_completed|relay_data_send_failed|relay_outbound_write_started|relay_outbound_write_completed|relay_outbound_write_failed|relay_inbound_frame_accepted|direct_data_send_started|direct_data_handoff_accepted|direct_data_send_failed|wireguard_inbound_decrypt_succeeded|hedge_duplicate_replay|outbound_send_timeout|outbound_terminal_drop' \
      "$ROUND_DIR"/node-*.log | head -160
    if [[ "$ACCEPTANCE_MODE" == "availability" ]]; then
      echo "== A first-usable timeline (all timepoints with corr_id + t_ms + path) =="
      grep -E 'daemon_started|control_registered|relay_selection_started|relay_transport_connected|relay_peer_confirmed|first_direct_probe_sent|direct_promoted|first_usable_path|first_usable_bidirectional_overlay_ms|first_real_business_ingress|relay_unavailable_or_first_packet_expired' "$ROUND_DIR/node-a.log" | head -14
      echo "== B first-usable timeline =="
      grep -E 'daemon_started|control_registered|relay_selection_started|relay_transport_connected|relay_peer_confirmed|first_direct_probe_sent|direct_promoted|first_usable_path|first_usable_bidirectional_overlay_ms|first_real_business_ingress|relay_unavailable_or_first_packet_expired' "$ROUND_DIR/node-b.log" | head -14
      echo "== direct results (informational only, not a usability gate) =="
      echo "a_direct=$A_DIRECT b_direct=$B_DIRECT a_first_usable_path=$A_FIRST_USABLE_PATH b_first_usable_path=$B_FIRST_USABLE_PATH"
      grep -h 'direct_path_promoted\|first_direct_probe_sent' "$ROUND_DIR/node-a.log" | head -2
      grep -h 'direct_path_promoted\|first_direct_probe_sent' "$ROUND_DIR/node-b.log" | head -2
      echo "== relay selection result =="
      grep -h 'relay_selection_started\|relay_transport_connected\|relay_peer_confirmed\|selected relay region' "$ROUND_DIR/node-a.log" | head -4
      grep -h 'relay_selection_started\|relay_transport_connected\|relay_peer_confirmed\|selected relay region' "$ROUND_DIR/node-b.log" | head -4
    fi
    if [[ "$ACCEPTANCE_MODE" == "strict" || "$ISOLATION_MODE" == "target-scoped-shared" ]]; then
      echo "== network isolation proof =="
      cat "$ROUND_DIR/isolation-prove.json" 2>/dev/null || echo "isolation-prove.json missing"
      echo "== device cleanup proof =="
      cat "$ROUND_DIR/isolation-delete.json" 2>/dev/null || echo "isolation-delete.json missing"
      cat "$ROUND_DIR/isolation-cleaned.json" 2>/dev/null || echo "isolation-cleaned.json missing"
    fi
  } >"$ROUND_DIR/evidence.log" 2>&1 || true

  MINI_ALIVE=1
  AIR_ALIVE=1
  if ! local_daemon_is_alive; then
    MINI_ALIVE=0
    echo "[mini-air] ROUND $round: FAIL (Mini daemon exited unexpectedly)"
  fi
  if ! remote_daemon_matches; then
    AIR_ALIVE=0
    echo "[mini-air] ROUND $round: FAIL (Air daemon exited unexpectedly)"
  fi

  round_ok=0
  if [[ "$ACCEPTANCE_MODE" == "compat" ]] && \
     [[ "$INFRASTRUCTURE_INVALID" -eq 0 ]] && \
     [[ "$direct_ok" -eq 1 ]] && [[ "$STATUS_CAPTURE_OK" -eq 1 ]] && \
     [[ "$A_CRASH_PANIC" -eq 0 ]] && [[ "$B_CRASH_PANIC" -eq 0 ]] && \
     is_public_ipv4_endpoint "$A_EP" && is_public_ipv4_endpoint "$B_EP" && \
     [[ -n "$FUNCTIONAL_DIRECT_MS" ]] && \
     [[ "$MINI_ALIVE" -eq 1 ]] && [[ "$AIR_ALIVE" -eq 1 ]]; then
    round_ok=1
  elif [[ "$ACCEPTANCE_MODE" == "strict" ]] && \
     [[ "$INFRASTRUCTURE_INVALID" -eq 0 ]] && \
     [[ "$direct_ok" -eq 1 ]] && [[ "$STATUS_CAPTURE_OK" -eq 1 ]] && \
     [[ "$A_STRICT_VALIDATION" -eq 1 ]] && [[ "$B_STRICT_VALIDATION" -eq 1 ]] && \
     [[ "$A_VALIDATION_PROMOTED" -gt 0 ]] && [[ "$B_VALIDATION_PROMOTED" -gt 0 ]] && \
     [[ "$A_PATH_PROMOTIONS" -gt 0 ]] && [[ "$B_PATH_PROMOTIONS" -gt 0 ]] && \
     [[ "$A_CRASH_PANIC" -eq 0 ]] && [[ "$B_CRASH_PANIC" -eq 0 ]] && \
     [[ "$A_HTTP_429" -eq 0 ]] && [[ "$B_HTTP_429" -eq 0 ]] && \
     [[ "$A_POST_DIRECT_TRAVERSAL" -eq 0 ]] && [[ "$B_POST_DIRECT_TRAVERSAL" -eq 0 ]] && \
     [[ "$A_NON_TARGET_TRAVERSAL" -eq 0 ]] && [[ "$B_NON_TARGET_TRAVERSAL" -eq 0 ]] && \
     [[ "$overlay_ok" -eq 1 ]] && is_public_ipv4_endpoint "$A_EP" && \
     is_public_ipv4_endpoint "$B_EP" && [[ "$STRICT_CONVERGENCE_MS" -le "$DIRECT_SUCCESS_TARGET_MS" ]] && \
     [[ "$MINI_ALIVE" -eq 1 ]] && [[ "$AIR_ALIVE" -eq 1 ]]; then
    round_ok=1
  elif [[ "$ACCEPTANCE_MODE" == "availability" ]] && \
     [[ "$INFRASTRUCTURE_INVALID" -eq 0 ]] && \
     [[ "$overlay_ok" -eq 1 ]] && [[ "$STATUS_CAPTURE_OK" -eq 1 ]] && \
     [[ "$A_CRASH_PANIC" -eq 0 ]] && [[ "$B_CRASH_PANIC" -eq 0 ]] && \
     [[ "$A_RELAY_PEER_CONFIRMED" -ge 1 ]] && [[ "$B_RELAY_PEER_CONFIRMED" -ge 1 ]] && \
     [[ "$A_FIRST_USABLE_PATH" == "relay" ]] && [[ "$B_FIRST_USABLE_PATH" == "relay" ]] && \
     [[ "$A_TARGET_PEER_OK" -ge 1 ]] && [[ "$B_TARGET_PEER_OK" -ge 1 ]] && \
     [[ -n "$FIRST_USABLE_AFTER_RELAY_MS" ]] && \
     [[ "$FIRST_USABLE_AFTER_RELAY_MS" -ge 0 ]] && \
     [[ "$FIRST_USABLE_AFTER_RELAY_MS" -le "$AVAILABILITY_FIRST_USABLE_TARGET_MS" ]] && \
     [[ "$MINI_ALIVE" -eq 1 ]] && [[ "$AIR_ALIVE" -eq 1 ]]; then
    round_ok=1
  fi
  record_sequence_round "$round" "$round_ok" "$FUNCTIONAL_DIRECT_MS" "$STRICT_CONVERGENCE_MS"
  if [[ "$round_ok" -eq 1 ]]; then
    if [[ "$ACCEPTANCE_MODE" == "compat" ]]; then
      echo "[mini-air] ROUND $round: FUNCTIONAL-DIRECT baseline functional_direct_ms=$FUNCTIONAL_DIRECT_MS a_ep=$A_EP b_ep=$B_EP evidence=$ROUND_DIR/evidence.log"
    elif [[ "$ACCEPTANCE_MODE" == "availability" ]]; then
      echo "[mini-air] ROUND $round: PASS availability first_usable_after_relay_ms=$FIRST_USABLE_AFTER_RELAY_MS a_path=$A_FIRST_USABLE_PATH b_path=$B_FIRST_USABLE_PATH a_direct=$A_DIRECT b_direct=$B_DIRECT evidence=$ROUND_DIR/evidence.log"
    else
      echo "[mini-air] ROUND $round: PASS strict_convergence_ms=$STRICT_CONVERGENCE_MS a_ep=$A_EP b_ep=$B_EP evidence=$ROUND_DIR/evidence.log"
    fi
  else
    if [[ "$ACCEPTANCE_MODE" == "compat" ]]; then
      echo "[mini-air] ROUND $round: FUNCTIONAL-DIRECT baseline incomplete a_direct=$A_DIRECT b_direct=$B_DIRECT elapsed_ms=$ELAPSED_MS a_ep=$A_EP b_ep=$B_EP evidence=$ROUND_DIR/evidence.log"
    elif [[ "$ACCEPTANCE_MODE" == "availability" ]]; then
      echo "[mini-air] ROUND $round: NO-FIRST-USABLE overlay_ok=$overlay_ok first_usable_after_relay_ms=$FIRST_USABLE_AFTER_RELAY_MS a_direct=$A_DIRECT b_direct=$B_DIRECT elapsed_ms=$ELAPSED_MS evidence=$ROUND_DIR/evidence.log"
    else
      echo "[mini-air] ROUND $round: NO-DIRECT-or-nonpublic-path a_direct=$A_DIRECT b_direct=$B_DIRECT elapsed_ms=$ELAPSED_MS a_ep=$A_EP b_ep=$B_EP evidence=$ROUND_DIR/evidence.log"
    fi
    overall=1
    # Strict acceptance gets a full evidence window for later regression
    # gates. Compatibility has no lifecycle gate, so its timeout is enough.
    if [[ "$ACCEPTANCE_MODE" == "strict" || "$ACCEPTANCE_MODE" == "availability" ]]; then
      FAILURE_CAPTURE_DEADLINE_MS=$((START_MS + 45000))
      while :; do
        NOW_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
        [[ "$NOW_MS" -ge "$FAILURE_CAPTURE_DEADLINE_MS" ]] && break
        sleep 0.5
      done
    fi
    if capture_status_pair; then
      cp "$CURRENT_A_POLL" "$ROUND_DIR/teardown-node-a.json"
      cp "$CURRENT_B_POLL" "$ROUND_DIR/teardown-node-b.json"
      cp "$CURRENT_RESULT" "$ROUND_DIR/teardown-strict-result.json"
    else
      printf '{}\n' >"$ROUND_DIR/teardown-node-a.json"
      printf '{}\n' >"$ROUND_DIR/teardown-node-b.json"
      printf '{"ok":false,"reason":"status_capture_failed"}\n' >"$ROUND_DIR/teardown-strict-result.json"
    fi
    collect_air_log || true
  fi

  if [[ "$REAL_TUN" == "1" ]]; then
    capture_route_snapshot "$ROUND_DIR" post-traffic "$MINI_VIRTUAL_IP" "$AIR_VIRTUAL_IP"
  fi

  # Teardown. NODE_B_PID is the local ssh pid; the remote daemon is signalled
  # only through this round's verified PID file.
  remote_daemon_cleanup || true
  kill_remote_wrapper
  local_daemon_cleanup || true
  redact_local_config || true

  # Delete this round's devices and prove cleanup before the next round. The
  # same helper is also used by every early-failure path above, so a daemon
  # startup/diagnostics failure cannot leak a registered device into a later
  # result.
  if ! delete_round_devices "$ROUND_DIR"; then
    exit 1
  fi
  sleep 0.5
done

echo "[mini-air] base dir: $BASE_DIR"
echo "[mini-air] round metrics: $BASE_DIR/round-metrics.tsv"
echo "[mini-air] RESULT: $([ "$overall" -eq 0 ] && echo PASS || echo FAIL)"
exit $overall
