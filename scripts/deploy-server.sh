#!/usr/bin/env bash
set -euo pipefail

# Deploy a released server bundle to a Linux host.  This script deliberately
# leaves password handling to OpenSSH and sudo: passwords never appear in
# arguments, environment variables, logs, or GitHub artifacts.

REPO=${P2WLAN_REPO:-yhan-sun/p2wlan}
MODE=upload
VERSION=
ARCHIVE=
ARCH=auto
HOST=
REMOTE_USER=
PORT=22
IDENTITY=
ROLE=all
START=0
NON_INTERACTIVE=0
DRY_RUN=0
REMOTE_ROOT=
REMOTE_CONFIG=
REMOTE_DATA=

usage() {
  cat <<'EOF'
P2WLAN server deployment helper

Usage:
  ./scripts/deploy-server.sh --host HOST --user USER --version server-vX.Y.Z [options]
  ./scripts/deploy-server.sh --host HOST --user USER --archive FILE [options]

Modes:
  upload (default)  download/verify locally, upload, verify remotely, then update
  fetch             ask an already installed p2wlan-server manager to download
                    and verify --version on the server itself

Options:
  --host HOST                 SSH host (required)
  --user USER                 SSH user (required)
  --port PORT                 SSH port (default: 22)
  --identity FILE             SSH private key; omit to let ssh prompt for a password
  --version server-vX.Y.Z     immutable server release tag
  --archive FILE              local archive; FILE.sha256 is required
  --mode upload|fetch         deployment source (default: upload)
  --arch amd64|arm64|auto     archive architecture for --version (default: auto)
  --role control|relay|all    services to verify/start (default: all)
  --start                     enable/start services and run the full health check
  --non-interactive           fail instead of prompting for SSH/sudo passwords
  --repo OWNER/REPO           GitHub repository (default: yhan-sun/p2wlan)
  --remote-root DIR           remote P2WLAN_SERVER_ROOT (non-default installs)
  --remote-config DIR         remote P2WLAN_SERVER_CONFIG (non-default installs)
  --remote-data DIR            remote P2WLAN_SERVER_DATA (non-default installs)
  --dry-run                   validate arguments and print the deployment plan
  -h, --help                  show this help

Examples:
  # SSH key authentication:
  ./scripts/deploy-server.sh --host server.example.com --user deploy \
    --identity ~/.ssh/id_ed25519 --version server-v0.1.162 --start

  # Password authentication: ssh and sudo will prompt in the terminal.
  ./scripts/deploy-server.sh --host example.com --user ubuntu \
    --version server-v0.1.162 --start

  # Upload an archive downloaded from an Actions artifact:
  ./scripts/deploy-server.sh --host example.com --user ubuntu \
    --archive ./p2wlan-server-linux-amd64.tar.gz --start

  # Let an already installed server pull the release itself:
  ./scripts/deploy-server.sh --mode fetch --host example.com --user ubuntu \
    --version server-v0.1.162 --start
EOF
}

die() { echo "deploy-server: $*" >&2; exit 1; }
require_value() { [ -n "${2:-}" ] || die "$1 is required"; }

valid_word() {
  case "$1" in
    ''|*[!A-Za-z0-9._:@%+/-]*) return 1 ;;
    *) return 0 ;;
  esac
}

shell_quote() {
  local value=$1
  value=${value//\'/\'"\'"\'}
  printf "'%s'" "$value"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --host) HOST=${2:?missing host}; shift 2 ;;
    --user) REMOTE_USER=${2:?missing user}; shift 2 ;;
    --port) PORT=${2:?missing port}; shift 2 ;;
    --identity) IDENTITY=${2:?missing identity}; shift 2 ;;
    --version) VERSION=${2:?missing version}; shift 2 ;;
    --archive) ARCHIVE=${2:?missing archive}; shift 2 ;;
    --mode) MODE=${2:?missing mode}; shift 2 ;;
    --arch) ARCH=${2:?missing arch}; shift 2 ;;
    --role) ROLE=${2:?missing role}; shift 2 ;;
    --repo) REPO=${2:?missing repo}; shift 2 ;;
    --remote-root) REMOTE_ROOT=${2:?missing remote root}; shift 2 ;;
    --remote-config) REMOTE_CONFIG=${2:?missing remote config}; shift 2 ;;
    --remote-data) REMOTE_DATA=${2:?missing remote data}; shift 2 ;;
    --start) START=1; shift ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

require_value --host "$HOST"
require_value --user "$REMOTE_USER"
valid_word "$HOST" || die "host contains unsupported characters"
valid_word "$REMOTE_USER" || die "user contains unsupported characters"
case "$PORT" in ''|*[!0-9]*) die "port must be numeric" ;; esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "port must be between 1 and 65535"
case "$MODE" in upload|fetch) ;; *) die "mode must be upload or fetch" ;; esac
case "$ROLE" in control|relay|all) ;; *) die "role must be control, relay, or all" ;; esac
case "$ARCH" in auto|amd64|arm64) ;; *) die "arch must be auto, amd64, or arm64" ;; esac
case "$REPO" in */*) ;; *) die "repo must be OWNER/REPO" ;; esac
if [ -n "$VERSION" ]; then
  case "$VERSION" in server-v[A-Za-z0-9._-]*) ;; *) die "version must look like server-vX.Y.Z" ;; esac
fi
if [ "$MODE" = fetch ]; then
  [ -n "$VERSION" ] || die "--version is required in fetch mode"
  [ -z "$ARCHIVE" ] || die "--archive cannot be used in fetch mode"
else
  [ -n "$VERSION" ] || [ -n "$ARCHIVE" ] || die "upload mode requires --version or --archive"
  [ -z "$VERSION" ] || [ -z "$ARCHIVE" ] || die "choose --version or --archive, not both"
fi
if [ -n "$IDENTITY" ]; then
  [ -f "$IDENTITY" ] || die "SSH identity not found: $IDENTITY"
  identity_mode=$(stat -f '%Lp' "$IDENTITY" 2>/dev/null || stat -c '%a' "$IDENTITY")
  case "$identity_mode" in
    400|600) ;;
    *) die "SSH identity must have mode 400 or 600: $IDENTITY" ;;
  esac
fi

if [ "$MODE" = upload ] && [ -n "$ARCHIVE" ]; then
  [ -f "$ARCHIVE" ] || die "archive not found: $ARCHIVE"
  [ -f "$ARCHIVE.sha256" ] || die "missing checksum: $ARCHIVE.sha256"
  (cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "$ARCHIVE.sha256")")
fi

if [ "$DRY_RUN" -eq 1 ]; then
  if [ "$MODE" = fetch ]; then
    echo "plan: ssh $REMOTE_USER@$HOST:$PORT; server fetches $VERSION; role=$ROLE; start=$START"
  elif [ -n "$ARCHIVE" ]; then
    echo "plan: verify/upload $(basename "$ARCHIVE") to $REMOTE_USER@$HOST:$PORT; role=$ROLE; start=$START"
  else
    echo "plan: resolve remote architecture, download $VERSION from GitHub, verify/upload; role=$ROLE; start=$START"
  fi
  echo "passwords: OpenSSH/sudo interactive prompts; no password is passed as an argument"
  exit 0
fi

command -v ssh >/dev/null 2>&1 || die "ssh is required"
command -v scp >/dev/null 2>&1 || die "scp is required for upload mode"
if [ "$MODE" = upload ] && [ -z "$ARCHIVE" ]; then
  command -v curl >/dev/null 2>&1 || die "curl is required when downloading a release"
fi

local_tmp=$(mktemp -d "${TMPDIR:-/tmp}/p2wlan-deploy.XXXXXX")
remote_dir=
control_socket="$local_tmp/ssh-control"
cleanup() {
  if [ -n "${remote_dir:-}" ]; then
    ssh_exec "rm -rf -- $(shell_quote "$remote_dir")" >/dev/null 2>&1 || true
  fi
  if [ -n "${TARGET:-}" ]; then
    ssh -o "ControlPath=$control_socket" -O exit "$TARGET" >/dev/null 2>&1 || true
  fi
  rm -rf "$local_tmp"
}
trap cleanup EXIT INT TERM

SSH_COMMON=(
  -p "$PORT"
  -o ConnectTimeout=15
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=2
  -o StrictHostKeyChecking=ask
  -o ControlMaster=auto
  -o ControlPersist=60
  -o "ControlPath=$control_socket"
)
SCP_COMMON=(
  -P "$PORT"
  -o ConnectTimeout=15
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=2
  -o StrictHostKeyChecking=ask
  -o ControlMaster=auto
  -o ControlPersist=60
  -o "ControlPath=$control_socket"
)
if [ "$NON_INTERACTIVE" -eq 1 ]; then
  SSH_COMMON+=( -o BatchMode=yes )
  SCP_COMMON+=( -o BatchMode=yes )
else
  SSH_COMMON+=( -o BatchMode=no )
  SCP_COMMON+=( -o BatchMode=no )
fi
[ -n "$IDENTITY" ] && { SSH_COMMON+=( -i "$IDENTITY" ); SCP_COMMON+=( -i "$IDENTITY" ); }
TARGET="$REMOTE_USER@$HOST"

ssh_exec() {
  ssh "${SSH_COMMON[@]}" "$TARGET" "$1"
}

ssh_script() {
  local command="bash -s --"
  local value quoted
  for value in "$@"; do
    quoted=$(shell_quote "$value")
    command+=" $quoted"
  done
  ssh -tt "${SSH_COMMON[@]}" "$TARGET" "$command"
}

if [ "$MODE" = fetch ]; then
  echo "connecting to $TARGET"
  ssh_script "$VERSION" "$ROLE" "$START" <<'REMOTE_FETCH'
set -euo pipefail
version=$1
role=$2
start=$3
command -v p2wlan-server >/dev/null 2>&1 || {
  echo "p2wlan-server is not installed; use upload mode for the first install" >&2
  exit 1
}
sudo p2wlan-server update --version "$version"
sudo p2wlan-server verify --service "$role"
if [ "$start" = 1 ]; then
  sudo p2wlan-server start --service "$role"
  sudo p2wlan-server check --service "$role"
else
  echo "verified release; service start/health check skipped (pass --start to enable it)"
fi
REMOTE_FETCH
  echo "server fetch deployment completed"
  exit 0
fi

remote_arch=$(ssh_exec 'uname -m')
case "$remote_arch" in
  x86_64|amd64) remote_arch=amd64 ;;
  aarch64|arm64) remote_arch=arm64 ;;
  *) die "unsupported remote architecture: $remote_arch" ;;
esac
if [ -z "$ARCHIVE" ]; then
  if [ "$ARCH" = auto ]; then
    ARCH=$remote_arch
  elif [ "$ARCH" != "$remote_arch" ]; then
    die "requested archive architecture $ARCH does not match remote $remote_arch"
  fi
  ARCHIVE="$local_tmp/p2wlan-server-linux-$ARCH.tar.gz"
  curl -fL --retry 3 -o "$ARCHIVE" "https://github.com/$REPO/releases/download/$VERSION/p2wlan-server-linux-$ARCH.tar.gz"
  curl -fL --retry 3 -o "$ARCHIVE.sha256" "https://github.com/$REPO/releases/download/$VERSION/p2wlan-server-linux-$ARCH.tar.gz.sha256"
  (cd "$local_tmp" && sha256sum -c "$(basename "$ARCHIVE.sha256")")
else
  ARCHIVE=$(cd "$(dirname "$ARCHIVE")" && pwd)/$(basename "$ARCHIVE")
fi

archive_name=$(basename "$ARCHIVE")
case "$archive_name" in
  p2wlan-server-linux-amd64.tar.gz) archive_arch=amd64 ;;
  p2wlan-server-linux-arm64.tar.gz) archive_arch=arm64 ;;
  *) die "archive must be named p2wlan-server-linux-<arch>.tar.gz" ;;
esac
[ "$archive_arch" = "$remote_arch" ] || die "archive architecture $archive_arch does not match remote $remote_arch"

tar -xOf "$ARCHIVE" p2wlan-server > "$local_tmp/p2wlan-server"
tar -xOf "$ARCHIVE" install-server.sh > "$local_tmp/install-server.sh"
chmod 0755 "$local_tmp/p2wlan-server" "$local_tmp/install-server.sh"

echo "uploading $archive_name to $TARGET"
remote_dir="/tmp/p2wlan-deploy-$(date -u +%Y%m%dT%H%M%SZ)-$$"
ssh_exec "umask 077; mkdir -p $(shell_quote "$remote_dir")"
scp "${SCP_COMMON[@]}" \
  "$ARCHIVE" "$ARCHIVE.sha256" "$local_tmp/p2wlan-server" "$local_tmp/install-server.sh" \
  "$TARGET:$remote_dir/"

ssh_script "$remote_dir" "$archive_name" "$ROLE" "$START" "$REMOTE_ROOT" "$REMOTE_CONFIG" "$REMOTE_DATA" <<'REMOTE_UPLOAD'
set -euo pipefail
remote_dir=$1
archive_name=$2
role=$3
start=$4
remote_root=$5
remote_config=$6
remote_data=$7
archive="$remote_dir/$archive_name"

cd "$remote_dir"
sha256sum -c "$(basename "$archive").sha256"

manager_env=()
installer_args=(--archive "$archive" --role "$role")
if [ -n "$remote_root" ]; then
  manager_env+=(P2WLAN_SERVER_ROOT="$remote_root")
  installer_args+=(--root "$remote_root")
fi
if [ -n "$remote_config" ]; then
  manager_env+=(P2WLAN_SERVER_CONFIG="$remote_config")
  installer_args+=(--config-dir "$remote_config")
fi
if [ -n "$remote_data" ]; then
  manager_env+=(P2WLAN_SERVER_DATA="$remote_data")
  installer_args+=(--data-dir "$remote_data")
fi

existing=0
if [ -n "$remote_root" ]; then
  [ -e "$remote_root/current" ] && existing=1 || true
else
  [ -e /opt/p2wlan-server/current ] && existing=1 || true
fi

if [ "$existing" -eq 1 ]; then
  sudo install -m 0755 p2wlan-server /usr/local/bin/p2wlan-server
  sudo env "${manager_env[@]}" p2wlan-server update --archive "$archive"
else
  sudo ./install-server.sh "${installer_args[@]}"
fi

sudo env "${manager_env[@]}" p2wlan-server verify --service "$role"
if [ "$start" = 1 ]; then
  sudo env "${manager_env[@]}" p2wlan-server start --service "$role"
  sudo env "${manager_env[@]}" p2wlan-server check --service "$role"
else
  echo "verified release; service start/health check skipped (pass --start to enable it)"
fi
REMOTE_UPLOAD

echo "server upload deployment completed"
