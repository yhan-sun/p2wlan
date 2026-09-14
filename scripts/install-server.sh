#!/usr/bin/env bash
set -euo pipefail

REPO=${P2WLAN_REPO:-yhan-sun/p2wlan}
VERSION=${P2WLAN_SERVER_VERSION:-latest}
ROLE=all
INSTALL_ROOT=${P2WLAN_SERVER_ROOT:-/opt/p2wlan-server}
CONFIG_DIR=${P2WLAN_SERVER_CONFIG:-/etc/p2wlan}
DATA_DIR=${P2WLAN_SERVER_DATA:-/var/lib/p2wlan}
DRY_RUN=0
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

die() {
  echo "install-server: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
P2WLAN self-hosted server installer

Usage:
  sudo ./install-server.sh [--role control|relay|all] [--version server-vX.Y.Z]
  sudo ./install-server.sh --archive p2wlan-server-linux-amd64.tar.gz

Optional isolated paths: --root DIR --config-dir DIR --data-dir DIR.

The installer verifies the archive's adjacent .sha256 file before extraction.
It keeps configuration and data outside the release directory.
EOF
}

ARCHIVE=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --role) ROLE=${2:?missing role}; shift 2 ;;
    --version) VERSION=${2:?missing version}; shift 2 ;;
    --archive) ARCHIVE=${2:?missing archive}; shift 2 ;;
    --repo) REPO=${2:?missing repo}; shift 2 ;;
    --root) INSTALL_ROOT=${2:?missing root}; shift 2 ;;
    --config-dir) CONFIG_DIR=${2:?missing config dir}; shift 2 ;;
    --data-dir) DATA_DIR=${2:?missing data dir}; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
case "$ROLE" in control|relay|all) ;; *) echo "invalid role: $ROLE" >&2; exit 2 ;; esac
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

arch=$(uname -m)
case "$arch" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac

tmp_dir=
cleanup() { [ -z "${tmp_dir:-}" ] || rm -rf "$tmp_dir"; }
trap cleanup EXIT INT TERM

if [ -z "$ARCHIVE" ]; then
  command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
  [ "$VERSION" != latest ] || { echo "--version is required for a reproducible server install" >&2; exit 2; }
  case "$VERSION" in
    server-v[A-Za-z0-9._-]*) ;;
    *) die "--version must look like server-vX.Y.Z" ;;
  esac
  tmp_dir=$(mktemp -d /tmp/p2wlan-server-install.XXXXXX)
  ARCHIVE="$tmp_dir/p2wlan-server-linux-$arch.tar.gz"
  curl -fL --retry 3 -o "$ARCHIVE" "https://github.com/$REPO/releases/download/$VERSION/p2wlan-server-linux-$arch.tar.gz"
  curl -fL --retry 3 -o "$ARCHIVE.sha256" "https://github.com/$REPO/releases/download/$VERSION/p2wlan-server-linux-$arch.tar.gz.sha256"
else
  [ -f "$ARCHIVE" ] || { echo "archive not found: $ARCHIVE" >&2; exit 1; }
  [ -f "$ARCHIVE.sha256" ] || { echo "missing checksum: $ARCHIVE.sha256" >&2; exit 1; }
fi

checksum_dir=$(dirname "$ARCHIVE")
(cd "$checksum_dir" && sha256sum -c "$(basename "$ARCHIVE.sha256")")

if [ "$DRY_RUN" -eq 1 ]; then
  echo "verified $ARCHIVE"
  echo "would install root=$INSTALL_ROOT config=$CONFIG_DIR data=$DATA_DIR role=$ROLE"
  exit 0
fi

install -d -m 0755 "$INSTALL_ROOT/releases" "$CONFIG_DIR" /usr/local/bin
manager_path=/usr/local/bin/p2wlan-server
manager_source="$SCRIPT_DIR/p2wlan-server"
[ -x "$manager_source" ] || die "p2wlan-server is missing beside install-server.sh; use the complete verified release archive"
install -m 0755 "$manager_source" "$manager_path"
P2WLAN_SERVER_ROOT="$INSTALL_ROOT" P2WLAN_SERVER_CONFIG="$CONFIG_DIR" P2WLAN_SERVER_DATA="$DATA_DIR" \
  "$manager_path" init --role "$ROLE"
P2WLAN_SERVER_ROOT="$INSTALL_ROOT" P2WLAN_SERVER_CONFIG="$CONFIG_DIR" P2WLAN_SERVER_DATA="$DATA_DIR" \
  "$manager_path" update --archive "$ARCHIVE"
echo "P2WLAN server installed. Configure relay catalog/TLS in $CONFIG_DIR before enabling public traffic."
