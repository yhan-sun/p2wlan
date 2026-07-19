#!/usr/bin/env sh
set -eu

REPO=${P2WLAN_REPO:-yhan-sun/p2wlan}
VERSION=${P2WLAN_VERSION:-latest}
INSTALL_DIR=${P2WLAN_INSTALL_DIR:-/usr/local/bin}

usage() {
  cat <<'EOF'
p2wlan Linux CLI installer

Usage:
  sudo ./install.sh
  curl -fsSL https://raw.githubusercontent.com/yhan-sun/p2wlan/main/scripts/install-linux-cli.sh -o /tmp/p2wlan-install.sh
  sudo sh /tmp/p2wlan-install.sh
  sudo env P2WLAN_VERSION=v0.1.23 sh /tmp/p2wlan-install.sh

Environment:
  P2WLAN_VERSION      Release tag to install, for example v0.1.23. Default: latest
  P2WLAN_REPO         GitHub repo to download from. Default: yhan-sun/p2wlan
  P2WLAN_INSTALL_DIR  Install directory. Default: /usr/local/bin
EOF
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run this installer with sudo." >&2
  exit 1
fi

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PACKAGE_DIR=$SOURCE_DIR
WORK_DIR=

cleanup() {
  if [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT INT TERM

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

download_file() {
  url=$1
  dest=$2
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --connect-timeout 20 -o "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$dest" "$url"
  else
    echo "Missing required command: curl or wget" >&2
    exit 1
  fi
}

detect_arch() {
  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64)
      echo "x64"
      ;;
    aarch64|arm64)
      echo "arm64"
      ;;
    *)
      echo "Unsupported Linux architecture: $arch" >&2
      exit 1
      ;;
  esac
}

if [ ! -f "$PACKAGE_DIR/p2wlan" ] || [ ! -f "$PACKAGE_DIR/p2pnet-daemon" ]; then
  need_cmd uname
  need_cmd mktemp
  need_cmd tar
  need_cmd install

  RELEASE_ARCH=$(detect_arch)
  ASSET="p2wlan-linux-${RELEASE_ARCH}-cli.tar.gz"
  if [ "$VERSION" = "latest" ]; then
    URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
  else
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
  fi

  WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/p2wlan-install.XXXXXX")
  ARCHIVE="$WORK_DIR/$ASSET"
  echo "Downloading $URL"
  download_file "$URL" "$ARCHIVE"
  tar -xzf "$ARCHIVE" -C "$WORK_DIR"
  PACKAGE_DIR="$WORK_DIR/p2wlan-linux-${RELEASE_ARCH}-cli"
fi

if [ ! -f "$PACKAGE_DIR/p2wlan" ] || [ ! -f "$PACKAGE_DIR/p2pnet-daemon" ]; then
  echo "p2wlan and p2pnet-daemon were not found in $PACKAGE_DIR." >&2
  exit 1
fi

need_cmd install

install -d "$INSTALL_DIR"
install -m 0755 "$PACKAGE_DIR/p2wlan" "$INSTALL_DIR/p2wlan"
install -m 0755 "$PACKAGE_DIR/p2pnet-daemon" "$INSTALL_DIR/p2pnet-daemon"

echo "Installed p2wlan to $INSTALL_DIR/p2wlan"
echo "Installed p2pnet-daemon to $INSTALL_DIR/p2pnet-daemon"
if [ -x "$INSTALL_DIR/p2wlan" ]; then
  "$INSTALL_DIR/p2wlan" --version
fi
echo "Run 'p2wlan help' to get started."
