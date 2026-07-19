#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run this installer with sudo." >&2
  exit 1
fi

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_DIR=${P2WLAN_INSTALL_DIR:-/usr/local/bin}

if [ ! -x "$SOURCE_DIR/p2wlan" ] || [ ! -x "$SOURCE_DIR/p2pnet-daemon" ]; then
  echo "p2wlan and p2pnet-daemon must be next to this installer." >&2
  exit 1
fi

install -d "$INSTALL_DIR"
install -m 0755 "$SOURCE_DIR/p2wlan" "$INSTALL_DIR/p2wlan"
install -m 0755 "$SOURCE_DIR/p2pnet-daemon" "$INSTALL_DIR/p2pnet-daemon"

echo "Installed p2wlan to $INSTALL_DIR/p2wlan"
echo "Run 'p2wlan help' to get started."
