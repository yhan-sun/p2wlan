#!/usr/bin/env sh
set -eu

REPO=${P2WLAN_REPO:-yhan-sun/p2wlan}
VERSION=${P2WLAN_VERSION:-}
INSTALL_DIR=${P2WLAN_INSTALL_DIR:-/usr/local/bin}
TMP_ROOT=${TMPDIR:-/tmp}
DRY_RUN=0

usage() {
  cat <<'EOF'
p2wlan Linux CLI installer

Usage:
  sudo sh install.sh                    Install the latest client release
  sudo sh install.sh --version vX.Y.Z   Install a fixed client release
  sh install.sh --install-dir "$HOME/.local/bin"
  curl -fsSL https://raw.githubusercontent.com/yhan-sun/p2wlan/main/scripts/install-linux-cli.sh -o /tmp/p2wlan-install.sh
  sudo sh /tmp/p2wlan-install.sh

Environment:
  P2WLAN_VERSION       Release tag to install, for example vX.Y.Z. Default: latest client release
  P2WLAN_REPO          GitHub repo to download from. Default: yhan-sun/p2wlan
  P2WLAN_INSTALL_DIR   Install directory. Default: /usr/local/bin
  P2WLAN_GITHUB_TOKEN  Optional token used when resolving the latest release (GitHub API rate limit)

Options:
  --version TAG       Install this exact release tag instead of the latest
  --repo OWNER/NAME   GitHub repo to download from
  --install-dir DIR   Install directory for p2wlan and p2wlan-daemon
  --dry-run           Print the selected package without installing
  -h, --help          Show this help
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --version)
      if [ "$#" -lt 2 ]; then
        echo "--version requires a release tag." >&2
        exit 1
      fi
      VERSION=$2
      shift 2
      ;;
    --version=*)
      VERSION=${1#*=}
      shift
      ;;
    --repo)
      if [ "$#" -lt 2 ]; then
        echo "--repo requires OWNER/NAME." >&2
        exit 1
      fi
      REPO=$2
      shift 2
      ;;
    --repo=*)
      REPO=${1#*=}
      shift
      ;;
    --install-dir)
      if [ "$#" -lt 2 ]; then
        echo "--install-dir requires a directory." >&2
        exit 1
      fi
      INSTALL_DIR=$2
      shift 2
      ;;
    --install-dir=*)
      INSTALL_DIR=${1#*=}
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ -f /etc/openwrt_release ]; then
  echo "OpenWrt requires the native .apk (25.12) or .ipk (24.10) package; this installer selects glibc binaries." >&2
  exit 1
fi

if [ -z "$REPO" ] || [ -z "$INSTALL_DIR" ]; then
  echo "P2WLAN_REPO and P2WLAN_INSTALL_DIR must not be empty." >&2
  exit 1
fi

SOURCE_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
PACKAGE_DIR=$SOURCE_DIR
LOCAL_PACKAGE=0
WORK_DIR=

cleanup() {
  case "${WORK_DIR:-}" in
    /tmp/p2wlan-install.*|"$TMP_ROOT"/p2wlan-install.*)
      if [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
      fi
      ;;
  esac
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

fetch_stdout() {
  url=$1
  if command -v curl >/dev/null 2>&1; then
    if [ -n "${P2WLAN_GITHUB_TOKEN:-}" ]; then
      curl -fsSL --retry 2 --connect-timeout 20 --max-time 60 \
        -H "Authorization: Bearer ${P2WLAN_GITHUB_TOKEN}" "$url"
    else
      curl -fsSL --retry 2 --connect-timeout 20 --max-time 60 "$url"
    fi
  elif command -v wget >/dev/null 2>&1; then
    if [ -n "${P2WLAN_GITHUB_TOKEN:-}" ]; then
      wget -q -O - --header="Authorization: Bearer ${P2WLAN_GITHUB_TOKEN}" "$url"
    else
      wget -q -O - "$url"
    fi
  else
    echo "Missing required command: curl or wget" >&2
    return 1
  fi
}

# Newest published client release. Client tags are plain vX.Y.Z; server
# releases use server-vX.Y.Z and pre-releases carry a suffix, so both are
# excluded by the tag pattern.
latest_client_version() {
  page=$(fetch_stdout "https://api.github.com/repos/${REPO}/releases?per_page=30") || return 1
  printf '%s\n' "$page" |
    sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\(v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)".*/\1/p' |
    head -n 1
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

if [ -f "$PACKAGE_DIR/p2wlan" ] &&
  [ -f "$PACKAGE_DIR/p2wlan-daemon" ] &&
  [ -f "$PACKAGE_DIR/README-LINUX-CLI.txt" ]; then
  LOCAL_PACKAGE=1
fi

if [ "$LOCAL_PACKAGE" -ne 1 ]; then
  if [ -z "$VERSION" ]; then
    if ! VERSION=$(latest_client_version); then
      echo "Could not read https://api.github.com/repos/${REPO}/releases." >&2
      echo "Check network access, set P2WLAN_GITHUB_TOKEN, or pass --version vX.Y.Z." >&2
      exit 1
    fi
    if [ -z "$VERSION" ]; then
      echo "No client release tag found on https://github.com/${REPO}/releases." >&2
      echo "Pass --version vX.Y.Z explicitly." >&2
      exit 1
    fi
    echo "Using latest client release $VERSION"
  fi
  case "$VERSION" in
    v?*) ;;
    *) echo "--version must look like vX.Y.Z." >&2; exit 1 ;;
  esac
  # Match the complete tag grammar used by the release metadata tools.
  case "$VERSION" in
    *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-]*) echo "--version must look like vX.Y.Z." >&2; exit 1 ;;
  esac
  need_cmd uname
  need_cmd mktemp
  need_cmd tar

  RELEASE_ARCH=$(detect_arch)
  ASSET="p2wlan-linux-${RELEASE_ARCH}-cli.tar.gz"
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "Would download $URL"
    echo "Would install to $INSTALL_DIR"
    exit 0
  fi

  WORK_DIR=$(mktemp -d "$TMP_ROOT/p2wlan-install.XXXXXX")
  ARCHIVE="$WORK_DIR/$ASSET"
  CHECKSUM="$WORK_DIR/$ASSET.sha256"
  echo "Downloading $URL"
  if ! download_file "$URL" "$ARCHIVE"; then
    echo "No release package at $URL" >&2
    echo "Client tags look like vX.Y.Z; server-vX.Y.Z releases carry no Linux CLI package." >&2
    echo "Pick an existing client release from https://github.com/${REPO}/releases and pass its exact tag." >&2
    exit 1
  fi
  if ! download_file "${URL}.sha256" "$CHECKSUM"; then
    echo "No checksum at ${URL}.sha256" >&2
    echo "Refusing to install a package without its release checksum." >&2
    exit 1
  fi
  (cd "$WORK_DIR" && sha256sum -c "$(basename "$CHECKSUM")")
  tar -xzf "$ARCHIVE" -C "$WORK_DIR"
  PACKAGE_DIR="$WORK_DIR/p2wlan-linux-${RELEASE_ARCH}-cli"
fi

if [ ! -f "$PACKAGE_DIR/p2wlan" ] || [ ! -f "$PACKAGE_DIR/p2wlan-daemon" ]; then
  echo "p2wlan and p2wlan-daemon were not found in $PACKAGE_DIR." >&2
  exit 1
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo "Would install $PACKAGE_DIR/p2wlan to $INSTALL_DIR/p2wlan"
  echo "Would install $PACKAGE_DIR/p2wlan-daemon to $INSTALL_DIR/p2wlan-daemon"
  exit 0
fi

if [ "$(id -u)" -ne 0 ] && [ "$INSTALL_DIR" = "/usr/local/bin" ]; then
  echo "Please run this installer with sudo, or choose a user-writable directory with --install-dir." >&2
  exit 1
fi

need_cmd install

install -d "$INSTALL_DIR"
install -m 0755 "$PACKAGE_DIR/p2wlan" "$INSTALL_DIR/p2wlan"
install -m 0755 "$PACKAGE_DIR/p2wlan-daemon" "$INSTALL_DIR/p2wlan-daemon"

echo "Installed p2wlan to $INSTALL_DIR/p2wlan"
echo "Installed p2wlan-daemon to $INSTALL_DIR/p2wlan-daemon"
if [ -x "$INSTALL_DIR/p2wlan" ]; then
  "$INSTALL_DIR/p2wlan" --version
fi
cat <<'EOF'
Next steps:
  1. p2wlan config set control https://control.example.com
  2. p2wlan login -u your-name
  3. p2wlan up
  4. p2wlan doctor

Use your deployment's real trusted Control URL. Login/configuration should run as your normal user, not with sudo.
EOF
