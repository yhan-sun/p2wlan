#!/usr/bin/env bash
set -euo pipefail
umask 077

REPO=${P2WLAN_REPO:-yhan-sun/p2wlan}
VERSION=${P2WLAN_SERVER_VERSION:-}
ROLE=all
INSTALL_ROOT=${P2WLAN_SERVER_ROOT:-/opt/p2wlan-server}
CONFIG_DIR=${P2WLAN_SERVER_CONFIG:-/etc/p2wlan}
DATA_DIR=${P2WLAN_SERVER_DATA:-/var/lib/p2wlan}
INTERACTIVE=0
[ "$#" -ne 0 ] || INTERACTIVE=1
DRY_RUN=0
START=0
START_SET=0
ARCHIVE=
ENDPOINT=
TLS_CERT=
TLS_KEY=
DEV_LOCALHOST=0
INSTALL_DEPS=0
CONTROL_PORT=18080
METRICS_PORT=18082
ROOT_SET=0
CONFIG_SET=0
DATA_SET=0
CONTROL_PORT_SET=0
METRICS_PORT_SET=0

die() { echo "install-server: $*" >&2; exit 1; }
usage() {
  cat <<'HELP'
P2WLAN self-hosted server installer (Linux + systemd)

Usage:
  sudo bash scripts/install-server.sh
  sudo bash install-server.sh --archive p2wlan-server-linux-amd64.tar.gz --interactive
  sudo bash install-server.sh --version server-vX.Y.Z --non-interactive [options]

No arguments opens the guided installer on /dev/tty. It preserves existing
configuration and data. New paired Control/Relay configuration uses a supplied
TLS certificate; Control HTTPS is provided by your existing reverse proxy.

Options:
  --interactive               guide installation using the terminal
  --non-interactive           never prompt (suitable for automation)
  --version server-vX.Y.Z     fixed server release tag (never latest)
  --archive FILE              local release archive and adjacent FILE.sha256
  --repo OWNER/REPO           release repository
  --role control|relay|all    systemd services to install (default: all)
  --relay-endpoint URL        tls://host:port for new paired configuration
  --tls-cert FILE             existing certificate chain covering Relay host
  --tls-key FILE              matching private key (never printed)
  --dev-localhost             isolated loopback test certificate, not public TLS
  --control-port PORT         internal loopback Control port (default: 18080)
  --metrics-port PORT         loopback readiness port (default: 18082)
  --start / --no-start        enable/start and check, or only install
                              (guided default: start; automation default: no-start)
  --install-deps              install missing prerequisites with apt-get/dnf
  --root DIR --config-dir DIR --data-dir DIR
                              absolute, separate persistent installation paths
  --dry-run                   verify archive/metadata/checksums without installing
  -h, --help                  show this help

For a new public paired deployment, supply --relay-endpoint, --tls-cert and
--tls-key, or use the wizard. Without these, automation only initializes files
for manual configuration; --start then requires existing complete configuration.
HELP
}
value() { [ "$#" -ge 2 ] && [ -n "$2" ] && [[ "$2" != --* ]] || die "$1 requires a value"; }
prompt() {
  local variable=$1 label=$2 default=${3:-} reply
  printf '%s%s: ' "$label" "${default:+ [$default]}" >&3
  IFS= read -r reply <&3 || die "terminal input ended; installation cancelled"
  case "$reply" in cancel|取消) die 'installation cancelled' ;; esac
  printf -v "$variable" '%s' "${reply:-$default}"
}
valid_path() {
  case "$1" in /*) ;; *) die "installation paths must be absolute" ;; esac
  case "$1" in /|*//*|*[!A-Za-z0-9_./-]*|*/../*|*/./*|*/..|*/.) die "unsafe installation path: $1" ;; esac
}
valid_version() {
  case "$1" in server-v?*) ;; *) die "version must look like server-vX.Y.Z (latest is not supported)" ;; esac
  case "$1" in *[!A-Za-z0-9._-]*) die "invalid version characters" ;; esac
}
validate_paths() {
  local path pair left right
  for path in "$INSTALL_ROOT" "$CONFIG_DIR" "$DATA_DIR"; do valid_path "$path"; done
  INSTALL_ROOT=${INSTALL_ROOT%/}; CONFIG_DIR=${CONFIG_DIR%/}; DATA_DIR=${DATA_DIR%/}
  for pair in "$INSTALL_ROOT:$CONFIG_DIR" "$INSTALL_ROOT:$DATA_DIR" "$CONFIG_DIR:$DATA_DIR"; do
    left=${pair%%:*}; right=${pair#*:}
    [[ "$left/" != "$right/"* && "$right/" != "$left/"* ]] || die 'root, config and data paths must be separate'
  done
}
wizard_paths() {
  local _paths_edit=${1:-0}
  printf '\n[1/7] 原生安装目录\n' >&3
  while true; do
    if [ "$_paths_edit" -eq 1 ] || [ "$ROOT_SET" -eq 0 ]; then prompt INSTALL_ROOT '程序目录' "$INSTALL_ROOT"; fi
    if [ "$_paths_edit" -eq 1 ] || [ "$CONFIG_SET" -eq 0 ]; then prompt CONFIG_DIR '配置目录' "$CONFIG_DIR"; fi
    if [ "$_paths_edit" -eq 1 ] || [ "$DATA_SET" -eq 0 ]; then prompt DATA_DIR '数据目录' "$DATA_DIR"; fi
    if (validate_paths) 2>/dev/null; then validate_paths; break; fi
    printf '目录无效：请输入三个安全、绝对且互不包含的路径。请重试，或输入“取消”。\n' >&3
    _paths_edit=1
  done
  printf '程序：%s\n配置：%s\n数据：%s\n' "$INSTALL_ROOT" "$CONFIG_DIR" "$DATA_DIR" >&3
}
ask_choice() {
  local _choice_target=$1 _choice_label=$2 _choice_default=$3 _choice_allowed=$4
  while true; do
    prompt "$_choice_target" "$_choice_label" "$_choice_default"
    [[ " $_choice_allowed " == *" ${!_choice_target} "* ]] && return 0
    printf '请选择 %s；输入“取消”可退出。\n' "$_choice_allowed" >&3
  done
}
check_input() {
  python3 - "$@" <<'PY_INPUT'
import ipaddress, json, os, pathlib, re, sys, urllib.parse
def port(value):
    if not re.fullmatch(r'[0-9]+', value) or not 1 <= int(value) <= 65535:
        raise ValueError()
    return int(value)
def host(value, dev):
    value = value.strip('[]')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value):
            raise ValueError()
        if any(not part or len(part) > 63 or part.startswith('-') or part.endswith('-') for part in value.split('.')):
            raise ValueError()
        if dev and value.lower() != 'localhost':
            raise ValueError()
        return value.lower()
    if address.is_unspecified or (dev and not address.is_loopback):
        raise ValueError()
    return address.compressed
def endpoint(value, dev=False):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != 'tls' or parsed.username is not None or parsed.password is not None
            or parsed.path or parsed.query or parsed.fragment or '?' in value or '#' in value
            or any(character in value for character in '\r\n\t\x00') or not parsed.hostname or parsed.port is None):
        raise ValueError()
    return host(parsed.hostname, dev), port(str(parsed.port))
def authority(name, number):
    return ('[' + name + ']' if ':' in name else name) + ':' + str(number)
try:
    action, value, *extra = sys.argv[1:]
    if action == 'port':
        number = port(value)
        if number in [port(other) for other in extra]:
            raise ValueError()
        print(number)
    elif action == 'host':
        print(host(value, extra[0] == '1'))
    elif action == 'file':
        if any(character in value for character in '\r\n\x00'):
            raise ValueError()
        path = pathlib.Path(value).expanduser()
        if not path.is_file() or not os.access(path, os.R_OK):
            raise ValueError()
        print(path.resolve())
    elif action == 'endpoint':
        print(*endpoint(value, extra[0] == '1'))
    elif action == 'public-info':
        control = pathlib.Path(value) / 'control.env'
        fields = {}
        if control.is_file():
            for line in control.read_text().splitlines():
                key, separator, item = line.partition('=')
                if separator and key in ('CONTROL_BIND', 'PORT', 'RELAY_CATALOG_JSON'):
                    fields[key] = item
        if fields:
            bind = fields.get('CONTROL_BIND', '127.0.0.1:' + fields.get('PORT', '18080'))
            name, _, number = bind.rpartition(':')
            name = name.strip('[]')
            if name in ('', '0.0.0.0'): name = '127.0.0.1'
            if name == '::': name = '::1'
            base = 'http://' + authority(host(name, False), port(number))
            label = 'Local Control' if extra[1] == '1' else 'Configured Control (services not started)'
            print(label + ': ' + base)
            print('Admin path: ' + base + '/admin/')
        relay = extra[0]
        if fields.get('RELAY_CATALOG_JSON'):
            catalog = json.loads(fields['RELAY_CATALOG_JSON'])
            if isinstance(catalog, list) and catalog and isinstance(catalog[0], dict):
                relay = catalog[0].get('endpoint', '')
        if relay:
            name, number = endpoint(relay)
            print('Relay endpoint: tls://' + authority(name, number))
    else:
        raise ValueError()
except (ValueError, OSError, RuntimeError, IndexError, OverflowError, TypeError):
    sys.exit(1)
PY_INPUT
}
ask_input() {
  local _input_target=$1 _input_label=$2 _input_default=$3 _input_action=$4
  shift 4
  while true; do
    prompt "$_input_target" "$_input_label" "$_input_default"
    if check_input "$_input_action" "${!_input_target}" "$@" >/dev/null 2>&1; then
      if [ "$_input_action" = file ] || [ "$_input_action" = host ] || [ "$_input_action" = port ]; then
        printf -v "$_input_target" '%s' "$(check_input "$_input_action" "${!_input_target}" "$@")"
      fi
      return 0
    fi
    printf '输入无效：请检查地址、端口范围/重复或可读取的 PEM 路径；输入“取消”可退出。\n' >&3
  done
}
wizard_new_configuration() {
  local _wizard_edit=${1:-0} _parts= _mode_default=1
  printf '\n[2/7] 部署模式\n  1) 公网部署（使用已有可信证书和 HTTPS/WSS 反向代理）\n  2) 本机测试（24 小时证书，仅 loopback）\n' >&3
  [ "$DEV_LOCALHOST" -eq 0 ] || _mode_default=2
  if [ "$_wizard_edit" -eq 1 ] || { [ "$DEV_LOCALHOST" -eq 0 ] && [ -z "$ENDPOINT$TLS_CERT$TLS_KEY" ]; }; then
    ask_choice mode_answer '部署模式' "$_mode_default" '1 2'
    case "$mode_answer" in 1) DEV_LOCALHOST=0 ;; 2) DEV_LOCALHOST=1 ;; esac
  elif [ "$_wizard_edit" -eq 0 ] && [ "$DEV_LOCALHOST" -eq 0 ] && { [ -z "$ENDPOINT" ] || [ -z "$TLS_CERT" ] || [ -z "$TLS_KEY" ]; }; then
    ask_choice mode_answer '部署模式' 1 '1 2'
    case "$mode_answer" in 1) DEV_LOCALHOST=0 ;; 2) DEV_LOCALHOST=1 ;; esac
  fi
  printf '\n[3/7] Relay 公告地址\n' >&3
  if [ -n "$ENDPOINT" ]; then _parts=$(check_input endpoint "$ENDPOINT" "$DEV_LOCALHOST" 2>/dev/null) || _parts=; fi
  if [ -n "$_parts" ]; then read -r RELAY_HOST RELAY_PORT <<<"$_parts"; else RELAY_HOST=; RELAY_PORT=18081; fi
  if [ "$_wizard_edit" -eq 1 ] || [ -z "$_parts" ]; then
    if [ -z "$RELAY_HOST" ] && [ "$DEV_LOCALHOST" -eq 1 ]; then RELAY_HOST=localhost; fi
    ask_input RELAY_HOST 'Relay主机（主机名或IP）' "$RELAY_HOST" host "$DEV_LOCALHOST"
    ask_input RELAY_PORT 'Relay端口' "$RELAY_PORT" port
    case "$RELAY_HOST" in *:*) ENDPOINT="tls://[$RELAY_HOST]:$RELAY_PORT" ;; *) ENDPOINT="tls://$RELAY_HOST:$RELAY_PORT" ;; esac
    read -r RELAY_HOST RELAY_PORT <<<"$(check_input endpoint "$ENDPOINT" "$DEV_LOCALHOST")"
    case "$RELAY_HOST" in *:*) ENDPOINT="tls://[$RELAY_HOST]:$RELAY_PORT" ;; *) ENDPOINT="tls://$RELAY_HOST:$RELAY_PORT" ;; esac
  fi
  printf 'Relay 地址：%s\n\n[4/7] TLS 证书\n' "$ENDPOINT" >&3
  if [ "$DEV_LOCALHOST" -eq 1 ]; then
    TLS_CERT=; TLS_KEY=
    printf '仅生成本机测试证书；不签发公网证书，不自动配置 HTTPS。\n' >&3
  else
    if [ "$_wizard_edit" -eq 1 ] || ! check_input file "$TLS_CERT" >/dev/null 2>&1; then ask_input TLS_CERT '证书链路径' "$TLS_CERT" file; fi
    if [ "$_wizard_edit" -eq 1 ] || ! check_input file "$TLS_KEY" >/dev/null 2>&1; then ask_input TLS_KEY '私钥路径' "$TLS_KEY" file; fi
    TLS_CERT=$(check_input file "$TLS_CERT"); TLS_KEY=$(check_input file "$TLS_KEY")
  fi
  printf '\n[5/7] 监听端口\n' >&3
  if [ "$_wizard_edit" -eq 1 ] || [ "$CONTROL_PORT_SET" -eq 0 ] || ! check_input port "$CONTROL_PORT" "$RELAY_PORT" >/dev/null 2>&1; then
    ask_input CONTROL_PORT 'Control端口' "$CONTROL_PORT" port "$RELAY_PORT"
  fi
  if [ "$_wizard_edit" -eq 1 ] || [ "$METRICS_PORT_SET" -eq 0 ] || ! check_input port "$METRICS_PORT" "$RELAY_PORT" "$CONTROL_PORT" >/dev/null 2>&1; then
    ask_input METRICS_PORT 'metrics端口' "$METRICS_PORT" port "$RELAY_PORT" "$CONTROL_PORT"
  fi
  CONTROL_PORT=$(check_input port "$CONTROL_PORT" "$RELAY_PORT")
  METRICS_PORT=$(check_input port "$METRICS_PORT" "$RELAY_PORT" "$CONTROL_PORT")
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --interactive) INTERACTIVE=1; shift ;;
    --non-interactive) INTERACTIVE=0; shift ;;
    --role) value "$@"; ROLE=$2; shift 2 ;;
    --version) value "$@"; VERSION=$2; shift 2 ;;
    --archive) value "$@"; ARCHIVE=$2; shift 2 ;;
    --repo) value "$@"; REPO=$2; shift 2 ;;
    --root) value "$@"; INSTALL_ROOT=$2; ROOT_SET=1; shift 2 ;;
    --config-dir) value "$@"; CONFIG_DIR=$2; CONFIG_SET=1; shift 2 ;;
    --data-dir) value "$@"; DATA_DIR=$2; DATA_SET=1; shift 2 ;;
    --relay-endpoint) value "$@"; ENDPOINT=$2; shift 2 ;;
    --tls-cert) value "$@"; TLS_CERT=$2; shift 2 ;;
    --tls-key) value "$@"; TLS_KEY=$2; shift 2 ;;
    --control-port) value "$@"; CONTROL_PORT=$2; CONTROL_PORT_SET=1; shift 2 ;;
    --metrics-port) value "$@"; METRICS_PORT=$2; METRICS_PORT_SET=1; shift 2 ;;
    --dev-localhost) DEV_LOCALHOST=1; shift ;;
    --install-deps) INSTALL_DEPS=1; shift ;;
    --start) START=1; START_SET=1; shift ;;
    --no-start) START=0; START_SET=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
case "$ROLE" in control|relay|all) ;; *) die "role must be control, relay, or all" ;; esac
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "repo must be OWNER/REPO"
if [ "$INTERACTIVE" -eq 0 ]; then validate_paths; fi
[ -z "$VERSION" ] || valid_version "$VERSION"
[ "$(uname -s)" = Linux ] || die "server installation requires Linux + systemd"
arch=$(uname -m)
case "$arch" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) die "unsupported architecture: $arch" ;; esac

if [ "$INTERACTIVE" -eq 1 ]; then
  { exec 3<>/dev/tty; } 2>/dev/null || die "interactive installation requires a terminal; use --non-interactive with --version or --archive"
  printf '\nP2WLAN 服务端安装向导 / Server setup\n' >&3
  printf '同机安装 Control + Relay；已有配置和数据会保留。\n' >&3
  if [ -z "$ARCHIVE" ] && [ -z "$VERSION" ]; then
    while true; do
      prompt VERSION '固定服务端版本（server-vX.Y.Z）' "$VERSION"
      if (valid_version "$VERSION") 2>/dev/null; then break; fi
      printf '请输入固定的 server-vX.Y.Z 版本，或输入“取消”。\n' >&3
    done
  fi
  wizard_paths 0
fi
[ -n "$ARCHIVE" ] || [ -n "$VERSION" ] || die "--version or --archive is required; use --interactive for guided setup"
[ "$DRY_RUN" -eq 1 ] || [ "$(id -u)" -eq 0 ] || die "run with sudo"

missing=()
for dependency in python3 tar; do
  command -v "$dependency" >/dev/null 2>&1 || missing+=("$dependency")
done
if [ -z "$ARCHIVE" ] || [ "$START" -eq 1 ] || [ "$INTERACTIVE" -eq 1 ]; then
  command -v curl >/dev/null 2>&1 || missing+=(curl)
fi
if [ "$DRY_RUN" -eq 0 ]; then
  for dependency in openssl useradd systemctl sha256sum; do
    command -v "$dependency" >/dev/null 2>&1 || missing+=("$dependency")
  done
fi
if [ "${#missing[@]}" -gt 0 ]; then
  if [ "$INTERACTIVE" -eq 1 ] && [ "$INSTALL_DEPS" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    prompt answer "缺少 ${missing[*]}，使用系统包管理器安装？y/n" y
    case "$answer" in y|Y|yes) INSTALL_DEPS=1 ;; *) die "missing prerequisites: ${missing[*]}" ;; esac
  fi
  [ "$INSTALL_DEPS" -eq 1 ] && [ "$DRY_RUN" -eq 0 ] || die "missing prerequisites: ${missing[*]} (use --install-deps)"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 curl ca-certificates tar openssl passwd coreutils
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 curl ca-certificates tar openssl shadow-utils coreutils
  else
    die "install prerequisites using your package manager: ${missing[*]}"
  fi
  for dependency in "${missing[@]}"; do command -v "$dependency" >/dev/null 2>&1 || die "still missing $dependency"; done
fi
if [ "$DRY_RUN" -eq 0 ]; then
  [ -d "${P2WLAN_SYSTEMD_DIR:-/run/systemd/system}" ] || die "a running systemd host is required"
fi

tmp_dir=$(mktemp -d /tmp/p2wlan-server-install.XXXXXX)
cleanup() { rm -rf "$tmp_dir"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [ -z "$ARCHIVE" ]; then
  ARCHIVE="$tmp_dir/p2wlan-server-linux-$arch.tar.gz"
  base="https://github.com/$REPO/releases/download/$VERSION"
  echo "[1/4] Downloading fixed release $VERSION ($arch)"
  curl -fL --retry 3 --connect-timeout 15 --max-time 300 -o "$ARCHIVE" "$base/$(basename "$ARCHIVE")"
  curl -fL --retry 3 --connect-timeout 15 --max-time 60 -o "$ARCHIVE.sha256" "$base/$(basename "$ARCHIVE").sha256"
else
  [ -f "$ARCHIVE" ] || die "archive not found: $ARCHIVE"
  [ -f "$ARCHIVE.sha256" ] || die "missing checksum: $ARCHIVE.sha256"
  # All later verification and installation use this private snapshot, even
  # when the original local download is replaced while the wizard is open.
  mkdir "$tmp_dir/input"
  cp -- "$ARCHIVE" "$tmp_dir/input/$(basename -- "$ARCHIVE")"
  cp -- "$ARCHIVE.sha256" "$tmp_dir/input/$(basename -- "$ARCHIVE").sha256"
  ARCHIVE="$tmp_dir/input/$(basename -- "$ARCHIVE")"
fi
[ -f "$ARCHIVE" ] || die "archive not found: $ARCHIVE"
[ -f "$ARCHIVE.sha256" ] || die "missing checksum: $ARCHIVE.sha256"
stage="$tmp_dir/bundle"
# Verify the actual archive, not a filename supplied by the checksum file. Only
# unique regular release members may be extracted; no tar links or path traversal.
python3 - "$ARCHIVE" "$stage" "$VERSION" "$arch" <<'PY_VERIFY'
import hashlib, pathlib, re, sys, tarfile
archive, output, expected, arch = sys.argv[1:]
try:
    checksum = pathlib.Path(archive + '.sha256').read_text().strip()
    match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *](.+)', checksum)
    if not match or pathlib.Path(match[2]).name != pathlib.Path(archive).name:
        raise ValueError('invalid archive checksum file')
    def digest(path):
        with open(path, 'rb') as stream:
            h = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(chunk)
            return h.hexdigest()
    if digest(archive) != match[1].lower():
        raise ValueError('archive checksum mismatch')
    binaries = {'p2wlan-control', 'p2wlan-relay', 'p2wlan-config', 'p2wlan-db'}
    executables = binaries | {'p2wlan-server', 'install-server.sh', 'deploy-server.sh'}
    required = executables | {'BUILD-METADATA.txt', 'SHA256SUMS'}
    with tarfile.open(archive, 'r:gz') as bundle:
        members = bundle.getmembers()
        if len(members) != len(required) or {m.name for m in members} != required:
            raise ValueError('archive must contain exactly the required release members')
        if any(not m.isfile() or m.size > 256 * 1024 * 1024 for m in members):
            raise ValueError('archive members must be bounded regular files')
        if any(m.name in executables and not m.mode & 0o111 for m in members):
            raise ValueError('archive contains non-executable release tools')
        metadata = {}
        for line in bundle.extractfile('BUILD-METADATA.txt').read().decode().splitlines():
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            if key in ('version', 'commit', 'arch') and key in metadata:
                raise ValueError('duplicate archive identity field: ' + key)
            metadata[key] = value
        version = metadata.get('version', '')
        if not re.fullmatch(r'server-(?:v|dev-)[A-Za-z0-9._-]+', version):
            raise ValueError('invalid archive release version')
        if expected and version != expected:
            raise ValueError('archive version does not match requested version')
        if not re.fullmatch(r'[0-9a-f]{40}', metadata.get('commit', '')):
            raise ValueError('archive requires a source commit')
        if metadata.get('arch') != arch:
            raise ValueError('archive architecture does not match host')
        sums = {}
        for line in bundle.extractfile('SHA256SUMS').read().decode().splitlines():
            entry = re.fullmatch(r'([0-9a-fA-F]{64}) [ *]([A-Za-z0-9.-]+)', line)
            if not entry or entry[2] in sums:
                raise ValueError('invalid binary checksum manifest')
            sums[entry[2]] = entry[1].lower()
        if set(sums) != binaries:
            raise ValueError('binary checksum manifest is incomplete')
        destination = pathlib.Path(output)
        destination.mkdir(mode=0o700)
        for member in members:
            data = bundle.extractfile(member).read()
            if member.name in sums and hashlib.sha256(data).hexdigest() != sums[member.name]:
                raise ValueError('binary checksum mismatch: ' + member.name)
            target = destination / member.name
            target.write_bytes(data)
            target.chmod(0o755 if member.name in executables else 0o600)
    print('[1/4] Verified release ' + version + ' commit=' + metadata['commit'] + ' arch=' + arch)
except (OSError, ValueError, tarfile.TarError, UnicodeError) as error:
    sys.exit('install-server: ' + str(error))
PY_VERIFY
if [ "$DRY_RUN" -eq 1 ]; then
  echo "would install root=$INSTALL_ROOT config=$CONFIG_DIR data=$DATA_DIR role=$ROLE start=$START"
  exit 0
fi

# Older server bundles cannot safely defer their first restart or render staged
# configuration paths. Reject those bundles before changing persistent files.
manager_help=$("$stage/p2wlan-server" --help 2>&1) || die "cannot inspect released manager"
[[ "$manager_help" == *--no-restart* ]] || die "release is too old for guided installation; select a bundle supporting update --no-restart"
metadata_version=$(awk -F= '$1 == "version" {print $2; exit}' "$stage/BUILD-METADATA.txt")
metadata_commit=$(awk -F= '$1 == "commit" {print $2; exit}' "$stage/BUILD-METADATA.txt")
for component in control relay; do
  identity=$("$stage/p2wlan-$component" --version) || die "cannot execute $component binary on this host"
  [ "$identity" = "p2wlan-$component $metadata_version ($metadata_commit)" ] || die "$component executable identity does not match archive metadata"
done

existing=0
configured=0
edit_configuration=0
while true; do
  existing=0
  [ ! -e "$INSTALL_ROOT/current" ] || existing=1
  configured=0
  if [ -e "$CONFIG_DIR/control.env" ] || [ -e "$CONFIG_DIR/relay.env" ]; then
    configured=1
    if [ "$edit_configuration" -eq 0 ]; then
      [ -z "$ENDPOINT$TLS_CERT$TLS_KEY" ] && [ "$DEV_LOCALHOST" -eq 0 ] || die "existing configuration is preserved; change certificates/configuration explicitly before reinstalling"
    else
      ENDPOINT=; TLS_CERT=; TLS_KEY=; DEV_LOCALHOST=0
    fi
  fi
  [ "$INTERACTIVE" -eq 1 ] || break
  if [ "$configured" -eq 1 ]; then
    printf '\n[2-5/7] 检测到已有配置：保留配置、证书、凭据、数据库与端口，只升级/重装选定版本。\n' >&3
    if [ "$ROLE" = all ] && { [ ! -f "$CONFIG_DIR/control.env" ] || [ ! -f "$CONFIG_DIR/relay.env" ]; }; then
      die 'partial existing configuration was preserved; complete matching service files explicitly before guided setup'
    fi
  else
    [ "$ROLE" = all ] || die "guided first setup supports --role all; split hosts require preconfigured matching files"
    wizard_new_configuration "$edit_configuration"
  fi
  printf '\n[6/7] 启动方式\n  1) 安装并启动（等待本机健康检查）\n  2) 只安装，不启动或重启服务\n' >&3
  if [ "$START_SET" -eq 0 ] || [ "$edit_configuration" -eq 1 ]; then
    start_default=1
    if [ "$START" -eq 0 ] && { [ "$START_SET" -eq 1 ] || [ "$edit_configuration" -eq 1 ]; }; then start_default=2; fi
    ask_choice start_answer '启动方式' "$start_default" '1 2'
    case "$start_answer" in 1) START=1 ;; 2) START=0 ;; esac
  fi
  printf '\n[7/7] 部署摘要\n固定版本：%s\n来源提交：%s\n服务：%s\n程序目录：%s\n配置目录：%s\n数据目录：%s\n' \
    "$metadata_version" "$metadata_commit" "$ROLE" "$INSTALL_ROOT" "$CONFIG_DIR" "$DATA_DIR" >&3
  if [ "$configured" -eq 1 ]; then
    printf '模式、Relay、TLS、Control/metrics 端口：沿用现有受保护配置，不轮换秘密。\n' >&3
  else
    mode_label=公网部署
    [ "$DEV_LOCALHOST" -eq 0 ] || mode_label=本机测试
    printf '部署模式：%s\nRelay地址：%s\nRelay端口：%s\nControl端口：%s\nmetrics端口：%s\n' \
      "$mode_label" "$ENDPOINT" "$RELAY_PORT" "$CONTROL_PORT" "$METRICS_PORT" >&3
    if [ "$DEV_LOCALHOST" -eq 1 ]; then
      printf 'TLS：生成仅 loopback 的本机测试证书（24 小时）。\n' >&3
    else
      printf '证书链路径：%s\n私钥路径：%s\n' "$TLS_CERT" "$TLS_KEY" >&3
    fi
  fi
  printf '安装后启动：%s\nControl 公网仍需可信 HTTPS/WSS 反向代理；本向导不签发公网证书。\n' "$START" >&3
  if [ "$configured" -eq 1 ]; then
    printf '  1) 确认部署  2) 重新选择启动方式  0) 取消\n' >&3
  else
    printf '  1) 确认部署  2) 重新填写配置  0) 取消\n' >&3
  fi
  ask_choice confirm_answer '确认部署' 1 '1 2 0'
  case "$confirm_answer" in
    0) die 'installation cancelled' ;;
    1) break ;;
    2)
      edit_configuration=1
      if [ "$configured" -eq 0 ]; then wizard_paths 1; fi
      ;;
  esac
done
if [ "$configured" -eq 0 ] && { [ -n "$ENDPOINT$TLS_CERT$TLS_KEY" ] || [ "$DEV_LOCALHOST" -eq 1 ]; }; then
  [ "$ROLE" = all ] || die "new paired configuration requires --role all"
  endpoint_parts=$(check_input endpoint "${ENDPOINT:-tls://localhost:18081}" "$DEV_LOCALHOST") || die 'invalid Relay endpoint'
  read -r RELAY_HOST RELAY_PORT <<<"$endpoint_parts"
  case "$RELAY_HOST" in *:*) ENDPOINT="tls://[$RELAY_HOST]:$RELAY_PORT" ;; *) ENDPOINT="tls://$RELAY_HOST:$RELAY_PORT" ;; esac
  CONTROL_PORT=$(check_input port "$CONTROL_PORT" "$RELAY_PORT") || die 'invalid or conflicting Control port'
  METRICS_PORT=$(check_input port "$METRICS_PORT" "$RELAY_PORT" "$CONTROL_PORT") || die 'invalid or conflicting metrics port'
  generator_help=$("$stage/p2wlan-config" --help 2>&1) || die "cannot inspect released configuration generator"
  [[ "$generator_help" == *-config-dir* && "$generator_help" == *-data-dir* ]] || die "release is too old for staged configuration; select a bundle supporting --config-dir and --data-dir"
  generator_args=(--mode native --output "$tmp_dir/config" --config-dir "$CONFIG_DIR" --data-dir "$DATA_DIR"
    --control-port "$CONTROL_PORT" --metrics-port "$METRICS_PORT")
  if [ "$DEV_LOCALHOST" -eq 1 ]; then
    [ -z "$TLS_CERT$TLS_KEY" ] || die "choose TLS files or --dev-localhost, not both"
    ENDPOINT=${ENDPOINT:-tls://localhost:18081}
    generator_args+=(--dev-localhost)
  else
    [ -n "$ENDPOINT" ] && [ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ] || die "new deployment needs --relay-endpoint, --tls-cert and --tls-key"
    generator_args+=(--tls-cert "$TLS_CERT" --tls-key "$TLS_KEY")
  fi
  generator_args+=(--relay-endpoint "$ENDPOINT")
  "$stage/p2wlan-config" "${generator_args[@]}"
  configured=2
fi
[ "$START" -eq 0 ] || [ "$configured" -ne 0 ] || die "--start requires complete configuration; use --interactive or supply TLS configuration"


# Fresh generated configuration is installed before init creates the units.
# Never merge freshly generated secrets into an existing/partial deployment.
if [ "$configured" -eq 2 ]; then
  if [ ! -d "$(dirname "$CONFIG_DIR")" ]; then install -d -m 0755 "$(dirname "$CONFIG_DIR")"; fi
  if [ -d "$CONFIG_DIR" ]; then
    rmdir "$CONFIG_DIR" || die "configuration directory must be empty for first setup"
  fi
  mv "$tmp_dir/config" "$CONFIG_DIR"
fi
echo '[2/4] Installing release and systemd units'
manager_env=(P2WLAN_SERVER_ROOT="$INSTALL_ROOT" P2WLAN_SERVER_CONFIG="$CONFIG_DIR" P2WLAN_SERVER_DATA="$DATA_DIR")
install -d -m 0755 /usr/local/bin
install -m 0755 "$stage/p2wlan-server" /usr/local/bin/p2wlan-server
env "${manager_env[@]}" "$stage/p2wlan-server" init --role "$ROLE"
env "${manager_env[@]}" "$stage/p2wlan-server" update --archive "$ARCHIVE" --service "$ROLE" --no-restart
env "${manager_env[@]}" "$stage/p2wlan-server" verify --service "$ROLE"
if [ "$START" -eq 1 ]; then
  echo '[3/4] Starting services'
  if [ "$existing" -eq 1 ]; then
    env "${manager_env[@]}" "$stage/p2wlan-server" restart --service "$ROLE"
  fi
  env "${manager_env[@]}" "$stage/p2wlan-server" start --service "$ROLE"
  echo '[4/4] Waiting for local health/readiness'
  healthy=0
  for ((attempt=1; attempt<=12; attempt++)); do
    if env "${manager_env[@]}" "$stage/p2wlan-server" check --service "$ROLE" >"$tmp_dir/health" 2>&1; then
      healthy=1; break
    fi
    [ "$attempt" -eq 12 ] || sleep 2
  done
  if [ "$healthy" -ne 1 ]; then
    cat "$tmp_dir/health" >&2
    die "service readiness failed; inspect sudo p2wlan-server status --service $ROLE and journalctl -u p2wlan-control -u p2wlan-relay"
  fi
  echo "P2WLAN server installed and local health checks passed."
else
  echo "P2WLAN server installed; services were not started or restarted."
fi
echo "Configuration: $CONFIG_DIR; data: $DATA_DIR"
echo "Admin console credential: CONTROL_ADMIN_TOKEN in $CONFIG_DIR/control.env (kept private)."
check_input public-info "$CONFIG_DIR" "$ENDPOINT" "$START" || true
echo "Status: sudo env P2WLAN_SERVER_ROOT=$INSTALL_ROOT P2WLAN_SERVER_CONFIG=$CONFIG_DIR P2WLAN_SERVER_DATA=$DATA_DIR p2wlan-server status --service $ROLE"
echo "Restart: sudo env P2WLAN_SERVER_ROOT=$INSTALL_ROOT P2WLAN_SERVER_CONFIG=$CONFIG_DIR P2WLAN_SERVER_DATA=$DATA_DIR p2wlan-server restart --service $ROLE"
echo 'Logs: sudo journalctl -u p2wlan-control.service -u p2wlan-relay.service -f'
echo 'Public Control access requires trusted HTTPS/WSS; Relay requires a client-trusted TLS certificate.'
if [ "$DEV_LOCALHOST" -eq 1 ]; then
  echo 'Local test only: the generated certificate expires in 24 hours and is not trusted by public clients.'
fi
