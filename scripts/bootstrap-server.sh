#!/usr/bin/env bash
# Keep the complete program inside main: a truncated curl pipe cannot execute
# package-manager changes before Bash has received the entire function body.
set -euo pipefail

main() {
  umask 077
  BOOT_REPO=${P2WLAN_REPO:-yhan-sun/p2wlan}
  BOOT_VERSION=${P2WLAN_SERVER_VERSION:-}
  BOOT_METHOD=
  BOOT_INTERACTIVE=0
  [ "$#" -ne 0 ] || BOOT_INTERACTIVE=1
  BOOT_INSTALL_DEPS=0
  BOOT_DRY_RUN=0
  BOOT_FORWARD=(--repo "$BOOT_REPO")
  BOOT_TMP_DIR=
  BOOT_DOCKER_OPTIONS=0
  BOOT_NATIVE_OPTIONS=0
  BOOT_NO_START=0

  die() { echo "bootstrap-server: $*" >&2; exit 1; }
  usage() {
    cat <<'HELP'
P2WLAN complete native/systemd or Docker server bootstrap

One-line interactive deployment (no checkout required):
  curl -fsSL https://raw.githubusercontent.com/yhan-sun/p2wlan/main/scripts/bootstrap-server.sh | sudo bash

Options:
  --method native|docker     installation method; interactive menu if omitted
  --version server-vX.Y.Z     exact server release; required for unattended use
  --interactive              select/confirm a release using /dev/tty
  --non-interactive          never prompt; requires --version
  --install-deps             allow missing prerequisites for the selected method
  --repo OWNER/REPO           release repository (default: yhan-sun/p2wlan)
  --dry-run                   download/verify the fixed bundle; no dependency install/deploy
  --dir DIR                  Docker persistent directory (default: /opt/p2wlan-docker)
  --root DIR --config-dir DIR --data-dir DIR
                             native program/configuration/database directories
  --relay-endpoint URL        public tls://host:port
  --tls-cert FILE --tls-key FILE
  --publish-host IP          Docker Relay host bind address (Docker only)
  --control-port PORT        internal Control port (default: 18080)
  --metrics-port PORT        loopback Relay readiness port (default: 18082)
  --no-start                 prepare deployment without starting/restarting services
  --start                    explicitly start native services (native only)
  --wait-timeout SECONDS     Docker health deadline (10-600, default: 90)
  --dev-localhost             isolated loopback test certificate
  -h, --help                 show this help

Fresh-host dependency installation supports Ubuntu 22.04/24.04/26.04 and
Debian 12/13, amd64/arm64, with systemd. Native installation prepares only
native prerequisites and never installs or invokes Docker. Existing prepared
Linux environments can be reused. Public use requires a trusted Relay
certificate and a Control HTTPS/WSS reverse proxy. Unattended deployments
should specify --method; its compatibility default is docker.
HELP
  }
  value() { [ "$#" -ge 2 ] && [ -n "$2" ] && [[ "$2" != --* ]] || die "$1 requires a value"; }
  prompt() {
    local variable=$1 label=$2 default=${3:-} reply
    printf '%s%s: ' "$label" "${default:+ [$default]}" >&3
    IFS= read -r reply <&3 || die 'terminal input ended; installation cancelled'
    printf -v "$variable" '%s' "${reply:-$default}"
  }
  valid_version() { [[ "$1" =~ ^server-v[A-Za-z0-9._-]+$ ]] || die 'version must be a fixed server-vX.Y.Z tag'; }
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --version) value "$@"; BOOT_VERSION=$2; shift 2 ;;
      --method) value "$@"; BOOT_METHOD=$2; shift 2 ;;
      --repo) value "$@"; BOOT_REPO=$2; shift 2 ;;
      --interactive) BOOT_INTERACTIVE=1; shift ;;
      --non-interactive) BOOT_INTERACTIVE=0; shift ;;
      --install-deps) BOOT_INSTALL_DEPS=1; shift ;;
      --dry-run) BOOT_DRY_RUN=1; shift ;;
      --dir|--publish-host|--wait-timeout)
        value "$@"; BOOT_FORWARD+=("$1" "$2"); BOOT_DOCKER_OPTIONS=1; shift 2 ;;
      --root|--config-dir|--data-dir)
        value "$@"; BOOT_FORWARD+=("$1" "$2"); BOOT_NATIVE_OPTIONS=1; shift 2 ;;
      --relay-endpoint|--tls-cert|--tls-key|--control-port|--metrics-port)
        value "$@"; BOOT_FORWARD+=("$1" "$2"); shift 2 ;;
      --start) BOOT_FORWARD+=("$1"); BOOT_NATIVE_OPTIONS=1; shift ;;
      --no-start) BOOT_FORWARD+=("$1"); BOOT_NO_START=1; shift ;;
      --dev-localhost) BOOT_FORWARD+=("$1"); shift ;;
      -h|--help) usage; return 0 ;;
      *) die "unknown option: $1" ;;
    esac
  done
  [[ "$BOOT_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die 'repo must be OWNER/REPO'
  BOOT_FORWARD[1]=$BOOT_REPO
  [ -z "$BOOT_VERSION" ] || valid_version "$BOOT_VERSION"
  case "$BOOT_METHOD" in ''|native|docker) ;; *) die 'method must be native or docker' ;; esac
  [ "$BOOT_INTERACTIVE" -eq 1 ] || [ -n "$BOOT_VERSION" ] || die '--non-interactive requires --version; use --interactive to discover a server release'
  [ "$(uname -s)" = Linux ] || die 'server bootstrap requires Linux'
  case "$(uname -m)" in x86_64|amd64) BOOT_ARCH=amd64 ;; aarch64|arm64) BOOT_ARCH=arm64 ;; *) die 'supported architectures: amd64 and arm64' ;; esac
  [ "$BOOT_DRY_RUN" -eq 1 ] || [ "$(id -u)" -eq 0 ] || die 'run as root, or pipe this script to sudo bash'
  if [ "$BOOT_INTERACTIVE" -eq 1 ]; then
    { exec 3<>/dev/tty; } 2>/dev/null || die 'interactive deployment requires a terminal; use --non-interactive --version TAG'
    printf '\nP2WLAN 一键安装向导\n阶段一：选择安装方式\n' >&3
    if [ -z "$BOOT_METHOD" ]; then
      printf '  1) 直接安装（Linux + systemd，不需要 Docker）\n  2) Docker 部署（Docker Compose）\n  0) 取消并退出\n' >&3
      while [ -z "$BOOT_METHOD" ]; do
        prompt method_choice '安装方式' 2
        case "$method_choice" in
          1) BOOT_METHOD=native ;;
          2) BOOT_METHOD=docker ;;
          0) printf '安装已取消。\n' >&3; return 0 ;;
          *) printf '请输入 1、2 或 0。\n' >&3 ;;
        esac
      done
    fi
    printf '已选择：%s\n\n阶段二：检测系统与准备所选方式的运行环境\n' "$BOOT_METHOD" >&3
  fi
  BOOT_METHOD=${BOOT_METHOD:-docker}
  if [ "$BOOT_METHOD" = native ]; then
    [ "$BOOT_DOCKER_OPTIONS" -eq 0 ] || die '--dir, --publish-host and --wait-timeout apply only to Docker; use --root/--config-dir/--data-dir for native installation'
    if [ "$BOOT_DRY_RUN" -eq 0 ]; then
      command -v systemctl >/dev/null 2>&1 && [ -d "${P2WLAN_SYSTEMD_DIR:-/run/systemd/system}" ] || die 'native installation requires a running systemd host'
    fi
  else
    [ "$BOOT_NATIVE_OPTIONS" -eq 0 ] || die '--root, --config-dir, --data-dir and --start apply only to native installation'
    case "${DOCKER_HOST:-unix://local}" in unix://*) ;; *) die 'a local Docker Engine is required; remote DOCKER_HOST is not supported' ;; esac
  fi
  BOOT_TMP_DIR=$(mktemp -d /tmp/p2wlan-bootstrap.XXXXXX)
  cleanup() {
    local result=$?
    trap - EXIT
    [ -z "${BOOT_TMP_DIR:-}" ] || rm -rf -- "$BOOT_TMP_DIR"
    exit "$result"
  }
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  need_base=0
  base_prerequisites=(python3 curl)
  [ "$BOOT_METHOD" != native ] || base_prerequisites+=(tar openssl useradd sha256sum)
  for prerequisite in "${base_prerequisites[@]}"; do
    command -v "$prerequisite" >/dev/null 2>&1 || need_base=1
  done
  need_engine=0
  need_compose=0
  compose_help=
  if [ "$BOOT_METHOD" = docker ]; then
    command -v docker >/dev/null 2>&1 || need_engine=1
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
      compose_help=$(docker compose up --help 2>/dev/null || true)
    fi
    [[ "$compose_help" == *--wait* && "$compose_help" == *--wait-timeout* ]] || need_compose=1
  fi
  need_docker=0
  [ "$need_engine" -eq 0 ] && [ "$need_compose" -eq 0 ] || need_docker=1
  if [ "$BOOT_DRY_RUN" -eq 0 ] && { [ "$need_base" -eq 1 ] || [ "$need_docker" -eq 1 ]; }; then
    os_file=${P2WLAN_BOOTSTRAP_OS_RELEASE:-/etc/os-release}
    [ -f "$os_file" ] || die "cannot identify Linux distribution; prepare the $BOOT_METHOD prerequisites manually"
    os_value() { awk -F= -v key="$1" '$1 == key { v=substr($0,index($0,"=")+1); gsub(/^"|"$/, "", v); print v; exit }' "$os_file"; }
    distro=$(os_value ID)
    distro_version=$(os_value VERSION_ID)
    codename=$(os_value VERSION_CODENAME)
    [ "$distro" != ubuntu ] || codename=${codename:-$(os_value UBUNTU_CODENAME)}
    case "$distro:$distro_version:$codename" in
      ubuntu:22.04:jammy|ubuntu:24.04:noble|ubuntu:26.04:resolute|debian:12:bookworm|debian:13:trixie) ;;
      *) die "automatic dependencies support Ubuntu 22.04/24.04/26.04 and Debian 12/13; prepare the selected $BOOT_METHOD prerequisites on this system first" ;;
    esac
    command -v apt-get >/dev/null 2>&1 || die 'apt-get is required on supported fresh hosts'
    command -v systemctl >/dev/null 2>&1 && [ -d "${P2WLAN_SYSTEMD_DIR:-/run/systemd/system}" ] || die 'automatic environment preparation requires a running systemd host'
    if [ "$need_docker" -eq 1 ]; then
      # Never remove or replace another container runtime to make installation work.
      for package in docker.io docker-compose docker-compose-v2 docker-buildx docker-doc podman-docker containerd runc; do
        if command -v dpkg-query >/dev/null 2>&1 && [ "$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true)" = installed ]; then
          die "existing package $package conflicts with Docker CE; preserve that runtime and install a compatible Compose plugin explicitly"
        fi
      done
    fi
    if [ "$BOOT_INSTALL_DEPS" -eq 0 ] && [ "$BOOT_INTERACTIVE" -eq 1 ]; then
      printf '\n所选 %s 方式缺少运行依赖。\n  1) 安装缺失依赖\n  0) 取消并退出\n' "$BOOT_METHOD" >&3
      while [ "$BOOT_INSTALL_DEPS" -eq 0 ]; do
        prompt answer '请选择' 1
        case "$answer" in
          1|y|Y|yes) BOOT_INSTALL_DEPS=1 ;;
          0|n|N|no) echo '安装已取消。' >&3; return 0 ;;
          *) printf '请输入 1 安装，或 0 退出。\n' >&3 ;;
        esac
      done
    fi
    [ "$BOOT_INSTALL_DEPS" -eq 1 ] || die 'missing prerequisites; pass --install-deps to allow dependency installation'
    apt-get update
    if [ "$need_base" -eq 1 ]; then
      base_packages=(ca-certificates curl python3)
      [ "$BOOT_METHOD" != native ] || base_packages+=(tar openssl passwd coreutils)
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove --no-install-recommends "${base_packages[@]}"
    fi
    if [ "$need_docker" -eq 1 ]; then
      arch=$(dpkg --print-architecture)
      case "$arch" in amd64|arm64) ;; *) die 'Docker apt architecture must be amd64 or arm64' ;; esac
      # Preserve an existing repository configuration. Fresh hosts receive the
      # documented Docker apt repository, scoped to its dedicated signing key.
      if [ ! -f /etc/apt/sources.list.d/docker.sources ] && [ ! -f /etc/apt/sources.list.d/docker.list ]; then
        curl -fSL --retry 3 --connect-timeout 15 --max-time 60 \
          "https://download.docker.com/linux/$distro/gpg" -o "$BOOT_TMP_DIR/docker.asc"
        install -d -m 0755 /etc/apt/keyrings /etc/apt/sources.list.d
        install -m 0644 "$BOOT_TMP_DIR/docker.asc" /etc/apt/keyrings/docker.asc
        cat > "$BOOT_TMP_DIR/docker.sources" <<SOURCES
Types: deb
URIs: https://download.docker.com/linux/$distro
Suites: $codename
Components: stable
Architectures: $arch
Signed-By: /etc/apt/keyrings/docker.asc
SOURCES
        install -m 0644 "$BOOT_TMP_DIR/docker.sources" /etc/apt/sources.list.d/docker.sources
      fi
      apt-get update
      if [ "$need_engine" -eq 1 ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        systemctl enable --now docker
      else
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove --no-install-recommends docker-compose-plugin
      fi
    fi
  fi
  command -v python3 >/dev/null 2>&1 && command -v curl >/dev/null 2>&1 || die 'Python 3 and curl are required; dry-run never installs prerequisites'
  if [ "$BOOT_DRY_RUN" -eq 0 ] && [ "$BOOT_METHOD" = docker ]; then
    command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 || die 'Docker Compose is unavailable after dependency preparation'
    python3 - "${P2WLAN_SYSTEMD_DIR:-/run/systemd/system}" <<'PY_ENGINE'
from pathlib import Path
import shutil
import subprocess
import sys

def command(arguments, timeout=30):
    try:
        return subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        sys.exit('bootstrap-server: Docker preparation command failed or timed out')

context = command(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'])
if context.returncode or not context.stdout.strip().startswith('unix://'):
    sys.exit('bootstrap-server: choose a local unix Docker context before deployment')
if command(['docker', 'info']).returncode:
    if (shutil.which('systemctl') and Path(sys.argv[1]).is_dir()
            and command(['systemctl', 'cat', 'docker.service']).returncode == 0):
        if command(['systemctl', 'start', 'docker'], timeout=120).returncode:
            sys.exit('bootstrap-server: failed to start the existing Docker service')
    if command(['docker', 'info']).returncode:
        sys.exit('bootstrap-server: Docker Engine is unavailable; check its service')
PY_ENGINE
  fi

  cat > "$BOOT_TMP_DIR/verify.py" <<'PY'
import collections
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile

DOCKER_ASSETS = {'p2wlan-server-docker.tar.gz', 'p2wlan-server-docker.tar.gz.sha256', 'SERVER-IMAGE.json', 'SERVER-IMAGE.json.sha256'}

def required_assets(method, arch):
    if method == 'native':
        name = f'p2wlan-server-linux-{arch}.tar.gz'
        return {name, name + '.sha256'}
    return DOCKER_ASSETS

def tag(value):
    return isinstance(value, str) and re.fullmatch(r'server-v[A-Za-z0-9._-]+', value)

def select(paths, method, arch):
    eligible = []
    required = required_assets(method, arch)
    for path in paths:
        releases = json.loads(Path(path).read_text())
        if not isinstance(releases, list):
            raise ValueError('release API did not return a release list')
        for release in releases:
            if not isinstance(release, dict) or release.get('draft') is not False or release.get('prerelease') is not False or not tag(release.get('tag_name')):
                continue
            assets = release.get('assets', [])
            names = collections.Counter(asset.get('name') for asset in assets if isinstance(asset, dict))
            uploaded = {asset.get('name') for asset in assets if isinstance(asset, dict) and asset.get('state') == 'uploaded'}
            if not required.issubset(uploaded) or any(names[name] != 1 for name in required):
                continue
            published = release.get('published_at')
            if not isinstance(published, str):
                continue
            try:
                stamp = datetime.datetime.fromisoformat(published.replace('Z', '+00:00'))
            except ValueError:
                continue
            if stamp.tzinfo is None:
                continue
            eligible.append((stamp, release['tag_name']))
    if not eligible:
        raise ValueError(f'no stable server release with complete {method} deployment assets was found; publish a compatible server release or pass a fixed --version')
    # Release tags are unique; deduplicate pages in case publication moved
    # pagination while the bounded catalog was being downloaded.
    ordered, seen = [], set()
    for stamp, version in sorted(eligible, reverse=True):
        if version not in seen:
            ordered.append({'version': version, 'published_at': stamp.isoformat()})
            seen.add(version)
    return ordered[:15]

def hash_stream(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(chunk)
    return digest.hexdigest()

def verify_native(archive, output, requested, arch):
    binaries = {'p2wlan-control', 'p2wlan-relay', 'p2wlan-config', 'p2wlan-db'}
    executables = binaries | {'p2wlan-server', 'install-server.sh', 'deploy-server.sh'}
    required = executables | {'BUILD-METADATA.txt', 'SHA256SUMS'}
    with tarfile.open(archive, 'r:gz') as bundle:
        members, total = {}, 0
        for member in bundle:
            limit = 256 * 1024 * 1024 if member.name in binaries else 2 * 1024 * 1024
            if (member.name not in required or member.name in members or not member.isfile()
                    or member.size > limit or (member.name in executables and not member.mode & 0o111)):
                raise ValueError('native archive requires nine unique bounded regular release members')
            total += member.size
            if total > 512 * 1024 * 1024:
                raise ValueError('native deployment exceeds its expanded size limit')
            members[member.name] = member
        if set(members) != required:
            raise ValueError('native deployment archive is incomplete')
        metadata = {}
        for line in bundle.extractfile('BUILD-METADATA.txt').read().decode().splitlines():
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            if key in ('version', 'commit', 'arch') and key in metadata:
                raise ValueError('duplicate native archive identity field')
            metadata[key] = value
        if metadata.get('version') != requested or metadata.get('arch') != arch:
            raise ValueError('native archive version or architecture does not match selection')
        if not re.fullmatch(r'[a-f0-9]{40}', metadata.get('commit', '')):
            raise ValueError('native archive requires an exact source SHA')
        sums = {}
        for line in bundle.extractfile('SHA256SUMS').read().decode().splitlines():
            entry = re.fullmatch(r'([a-fA-F0-9]{64}) [ *]([A-Za-z0-9.-]+)', line)
            if not entry or entry[2] in sums:
                raise ValueError('invalid native binary checksum manifest')
            sums[entry[2]] = entry[1].lower()
        if set(sums) != binaries:
            raise ValueError('native binary checksum manifest is incomplete')
        output.mkdir(mode=0o700)
        for name, member in members.items():
            target = output / name
            digest = hashlib.sha256()
            with bundle.extractfile(member) as source, target.open('xb') as destination:
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    digest.update(chunk)
                    destination.write(chunk)
            if name in sums and digest.hexdigest() != sums[name]:
                raise ValueError('native binary checksum mismatch: ' + name)
            target.chmod(0o755 if name in executables else 0o600)
    print('Verified native ' + requested + ' source=' + metadata['commit'] + ' arch=' + arch)

def verify(archive, output, requested, method, arch):
    archive, output = Path(archive), Path(output)
    limit = 256 * 1024 * 1024 if method == 'native' else 16 * 1024 * 1024
    if archive.stat().st_size > limit:
        raise ValueError('deployment archive exceeds its size limit')
    checksum = archive.with_name(archive.name + '.sha256').read_text().strip()
    match = re.fullmatch(r'([a-fA-F0-9]{64}) [ *]' + re.escape(archive.name), checksum)
    with archive.open('rb') as source:
        digest = hash_stream(source)
    if not match or digest != match[1].lower():
        raise ValueError('deployment archive checksum mismatch')
    if method == 'native':
        verify_native(archive, output, requested, arch)
        return
    limits = {'install-server-docker.sh': 2 * 1024 * 1024, 'compose.production.yml': 1024 * 1024,
              'SERVER-IMAGE.json': 64 * 1024, 'SERVER-IMAGE.json.sha256': 1024}
    content = {}
    with tarfile.open(archive, 'r:gz') as bundle:
        for member in bundle:
            if member.name not in limits or member.name in content or not member.isfile() or member.size > limits[member.name]:
                raise ValueError('Docker archive must contain only four unique bounded regular deployment members')
            content[member.name] = bundle.extractfile(member).read()
    if set(content) != set(limits):
        raise ValueError('Docker deployment archive is incomplete')
    manifest_bytes = content['SERVER-IMAGE.json']
    checksum = content['SERVER-IMAGE.json.sha256'].decode().strip()
    match = re.fullmatch(r'([a-fA-F0-9]{64}) [ *]SERVER-IMAGE.json', checksum)
    if not match or hashlib.sha256(manifest_bytes).hexdigest() != match[1].lower():
        raise ValueError('image manifest checksum mismatch')
    metadata = json.loads(manifest_bytes)
    if metadata.get('schema_version') != 1 or metadata.get('version') != requested:
        raise ValueError('Docker archive does not match the selected server version')
    if not re.fullmatch(r'[a-f0-9]{40}', metadata.get('source_sha', '')):
        raise ValueError('Docker archive requires an exact source SHA')
    image = metadata.get('image', '')
    if not re.fullmatch(r'[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}', image) or '//' in image:
        raise ValueError('Docker archive requires an immutable image digest')
    if metadata.get('digest') != image.split('@', 1)[1] or metadata.get('platforms') != ['linux/amd64', 'linux/arm64']:
        raise ValueError('Docker image digest/platform metadata is inconsistent')
    output.mkdir(mode=0o700)
    for name, data in content.items():
        path = output / name
        path.write_bytes(data)
        path.chmod(0o755 if name.endswith('.sh') else 0o600)
    print('Verified ' + requested + ' source=' + metadata['source_sha'] + ' image=' + image)

try:
    if sys.argv[1] == 'count':
        data = json.loads(Path(sys.argv[2]).read_text())
        if not isinstance(data, list):
            raise ValueError('release API did not return a release list')
        print(len(data))
    elif sys.argv[1] == 'select':
        print(select(sys.argv[4:], sys.argv[2], sys.argv[3])[0]['version'])
    elif sys.argv[1] == 'catalog':
        print(json.dumps(select(sys.argv[4:], sys.argv[2], sys.argv[3])))
    elif sys.argv[1] == 'show':
        for index, release in enumerate(json.loads(Path(sys.argv[2]).read_text()), 1):
            print(f"  {index}) {release['version']}  发布于 {release['published_at'][:10]}")
    elif sys.argv[1] == 'choose':
        catalog = json.loads(Path(sys.argv[2]).read_text())
        index = int(sys.argv[3])
        if not 1 <= index <= len(catalog):
            raise ValueError('release choice is outside the displayed list')
        print(catalog[index - 1]['version'])
    elif sys.argv[1] == 'verify':
        verify(*sys.argv[2:])
    else:
        raise ValueError('unknown verification action')
except (OSError, ValueError, TypeError, AttributeError, tarfile.TarError, UnicodeError) as error:
    sys.exit('bootstrap-server: ' + str(error))
PY

  if [ -z "$BOOT_VERSION" ]; then
    printf '\n阶段三：选择服务端版本\n正在查找带完整 %s 部署包的正式版本…\n' "$BOOT_METHOD" >&3
    pages=()
    for page in 1 2 3 4 5; do
      result="$BOOT_TMP_DIR/releases-$page.json"
      curl -fSL --retry 2 --connect-timeout 15 --max-time 60 --max-filesize 8388608 \
        -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' \
        "https://api.github.com/repos/$BOOT_REPO/releases?per_page=100&page=$page" -o "$result"
      pages+=("$result")
      count=$(python3 "$BOOT_TMP_DIR/verify.py" count "$result")
      [ "$count" -ge 100 ] || break
    done
    catalog="$BOOT_TMP_DIR/catalog.json"
    python3 "$BOOT_TMP_DIR/verify.py" catalog "$BOOT_METHOD" "$BOOT_ARCH" "${pages[@]}" > "$catalog"
    python3 "$BOOT_TMP_DIR/verify.py" show "$catalog" >&3
    printf '  m) 手动输入其他 server-v 版本\n  0) 取消并退出\n' >&3
    while [ -z "$BOOT_VERSION" ]; do
      prompt choice '请选择版本编号' 1
      case "$choice" in
        0) printf '安装已取消。\n' >&3; return 0 ;;
        m|M)
          prompt manual_version '请输入固定版本（server-vX.Y.Z）'
          if [[ "$manual_version" =~ ^server-v[A-Za-z0-9._-]+$ ]]; then
            BOOT_VERSION=$manual_version
          else
            printf '版本格式不正确，请重新选择或输入。\n' >&3
          fi
          ;;
        *)
          if [[ "$choice" =~ ^[0-9]{1,2}$ ]] && selected=$(python3 "$BOOT_TMP_DIR/verify.py" choose "$catalog" "$choice" 2>/dev/null); then
            BOOT_VERSION=$selected
          else
            printf '请选择列表中的编号、m 或 0。\n' >&3
          fi
          ;;
      esac
    done
    printf '已选择固定版本：%s\n' "$BOOT_VERSION" >&3
  elif [ "$BOOT_INTERACTIVE" -eq 1 ]; then
    printf '\n阶段三：使用指定服务端版本 %s\n' "$BOOT_VERSION" >&3
  fi
  echo "阶段四：下载并校验固定发布包 $BOOT_VERSION ($BOOT_METHOD)"
  asset=p2wlan-server-docker.tar.gz
  max_size=16777216
  download_timeout=120
  if [ "$BOOT_METHOD" = native ]; then
    asset="p2wlan-server-linux-$BOOT_ARCH.tar.gz"
    max_size=268435456
    download_timeout=300
  fi
  base="https://github.com/$BOOT_REPO/releases/download/$BOOT_VERSION"
  for name in "$asset" "$asset.sha256"; do
    curl -fSL --retry 3 --connect-timeout 15 --max-time "$download_timeout" --max-filesize "$max_size" \
      "$base/$name" -o "$BOOT_TMP_DIR/$name"
  done
  python3 "$BOOT_TMP_DIR/verify.py" verify "$BOOT_TMP_DIR/$asset" "$BOOT_TMP_DIR/deployment" "$BOOT_VERSION" "$BOOT_METHOD" "$BOOT_ARCH"
  if [ "$BOOT_DRY_RUN" -eq 1 ]; then
    echo "Verified $BOOT_METHOD deployment bundle; would configure and deploy the selected release."
    return 0
  fi
  if [ "$BOOT_INTERACTIVE" -eq 1 ]; then
    BOOT_FORWARD=(--interactive "${BOOT_FORWARD[@]}")
  else
    BOOT_FORWARD=(--non-interactive "${BOOT_FORWARD[@]}")
  fi
  echo 'Starting the verified release installer. Existing deployment data and credentials are preserved.'
  # Do not exec: keep the EXIT cleanup active for both successful deployments
  # and installers that fail their health checks.
  if [ "$BOOT_METHOD" = native ]; then
    installer_help=$(bash "$BOOT_TMP_DIR/deployment/install-server.sh" --help) || die 'cannot inspect the verified native installer'
    for required_option in --interactive --control-port --metrics-port --no-start; do
      [[ "$installer_help" == *"$required_option"* ]] || die 'this native server release predates guided installation; select a newer compatible server release'
    done
    [ "$BOOT_INSTALL_DEPS" -eq 0 ] || BOOT_FORWARD+=(--install-deps)
    if [ "$BOOT_INTERACTIVE" -eq 0 ] && [ "$BOOT_NO_START" -eq 0 ]; then
      BOOT_FORWARD+=(--start)
    fi
    bash "$BOOT_TMP_DIR/deployment/install-server.sh" --archive "$BOOT_TMP_DIR/$asset" \
      --version "$BOOT_VERSION" "${BOOT_FORWARD[@]}"
  else
    bash "$BOOT_TMP_DIR/deployment/install-server-docker.sh" \
      --manifest "$BOOT_TMP_DIR/deployment/SERVER-IMAGE.json" "${BOOT_FORWARD[@]}"
  fi
}

main "$@"
