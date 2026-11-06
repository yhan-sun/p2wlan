#!/usr/bin/env bash
set -euo pipefail
command -v python3 >/dev/null 2>&1 || { echo 'install-server-docker: Python 3 is required' >&2; exit 1; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 - "$SCRIPT_DIR" "$@" <<'PY'
"""Build verified server source locally or install a fixed server image."""
import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
import urllib.parse

os.umask(0o077)
script_dir = Path(sys.argv[1])
parser = argparse.ArgumentParser(prog='install-server-docker.sh', description='P2WLAN Docker installer (local Linux Docker Engine + Compose)')
source = parser.add_mutually_exclusive_group()
source.add_argument('--source', help='verified SERVER-SOURCE.json bundle directory; build locally with Compose')
source.add_argument('--version', help='fixed server-vX.Y.Z release; downloads its image digest manifest')
source.add_argument('--image', help='released image pinned as registry/repository@sha256:DIGEST')
source.add_argument('--manifest', help='local checksum-verified SERVER-IMAGE.json from a fixed release bundle')
source.add_argument('--local-image', help='local sha256:IMAGE_ID; isolated --dev-localhost tests only')
interaction = parser.add_mutually_exclusive_group()
interaction.add_argument('--interactive', action='store_true')
interaction.add_argument('--non-interactive', action='store_true')
parser.add_argument('--repo', default='yhan-sun/p2wlan')
parser.add_argument('--dir', help='private persistent deployment directory (default: /opt/p2wlan-docker)')
parser.add_argument('--relay-endpoint')
parser.add_argument('--tls-cert')
parser.add_argument('--tls-key')
parser.add_argument('--control-port', type=int, help='internal Control port (default: 18080)')
parser.add_argument('--metrics-port', type=int, help='internal Relay readiness port (default: 18082)')
parser.add_argument('--publish-host', help='Relay host bind IP; public 0.0.0.0, test 127.0.0.1')
parser.add_argument('--dev-localhost', action='store_true')
parser.add_argument('--no-start', action='store_true', help='prepare deployment without starting/recreating services')
parser.add_argument('--dry-run', action='store_true', help='show a plan without Docker, downloads or filesystem changes')
parser.add_argument('--wait-timeout', type=int, default=90, help='Compose health deadline, 10-600 seconds')
args = parser.parse_args(sys.argv[2:])
interactive = args.interactive or len(sys.argv) == 2

class InstallError(Exception):
    pass

def fail(message):
    raise InstallError(message)

def run(arguments, *, timeout=30, capture=True, env=None):
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE if capture else None,
                                stderr=subprocess.PIPE if capture else None,
                                text=True, timeout=timeout, env=env, check=False)
    except subprocess.TimeoutExpired:
        fail('command timed out: ' + ' '.join(arguments[:3]))
    except OSError:
        fail('cannot execute ' + arguments[0])
    if result.returncode:
        # Docker output can include environment/configuration. Keep credentials
        # out of installer output; status/logs remain an explicit operator step.
        fail('command failed: ' + ' '.join(arguments[:3]))
    return result.stdout.strip() if capture else ''

def read_env(path, content=None):
    values = {}
    allowed = {'P2WLAN_UID', 'P2WLAN_GID', 'CONTROL_PORT', 'RELAY_PORT', 'METRICS_PORT',
               'RELAY_PUBLISH_HOST', 'P2WLAN_IMAGE', 'P2WLAN_CONFIG_DIR', 'COMPOSE_PROJECT_NAME',
               'P2WLAN_VERSION', 'P2WLAN_COMMIT', 'P2WLAN_DEV_LOCALHOST',
               'P2WLAN_INSTALL_MODE', 'P2WLAN_SOURCE_DIR', 'P2WLAN_BUILD_IMAGE'}
    for line in (path.read_text() if content is None else content.decode()).splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or key not in allowed or key in values:
            fail('invalid deployment environment file')
        if any(c in value for c in '\r\n\x00'):
            fail('invalid deployment environment value')
        values[key] = value
    if values.get('P2WLAN_INSTALL_MODE', 'image') not in ('source', 'image'):
        fail('invalid saved installation mode')
    return values

def write_env(path, values):
    if any(any(character in value for character in '\r\n\x00') for value in values.values()):
        fail('deployment environment values cannot contain newlines')
    path.write_text(''.join(f'{key}={value}\n' for key, value in values.items()))
    path.chmod(0o600)

def protected(path, *, directory=False):
    info = path.lstat()
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or info.st_mode & 0o077 or (not directory and info.st_nlink != 1)):
        fail('private regular configuration files and directories are required: ' + str(path))
    return info

def prompt(terminal, label, default=''):
    terminal.write(label + (f' [{default}]' if default else '') + ': ')
    terminal.flush()
    reply = terminal.readline()
    if not reply:
        fail('terminal input ended; installation cancelled')
    value = reply.strip() or default
    if value.lower() in ('cancel', '取消'):
        fail('installation cancelled')
    return value

def ask(terminal, label, default, validate):
    while True:
        value = prompt(terminal, label, str(default) if default is not None else '')
        try:
            return validate(value)
        except InstallError as error:
            terminal.write('输入无效：' + str(error) + '。请重试，或输入“取消”。\n')
        except (OSError, ValueError):
            terminal.write('输入格式不正确或路径不可读取。请重试，或输入“取消”。\n')

def choice(terminal, label, default, choices):
    def validate(value):
        if value not in choices:
            fail('请选择 ' + '/'.join(choices))
        return value
    return ask(terminal, label, default, validate)

def deployment_directory(raw):
    if (not raw.startswith('/') or not re.fullmatch(r'/[A-Za-z0-9_./-]+', raw)
            or '..' in Path(raw).parts or '//' in raw or Path(raw) == Path('/')):
        fail('deployment directory must be a safe absolute path')
    directory = Path(raw)
    if directory.is_symlink():
        fail('deployment directory cannot be a symlink')
    directory = directory.resolve()
    if directory.exists():
        owner = protected(directory, directory=True)
        if owner.st_uid != os.geteuid():
            fail('deployment directory must belong to the installer user; run with its owner')
    return directory

def port_number(value, used=()):
    if not str(value).isascii() or not str(value).isdigit() or not 1 <= int(value) <= 65535:
        fail('端口必须是 1-65535 的整数')
    number = int(value)
    if number in used:
        fail('Control、Relay 和 metrics 端口不能重复')
    return number

def relay_host(value, dev=False):
    value = value.strip('[]')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value):
            fail('请输入主机名或 IP，不含协议和端口')
        if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in value.split('.')):
            fail('主机名格式不正确')
        if dev and value.lower() != 'localhost':
            fail('本机测试的 Relay 主机必须是 localhost 或 loopback IP')
        return value.lower()
    if address.is_unspecified:
        fail('Relay 公告地址不能是通配地址')
    if dev and not address.is_loopback:
        fail('本机测试的 Relay 主机必须是 loopback IP')
    return address.compressed

def endpoint_parts(endpoint, dev=False):
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        host, port = parsed.hostname, parsed.port
    except (ValueError, TypeError):
        fail('Relay 地址必须是 tls://host:port，端口为 1-65535 的整数')
    if (parsed.scheme != 'tls' or parsed.username is not None or parsed.password is not None
            or parsed.path or parsed.query or parsed.fragment or '?' in endpoint or '#' in endpoint
            or any(character in endpoint for character in '\r\n\t\x00') or not host or port is None):
        fail('Relay 地址必须是 tls://host:port，不含路径或凭据')
    return relay_host(host, dev), port_number(port)

def tls_path(value):
    try:
        if any(character in value for character in '\r\n\x00'):
            fail('PEM 文件路径不能包含控制字符')
        path = Path(value).expanduser()
        if path.is_file() and os.access(path, os.R_OK):
            return str(path.resolve())
    except (OSError, RuntimeError, ValueError):
        pass
    fail('请输入存在且可读取的 PEM 文件路径')

def bind_address(value, dev=False):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        fail('Relay 绑定地址必须是 IPv4 或 IPv6 地址')
    if dev and not address.is_loopback:
        fail('本机测试的 Relay 绑定 IP 必须是 loopback 地址')
    return address.compressed

def saved_deployment(directory):
    config, environment = directory / 'config', directory / '.env'
    if not (config.exists() or environment.exists()):
        return None
    if not config.is_dir() or not environment.is_file():
        fail('partial deployment found; existing configuration was preserved')
    protected(config, directory=True)
    protected(environment)
    snapshot = environment.read_bytes()
    settings = read_env(environment, snapshot)
    if settings.get('P2WLAN_DEV_LOCALHOST') not in ('true', 'false'):
        fail('deployment test/production mode is missing from .env')
    for name in ('control.env', 'relay.env', 'tls.crt', 'tls.key'):
        protected(config / name)
    protected(config / 'data', directory=True)
    return settings, snapshot

def configure_new(terminal, plan, edit=False):
    previous_dev = plan['dev']
    supplied_tls = bool(args.relay_endpoint and args.tls_cert and args.tls_key)
    terminal.write('\n[2/7] 部署模式\n  1) 公网部署（需要已有可信证书和 HTTPS/WSS 反向代理）\n  2) 本机测试（24 小时测试证书，仅 loopback）\n')
    if edit or not (args.dev_localhost or supplied_tls):
        mode = choice(terminal, '部署模式', '2' if plan['dev'] else '1', ('2',) if args.local_image else ('1', '2'))
        plan['dev'] = mode == '2'
    if previous_dev != plan['dev'] and plan['publish_host'] == ('127.0.0.1' if previous_dev else '0.0.0.0'):
        plan['publish_host'] = None
    terminal.write('已选择：' + ('本机测试\n' if plan['dev'] else '公网部署\n'))
    terminal.write('\n[3/7] Relay 公告地址\n')
    parts = None
    if plan['endpoint']:
        try:
            parts = endpoint_parts(plan['endpoint'], plan['dev'])
        except (InstallError, ValueError):
            if not edit and args.relay_endpoint:
                terminal.write('提供的 Relay 地址无效，请重新输入主机和端口。\n')
    if edit or not args.relay_endpoint or parts is None:
        host = ask(terminal, 'Relay主机（主机名或IP）', parts[0] if parts else ('localhost' if plan['dev'] else ''),
                   lambda value: relay_host(value, plan['dev']))
        relay_port = ask(terminal, 'Relay端口', parts[1] if parts else 18081, port_number)
        plan['endpoint'] = 'tls://' + ('[' + host + ']' if ':' in host else host) + ':' + str(relay_port)
    else:
        relay_port = parts[1]
    terminal.write('Relay 地址：' + plan['endpoint'] + '\n')
    terminal.write('\n[4/7] TLS 证书\n')
    if plan['dev']:
        plan['tls_cert'] = plan['tls_key'] = None
        terminal.write('使用仅本机测试证书；不会配置公网 HTTPS 或签发可信证书。\n')
    else:
        for field, label, supplied in (('tls_cert', '证书链路径', args.tls_cert), ('tls_key', '私钥路径', args.tls_key)):
            if edit or not supplied:
                plan[field] = ask(terminal, label, plan[field], tls_path)
            else:
                try:
                    plan[field] = tls_path(supplied)
                except (InstallError, OSError, ValueError):
                    plan[field] = ask(terminal, label, supplied, tls_path)
    terminal.write('\n[5/7] 监听端口与 Relay 绑定\n')
    for field, label, supplied in (
        ('control_port', 'Control端口', args.control_port),
        ('metrics_port', 'metrics端口', args.metrics_port),
    ):
        used = (relay_port,) if field == 'control_port' else (relay_port, plan['control_port'])
        if edit or supplied is None or plan[field] in used:
            plan[field] = ask(terminal, label, plan[field], lambda value, used=used: port_number(value, used))
        else:
            plan[field] = port_number(plan[field], used)
    # Recheck after Control may have changed: metrics must use its final value.
    if plan['metrics_port'] == plan['control_port']:
        plan['metrics_port'] = ask(terminal, 'metrics端口', plan['metrics_port'],
                                   lambda value: port_number(value, (relay_port, plan['control_port'])))
    default_bind = plan['publish_host'] or ('127.0.0.1' if plan['dev'] else '0.0.0.0')
    if edit or not args.publish_host:
        plan['publish_host'] = ask(terminal, 'Relay绑定IP', default_bind, lambda value: bind_address(value, plan['dev']))
    else:
        plan['publish_host'] = bind_address(args.publish_host, plan['dev'])
    return plan

def validate_reference(image, local=False):
    pattern = r'sha256:[a-f0-9]{64}' if local else r'[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}'
    if not re.fullmatch(pattern, image or '') or '//' in image:
        fail('image must be pinned to an immutable SHA-256 digest')

def manifest(path, requested=None):
    checksum = path.with_name(path.name + '.sha256').read_text().strip()
    match = re.fullmatch(r'([a-fA-F0-9]{64}) [ *]SERVER-IMAGE.json', checksum)
    if not match or hashlib.sha256(path.read_bytes()).hexdigest() != match[1].lower():
        fail('image manifest checksum mismatch')
    data = json.loads(path.read_text())
    if data.get('schema_version') != 1 or not re.fullmatch(r'server-v[A-Za-z0-9._-]+', data.get('version', '')):
        fail('invalid server image manifest version')
    if requested and data['version'] != requested:
        fail('image manifest does not match requested version')
    if not re.fullmatch(r'[a-f0-9]{40}', data.get('source_sha', '')):
        fail('image manifest requires an exact source SHA')
    validate_reference(data.get('image'))
    return data

SOURCE_REQUIRED = {'server/Dockerfile', 'server/go.mod', 'server/go.sum', 'scripts/install-server-docker.sh',
                   'deploy/selfhost/compose.production.yml', 'deploy/selfhost/compose.build.yml'}
SOURCE_METADATA = {'SERVER-SOURCE.json', 'SERVER-SOURCE.json.sha256'}

def source_member(name):
    if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,512}', name)
            or str(PurePosixPath(name)) != name or name.startswith('/')
            or any(part in ('.', '..') for part in name.split('/')) or len(name.split('/')) > 32
            or not (name.startswith('server/') or name in SOURCE_REQUIRED)):
        fail('source manifest contains an unsupported relative path')
    return name

def source_read(root, name, limit, *, destination=None, capture=False):
    """Read via no-follow directory handles and fence each regular file read."""
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    descriptor = None
    writer = None
    try:
        parts = name.split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            fail('source files must be bounded regular files without hard links')
        if destination is not None:
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            writer = destination.open('xb')
        content = bytearray() if capture else None
        digest, length = hashlib.sha256(), 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            length += len(block)
            if length > limit:
                fail('source file exceeds its size limit')
            digest.update(block)
            if writer is not None:
                writer.write(block)
            if content is not None:
                content.extend(block)
        after = os.fstat(descriptor)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
        if identity(before) != identity(after) or length != before.st_size:
            fail('source file changed during verification')
        if writer is not None:
            writer.close()
            writer = None
            destination.chmod(0o700 if before.st_mode & 0o111 else 0o600)
        return bytes(content) if content is not None else None, digest.hexdigest(), length
    finally:
        if writer is not None:
            writer.close()
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)

def verified_source(raw, resources, *, copy=True, exact=False):
    root = Path(raw)
    if root.is_symlink() or not root.is_dir():
        fail('source directory must be a real directory')
    root = root.resolve()
    metadata_bytes, metadata_hash, _ = source_read(root, 'SERVER-SOURCE.json', 1024 * 1024, capture=True)
    checksum, _, _ = source_read(root, 'SERVER-SOURCE.json.sha256', 1024, capture=True)
    match = re.fullmatch(r'([a-fA-F0-9]{64}) [ *]SERVER-SOURCE.json', checksum.decode().strip())
    if not match or metadata_hash != match[1].lower():
        fail('source manifest checksum mismatch')
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail('source manifest contains duplicate keys')
            result[key] = value
        return result
    metadata = json.loads(metadata_bytes, object_pairs_hook=unique_object)
    if (not isinstance(metadata, dict) or metadata.get('schema_version') != 1 or metadata.get('context') != 'server'
            or not isinstance(metadata.get('version'), str) or not isinstance(metadata.get('source_sha'), str)
            or not re.fullmatch(r'server-v[A-Za-z0-9._-]+', metadata.get('version', ''))
            or not re.fullmatch(r'[a-f0-9]{40}', metadata.get('source_sha', ''))):
        fail('source manifest requires a fixed server version, source SHA and server context')
    files = metadata.get('files')
    if not isinstance(files, dict) or not 1 <= len(files) <= 4096 or not SOURCE_REQUIRED.issubset(files):
        fail('source manifest is missing required build files or exceeds its file count limit')
    for name, digest in files.items():
        source_member(name)
        if not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest):
            fail('source manifest contains an invalid file checksum')
    if exact:
        expected_files = set(files) | SOURCE_METADATA
        expected_directories = {str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent) != '.'}
        observed = set()
        for directory, folders, names in os.walk(root, followlinks=False):
            for name in folders:
                path = Path(directory) / name
                if path.is_symlink() or path.relative_to(root).as_posix() not in expected_directories:
                    fail('saved source directory contains unexpected directories or links')
            for name in names:
                relative = (Path(directory) / name).relative_to(root).as_posix()
                if relative not in expected_files:
                    fail('saved source directory contains unverified files')
                observed.add(relative)
        if observed != expected_files:
            fail('saved source directory is incomplete')
    snapshot = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix='p2wlan-source-'))) if copy else None
    total = len(metadata_bytes) + len(checksum)
    for name, digest in files.items():
        _, actual, size = source_read(root, name, min(64 * 1024 * 1024, 256 * 1024 * 1024 - total),
                                     destination=snapshot / name if snapshot is not None else None)
        if actual != digest:
            fail('source file checksum mismatch: ' + name)
        total += size
    if snapshot is not None:
        (snapshot / 'SERVER-SOURCE.json').write_bytes(metadata_bytes)
        (snapshot / 'SERVER-SOURCE.json.sha256').write_bytes(checksum)
    return dict(metadata=metadata, snapshot=snapshot, root=root, metadata_hash=metadata_hash)

def source_image(directory, commit):
    return 'p2wlan-' + hashlib.sha256(str(directory).encode()).hexdigest()[:12] + '-server:' + commit

def persist_source(directory, bundle, resources):
    parent = directory / 'sources'
    if parent.exists() or parent.is_symlink():
        owner = protected(parent, directory=True)
        if owner.st_uid != os.geteuid():
            fail('saved source parent must belong to the installer user')
    else:
        parent.mkdir(mode=0o700)
    target = parent / bundle['metadata']['source_sha']
    if target.exists() or target.is_symlink():
        owner = protected(target, directory=True)
        if owner.st_uid != os.geteuid():
            fail('saved source must belong to the installer user')
        saved = verified_source(target, resources, copy=False, exact=True)
        if saved['metadata_hash'] != bundle['metadata_hash']:
            fail('saved source SHA already has different release metadata')
        return target
    temporary = Path(tempfile.mkdtemp(prefix='.source-', dir=parent))
    try:
        shutil.copytree(bundle['snapshot'], temporary, dirs_exist_ok=True)
        temporary.rename(target)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return target

def install(resources):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repo):
        fail('repo must be OWNER/REPO')
    if args.version and not re.fullmatch(r'server-v[A-Za-z0-9._-]+', args.version):
        fail('version must be a fixed server-vX.Y.Z tag')
    terminal = None
    if interactive and not args.dry_run:
        try:
            terminal = io.TextIOWrapper(open('/dev/tty', 'r+b', buffering=0),
                                        encoding='utf-8', write_through=True)
        except OSError:
            fail('interactive setup requires a terminal; use --non-interactive with --version or --image')
        terminal.write('P2WLAN Docker 服务端安装向导；所有步骤可输入“取消”。\n\n[1/7] 部署目录\n')
    if terminal and args.dir is None:
        directory = ask(terminal, '部署目录', '/opt/p2wlan-docker', deployment_directory)
    else:
        directory = deployment_directory(args.dir or '/opt/p2wlan-docker')
        if terminal:
            terminal.write('部署目录：' + str(directory) + '\n')
    if not 10 <= args.wait_timeout <= 600:
        fail('wait timeout must be between 10 and 600 seconds')
    if args.local_image and not args.dev_localhost:
        fail('--local-image is restricted to --dev-localhost tests')
    if args.dev_localhost and (args.tls_cert or args.tls_key):
        fail('choose supplied TLS files or --dev-localhost')
    if args.image:
        validate_reference(args.image)
    if args.local_image:
        validate_reference(args.local_image, local=True)
    if args.publish_host:
        address = ipaddress.ip_address(args.publish_host)
        if args.dev_localhost and not address.is_loopback:
            fail('development Relay publication must remain loopback-only')
    config = directory / 'config'
    settings_path = directory / '.env'
    saved = saved_deployment(directory)
    existing = saved is not None
    settings, settings_snapshot = saved if existing else ({}, None)
    if existing:
        if args.dev_localhost and settings['P2WLAN_DEV_LOCALHOST'] != 'true':
            fail('existing production TLS is preserved; use a separate directory for local tests')
        if args.relay_endpoint or args.tls_cert or args.tls_key:
            fail('existing TLS and configuration are preserved; rotate them explicitly')
        for option, key in ((args.control_port, 'CONTROL_PORT'), (args.metrics_port, 'METRICS_PORT')):
            if option is not None and str(option) != settings.get(key):
                fail('existing ports are preserved; change deployment configuration explicitly')
        if args.publish_host and args.publish_host != settings.get('RELAY_PUBLISH_HOST'):
            fail('existing publication is preserved; edit .env explicitly to change it')
    else:
        settings = {}
    selection = bool(args.source or args.version or args.image or args.local_image or args.manifest)
    source_bundle = None
    expected = None
    if args.source:
        source_bundle = verified_source(args.source, resources, copy=not args.dry_run)
    elif not selection and existing and settings.get('P2WLAN_INSTALL_MODE') == 'source':
        stored_commit = settings.get('P2WLAN_COMMIT', '')
        stored_source = directory / 'sources' / stored_commit
        if (not re.fullmatch(r'[a-f0-9]{40}', stored_commit)
                or settings.get('P2WLAN_SOURCE_DIR') != str(stored_source)
                or settings.get('P2WLAN_BUILD_IMAGE') != source_image(directory, stored_commit)):
            fail('saved source deployment identity is invalid')
        source_bundle = verified_source(stored_source, resources, copy=not args.dry_run, exact=True)
        if (source_bundle['metadata']['version'] != settings.get('P2WLAN_VERSION')
                or source_bundle['metadata']['source_sha'] != stored_commit):
            fail('saved source identity does not match deployment settings')
    elif not selection and not existing and (script_dir.parent / 'SERVER-SOURCE.json').is_file():
        source_bundle = verified_source(script_dir.parent, resources, copy=not args.dry_run)
    if source_bundle is not None:
        expected = source_bundle['metadata']
        selection = True
        template = (source_bundle['snapshot'] or source_bundle['root']) / 'deploy/selfhost/compose.production.yml'
    else:
        template = next((path for path in (script_dir / 'compose.production.yml', script_dir.parent / 'deploy/selfhost/compose.production.yml') if path.is_file()), None)
    if template is None:
        fail('compose.production.yml is missing; use the complete Docker deployment bundle')
    if args.dry_run:
        if not existing:
            control_port = port_number(args.control_port if args.control_port is not None else 18080)
            metrics_port = port_number(args.metrics_port if args.metrics_port is not None else 18082, (control_port,))
            endpoint = args.relay_endpoint or ('tls://localhost:18081' if args.dev_localhost else '')
            if endpoint:
                relay_port = endpoint_parts(endpoint, args.dev_localhost)[1]
                port_number(control_port, (relay_port,))
                port_number(metrics_port, (relay_port, control_port))
        if source_bundle is not None:
            print('Would build source ' + expected['version'] + ' commit=' + expected['source_sha'] + ' with Docker Compose')
        else:
            print('Would deploy ' + (args.image or args.local_image or args.version or settings.get('P2WLAN_IMAGE', 'a fixed server release')))
        print(f'Directory: {directory}; start={not args.no_start}; health timeout={args.wait_timeout}s')
        return
    adjacent = script_dir / 'SERVER-IMAGE.json'
    if source_bundle is not None:
        pass
    elif args.manifest:
        expected = manifest(Path(args.manifest))
        args.image = expected['image']
    elif not selection and existing:
        args.image = settings.get('P2WLAN_IMAGE')
        if settings.get('P2WLAN_DEV_LOCALHOST') == 'true':
            args.dev_localhost = True
            if (args.image or '').startswith('sha256:'):
                args.local_image, args.image = args.image, None
    elif not selection and adjacent.is_file():
        expected = manifest(adjacent)
        args.image = expected['image']
    elif not selection and terminal:
        args.version = prompt(terminal, '固定服务端版本（server-vX.Y.Z）')
        if not re.fullmatch(r'server-v[A-Za-z0-9._-]+', args.version):
            fail('version must be a fixed server-vX.Y.Z tag')
    if not (source_bundle or args.version or args.image or args.local_image):
        fail('provide --source, --version or --image, or use --interactive')
    # Fetch metadata into an ephemeral directory so the complete plan can be
    # confirmed before pulling an image or creating the persistent deployment.
    if args.version:
        with tempfile.TemporaryDirectory(prefix='p2wlan-image-') as temporary:
            metadata_dir = Path(temporary)
            for name in ('SERVER-IMAGE.json', 'SERVER-IMAGE.json.sha256'):
                url = f'https://github.com/{args.repo}/releases/download/{args.version}/{name}'
                with urllib.request.urlopen(url, timeout=30) as response:
                    data = response.read(64 * 1024 + 1)
                if len(data) > 64 * 1024:
                    fail('image manifest exceeds its size limit')
                (metadata_dir / name).write_bytes(data)
            expected = manifest(metadata_dir / 'SERVER-IMAGE.json', args.version)
            args.image = expected['image']
    image = source_image(directory, expected['source_sha']) if source_bundle else args.local_image or args.image
    if source_bundle is None:
        validate_reference(image, local=bool(args.local_image))

    def plan_for(saved):
        if saved:
            endpoint = '沿用已有 Relay catalog'
            for line in (directory / 'config/control.env').read_text().splitlines():
                if line.startswith('RELAY_CATALOG_JSON='):
                    try:
                        catalog = json.loads(line.split('=', 1)[1])
                        if catalog and isinstance(catalog[0].get('endpoint'), str):
                            host, port = endpoint_parts(catalog[0]['endpoint'], saved['P2WLAN_DEV_LOCALHOST'] == 'true')
                            endpoint = 'tls://' + ('[' + host + ']' if ':' in host else host) + ':' + str(port)
                    except (InstallError, ValueError, TypeError, AttributeError, KeyError, IndexError):
                        pass
                    break
            return dict(dev=saved['P2WLAN_DEV_LOCALHOST'] == 'true', endpoint=endpoint,
                        tls_cert=str(directory / 'config/tls.crt'), tls_key=str(directory / 'config/tls.key'),
                        control_port=port_number(saved.get('CONTROL_PORT', '')),
                        metrics_port=port_number(saved.get('METRICS_PORT', '')),
                        relay_port=port_number(saved.get('RELAY_PORT', '')),
                        publish_host=saved.get('RELAY_PUBLISH_HOST', ''), no_start=args.no_start)
        return dict(dev=args.dev_localhost, endpoint=args.relay_endpoint or '',
                    tls_cert=args.tls_cert, tls_key=args.tls_key,
                    control_port=args.control_port if args.control_port is not None else 18080,
                    metrics_port=args.metrics_port if args.metrics_port is not None else 18082,
                    publish_host=args.publish_host, no_start=args.no_start)

    plan = plan_for(settings)
    edit = False
    if terminal:
        while True:
            if existing:
                terminal.write('\n[2-5/7] 检测到已有部署，将升级/重装选定版本并保留配置、证书、数据库与端口。\n')
                terminal.write('当前版本：' + settings.get('P2WLAN_VERSION', '未知') + '\n')
            else:
                plan = configure_new(terminal, plan, edit)
                plan['relay_port'] = endpoint_parts(plan['endpoint'], plan['dev'])[1]
            terminal.write('\n[6/7] 启动方式\n  1) 安装并启动（等待本机健康检查）\n  2) 只准备，不启动或重新创建容器\n')
            if edit or not args.no_start:
                plan['no_start'] = choice(terminal, '启动方式', '2' if plan['no_start'] else '1', ('1', '2')) == '2'
            terminal.write('\n[7/7] 部署摘要\n')
            target_version = expected['version'] if expected else args.version or '镜像版本将在拉取后核验'
            if source_bundle:
                image = source_image(directory, expected['source_sha'])
                terminal.write('安装来源：已校验源码，本机 Docker Compose 构建\n源码提交：' + expected['source_sha'] + '\n')
            for label, value in (
                ('目标版本', target_version), ('本机构建镜像' if source_bundle else '固定镜像', image), ('部署目录', str(directory)),
                ('部署模式', '本机测试' if plan['dev'] else '公网部署'), ('Relay地址', plan['endpoint']),
                ('Control端口', plan['control_port']), ('Relay端口', plan['relay_port']),
                ('metrics端口', plan['metrics_port']), ('Relay绑定IP', plan['publish_host']),
                ('证书链路径', plan['tls_cert'] or '自动生成本机测试证书'),
                ('私钥路径', plan['tls_key'] or '自动生成本机测试私钥'),
                ('启动方式', '只准备' if plan['no_start'] else '安装并启动'),
            ):
                terminal.write(f'  {label}：{value}\n')
            terminal.write('Control 公网访问仍需您配置可信 HTTPS/WSS 反向代理；本向导不签发公网证书。\n')
            terminal.write('  1) 确认部署  2) 重新填写' + ('启动方式' if existing else '配置') + '  0) 取消\n')
            action = choice(terminal, '确认部署', '1', ('1', '2', '0'))
            if action == '0':
                fail('installation cancelled')
            if action == '1':
                break
            edit = True
            if not existing:
                terminal.write('\n[1/7] 重新填写部署目录\n')
                selected = ask(terminal, '部署目录', str(directory), deployment_directory)
                if selected != directory:
                    directory = selected
                    config, settings_path = directory / 'config', directory / '.env'
                    saved = saved_deployment(directory)
                    existing = saved is not None
                    settings, settings_snapshot = saved if existing else ({}, None)
                    if existing:
                        plan = plan_for(settings)
    elif not existing:
        endpoint = plan['endpoint'] or ('tls://localhost:18081' if plan['dev'] else '')
        if not endpoint:
            fail('new deployment requires --relay-endpoint and TLS files, or --dev-localhost')
        host, relay_port = endpoint_parts(endpoint, plan['dev'])
        plan['endpoint'], plan['relay_port'] = endpoint, relay_port
        plan['control_port'] = port_number(plan['control_port'], (relay_port,))
        plan['metrics_port'] = port_number(plan['metrics_port'], (relay_port, plan['control_port']))
        plan['publish_host'] = bind_address(plan['publish_host'] or ('127.0.0.1' if plan['dev'] else '0.0.0.0'), plan['dev'])
        if not plan['dev']:
            plan['tls_cert'], plan['tls_key'] = tls_path(plan['tls_cert'] or ''), tls_path(plan['tls_key'] or '')
    args.dev_localhost, args.relay_endpoint = plan['dev'], plan['endpoint']
    args.tls_cert, args.tls_key = plan['tls_cert'], plan['tls_key']
    args.control_port, args.metrics_port = plan['control_port'], plan['metrics_port']
    args.publish_host, args.no_start = plan['publish_host'], plan['no_start']
    if args.local_image and not args.dev_localhost:
        fail('--local-image is restricted to --dev-localhost tests')
    if not shutil.which('docker'):
        fail('install Docker Engine and the Docker Compose plugin first')
    if os.environ.get('DOCKER_HOST') and not os.environ['DOCKER_HOST'].startswith('unix://'):
        fail('a local Docker Engine is required for private bind mounts')
    host = run(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'])
    if not host.startswith('unix://'):
        fail('a local Docker Engine context is required')
    info = json.loads(run(['docker', 'info', '--format', '{{json .}}']))
    if info.get('OSType') != 'linux' or any('rootless' in option or 'userns' in option for option in info.get('SecurityOptions', [])):
        fail('this installer requires local rootful Linux Docker without user namespace remapping')
    run(['docker', 'compose', 'version', '--short'])
    help_text = run(['docker', 'compose', 'up', '--help'])
    if '--wait' not in help_text or '--wait-timeout' not in help_text:
        fail('upgrade Docker Compose: up --wait and --wait-timeout are required')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    owner = protected(directory, directory=True)
    if owner.st_uid != os.geteuid():
        fail('deployment directory must belong to the installer user; run with its owner')
    lock_fd = os.open(directory / '.install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'w') as lock:
        if os.fstat(lock.fileno()).st_nlink != 1:
            fail('unsafe installation lock')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail('another installation is already using this directory')
        # Recheck after acquiring the directory lock: no second installer may
        # rotate configuration that appeared while Docker was being inspected.
        if existing != (config.exists() or settings_path.exists()) or (existing and settings_path.read_bytes() != settings_snapshot):
            fail('deployment changed; rerun to preserve the new configuration')
        with tempfile.TemporaryDirectory(prefix='.setup-', dir=directory) as temporary:
            stage = Path(temporary)
            saved_source = None
            build_image = None
            if source_bundle:
                saved_source = persist_source(directory, source_bundle, resources)
                project = 'p2wlan-' + hashlib.sha256(str(directory).encode()).hexdigest()[:12]
                build_image = source_image(directory, expected['source_sha'])
                build_env = dict(os.environ, P2WLAN_BUILD_CONTEXT=str(saved_source / 'server'),
                                 P2WLAN_BUILD_IMAGE=build_image, P2WLAN_VERSION=expected['version'],
                                 P2WLAN_COMMIT=expected['source_sha'])
                print('[1/3] Building the verified source with Docker Compose')
                try:
                    run(['docker', 'compose', '--project-name', project + '-build', '--env-file', '/dev/null',
                         '-f', str(saved_source / 'deploy/selfhost/compose.build.yml'), 'build', 'builder'],
                        timeout=1800, capture=False, env=build_env)
                except InstallError:
                    fail('source build failed; existing runtime configuration and data were preserved')
                image = build_image
            elif not args.local_image:
                print('[1/3] Pulling the fixed image digest')
                try:
                    run(['docker', 'pull', image], timeout=600, capture=False)
                except InstallError:
                    fail('image pull failed; check registry access/network and docker login if the image is private')
            metadata = json.loads(run(['docker', 'image', 'inspect', image, '--format', '{{json .}}']))
            labels = metadata.get('Config', {}).get('Labels') or {}
            version = labels.get('org.opencontainers.image.version', '')
            commit = labels.get('org.opencontainers.image.revision', '')
            if args.local_image:
                if metadata.get('Id') != image:
                    fail('local image identity mismatch')
            elif source_bundle:
                if (version != expected['version'] or commit != expected['source_sha']
                        or not re.fullmatch(r'sha256:[a-f0-9]{64}', metadata.get('Id', ''))):
                    fail('built image identity does not match the verified source')
                image = metadata['Id']
            else:
                if (not re.fullmatch(r'server-v[A-Za-z0-9._-]+', version)
                        or not re.fullmatch(r'[a-f0-9]{40}', commit)
                        or image not in metadata.get('RepoDigests', [])):
                    fail('image must be a released server digest with version/source labels')
                if expected and (version != expected['version'] or commit != expected['source_sha']):
                    fail('image identity does not match the release manifest')
            common = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                      '--security-opt', 'no-new-privileges=true']
            if not args.local_image:
                for component in ('control', 'relay'):
                    identity = run(common + ['--entrypoint', f'/usr/local/bin/p2wlan-{component}', image, '--version'])
                    if identity != f'p2wlan-{component} {version} ({commit})':
                        fail('image binary identity does not match its release labels')
            if existing:
                for name in ('control.env', 'relay.env', 'tls.crt', 'tls.key'):
                    protected(config / name)
                protected(config / 'data', directory=True)
                candidate = config
                settings = dict(settings)
            else:
                endpoint = args.relay_endpoint or ('tls://localhost:18081' if args.dev_localhost else '')
                if not endpoint:
                    fail('new deployment requires --relay-endpoint and TLS files, or --dev-localhost')
                uid = os.geteuid() or 10001
                gid = os.getegid() if os.geteuid() else 10001
                if uid <= 0 or gid <= 0:
                    fail('a non-root container UID/GID is required')
                if os.geteuid() == 0:
                    os.chown(stage, uid, gid)
                generator = ['--mode', 'docker', '--output', '/output/config', '--relay-endpoint', endpoint,
                             '--control-port', str(args.control_port), '--metrics-port', str(args.metrics_port)]
                if args.dev_localhost:
                    generator += ['--dev-localhost']
                else:
                    for source_path, destination in ((args.tls_cert, 'input.crt'), (args.tls_key, 'input.key')):
                        if not source_path or not Path(source_path).is_file():
                            fail('provide readable --tls-cert and --tls-key files')
                        shutil.copyfile(source_path, stage / destination)
                        (stage / destination).chmod(0o600)
                        if os.geteuid() == 0:
                            os.chown(stage / destination, uid, gid)
                    generator += ['--tls-cert', '/output/input.crt', '--tls-key', '/output/input.key']
                print('[2/3] Generating private matching configuration')
                try:
                    run(common + ['--user', f'{uid}:{gid}', '--mount', f'type=bind,src={stage},dst=/output',
                                  '--entrypoint', '/usr/local/bin/p2wlan-config', image] + generator, timeout=60)
                except InstallError:
                    fail('configuration generation failed; verify Relay endpoint, matching TLS chain/key and certificate hostname/validity')
                candidate = stage / 'config'
                for name in ('control.env', 'relay.env', 'tls.crt', 'tls.key', 'compose.env'):
                    protected(candidate / name)
                protected(candidate, directory=True)
                protected(candidate / 'data', directory=True)
                settings = read_env(candidate / 'compose.env')
                settings['RELAY_PUBLISH_HOST'] = args.publish_host or ('127.0.0.1' if args.dev_localhost else '0.0.0.0')
            for key in ('P2WLAN_UID', 'P2WLAN_GID'):
                if not settings.get(key, '').isdigit() or int(settings[key]) <= 0:
                    fail('Compose requires a non-root UID/GID')
            for key in ('CONTROL_PORT', 'RELAY_PORT', 'METRICS_PORT'):
                if not settings.get(key, '').isdigit() or not 1 <= int(settings[key]) <= 65535:
                    fail('invalid deployment port')
            publish = ipaddress.ip_address(settings.get('RELAY_PUBLISH_HOST', ''))
            if args.dev_localhost and not publish.is_loopback:
                fail('development publication must stay loopback-only')
            project = 'p2wlan-' + hashlib.sha256(str(directory).encode()).hexdigest()[:12]
            settings.update(P2WLAN_IMAGE=image, P2WLAN_CONFIG_DIR=str(config), COMPOSE_PROJECT_NAME=project,
                            P2WLAN_VERSION=version, P2WLAN_COMMIT=commit,
                            P2WLAN_DEV_LOCALHOST='true' if args.dev_localhost else 'false',
                            P2WLAN_INSTALL_MODE='source' if source_bundle else 'image')
            if source_bundle:
                settings.update(P2WLAN_SOURCE_DIR=str(saved_source), P2WLAN_BUILD_IMAGE=build_image)
            else:
                settings.pop('P2WLAN_SOURCE_DIR', None)
                settings.pop('P2WLAN_BUILD_IMAGE', None)
            staged_compose = stage / 'compose.yml'
            shutil.copyfile(template, staged_compose)
            staged_env = stage / '.env'
            write_env(staged_env, settings)
            # Validate against the candidate mounts before committing files.
            validation_env = dict(os.environ, **settings)
            validation_env['P2WLAN_CONFIG_DIR'] = str(candidate)
            base = ['docker', 'compose', '--project-name', project]
            run(base + ['--env-file', str(staged_env), '-f', str(staged_compose), 'config', '--quiet'], env=validation_env)
            if not existing:
                (candidate / 'compose.env').unlink()
                candidate.rename(config)
            staged_compose.replace(directory / 'compose.yml')
            staged_env.replace(settings_path)
            command = base + ['--env-file', str(settings_path), '-f', str(directory / 'compose.yml')]
            if not args.no_start:
                print('[3/3] Starting Control/Relay and waiting for health')
                try:
                    run(command + ['up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', str(args.wait_timeout)],
                        timeout=args.wait_timeout + 60, capture=False, env=dict(os.environ, **settings))
                except InstallError:
                    print(f'Deployment files were preserved. Inspect: cd {directory} && docker compose ps', file=sys.stderr)
                    raise
                print('P2WLAN Docker deployment is healthy locally.')
            else:
                print('P2WLAN Docker deployment prepared; services were not started or recreated.')
            print(f'Deployment: {directory}; persistent database and private configuration: {config}')
            print(f'Manage: cd {directory} && docker compose ps')
            print(f'Logs: cd {directory} && docker compose logs --tail 100 control relay')
            print(f'Restart: cd {directory} && docker compose restart')
            label = 'Configured Control (services not started)' if args.no_start else 'Local Control'
            print(f'{label}: http://127.0.0.1:{settings["CONTROL_PORT"]}')
            print(f'Admin path: http://127.0.0.1:{settings["CONTROL_PORT"]}/admin/')
            print('Relay endpoint: ' + plan['endpoint'])
            print('Admin credential: CONTROL_ADMIN_TOKEN in config/control.env (not printed).')
            print('Public Control access still requires trusted HTTPS/WSS; Relay requires client-trusted TLS.')
            if args.dev_localhost:
                print('Local test only: the generated certificate expires in 24 hours and is not publicly trusted.')
    if terminal:
        terminal.close()

try:
    with contextlib.ExitStack() as resources:
        install(resources)
except (InstallError, OSError, ValueError, KeyError) as error:
    sys.exit('install-server-docker: ' + str(error))
PY
