#!/usr/bin/env bash
set -euo pipefail
command -v python3 >/dev/null 2>&1 || { echo 'install-server-docker: Python 3 is required' >&2; exit 1; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 - "$SCRIPT_DIR" "$@" <<'PY'
"""Build verified server source locally or install a fixed server image."""
import argparse
import contextlib
import fcntl
import errno
import getpass
import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import urllib.request
import urllib.parse
import warnings

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
parser.add_argument('--tls-mode', choices=('auto', 'selfsigned', 'files'),
                    help='auto: Let\'s Encrypt for a domain; selfsigned: local CA for an IP/host; files: use --tls-cert/--tls-key')
parser.add_argument('--tls-domain', help='certificate domain for --tls-mode auto; must equal the Relay host')
parser.add_argument('--tls-email', help='ACME account email for --tls-mode auto')
parser.add_argument('--control-port', type=int, help='internal Control port (default: 18080)')
parser.add_argument('--http-port', type=int, help='public HTTP redirect port (default: 80)')
parser.add_argument('--https-port', type=int, help='public HTTPS panel port (default: 443)')
parser.add_argument('--metrics-port', type=int, help='internal Relay readiness port (default: 18082)')
parser.add_argument('--publish-host', help='Relay host bind IP; public 0.0.0.0, test 127.0.0.1')
parser.add_argument('--dev-localhost', action='store_true')
parser.add_argument('--no-start', action='store_true', help='prepare deployment without starting/recreating services')
parser.add_argument('--dry-run', action='store_true', help='show a plan without Docker, downloads or filesystem changes')
parser.add_argument('--wait-timeout', type=int, default=90, help='Compose health deadline, 10-600 seconds')
args = parser.parse_args(sys.argv[2:])
interactive = args.interactive or len(sys.argv) == 2

EDGE_IMAGE_DEFAULT = 'nginxinc/nginx-unprivileged:1.27-alpine'
ACME_LIVE_DIR = Path(os.environ.get('P2WLAN_ACME_LIVE_DIR', '/etc/letsencrypt/live'))
RENEWAL_HOOKS_DIR = Path(os.environ.get('P2WLAN_RENEWAL_HOOKS_DIR', '/etc/letsencrypt/renewal-hooks'))

class InstallError(Exception):
    pass

def fail(message):
    raise InstallError(message)

def run(arguments, *, timeout=30, capture=True, env=None, input_text=None):
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL if input_text is None else None, input=input_text,
                                stdout=subprocess.PIPE if capture else None,
                                stderr=subprocess.PIPE if capture else None,
                                text=True, encoding='utf-8' if input_text is not None else None,
                                timeout=timeout, env=env, check=False)
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
               'P2WLAN_INSTALL_MODE', 'P2WLAN_SOURCE_DIR', 'P2WLAN_BUILD_IMAGE',
               'P2WLAN_BUILD_MANIFEST', 'P2WLAN_BUILD_PLATFORM',
               'P2WLAN_TLS_MODE', 'P2WLAN_TLS_DOMAIN', 'COMPOSE_PROFILES',
               'P2WLAN_HTTP_PORT', 'P2WLAN_HTTPS_PORT', 'P2WLAN_EDGE_CONF'}
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

CANCEL_REPLIES = frozenset(('q', 'quit', 'exit', 'cancel', '取消'))

def decode_reply(data):
    # Terminals do not always send UTF-8: legacy zh_CN sessions use GB18030.
    # Decode leniently so a stray byte cancels or re-prompts instead of
    # aborting the wizard with a codec error.
    for encoding in ('utf-8', 'gb18030'):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode('utf-8', 'replace')

def prompt(terminal, label, default=''):
    terminal.write(label + (f' [{default}]' if default else '') + ': ')
    terminal.flush()
    try:
        raw = terminal.buffer.readline()
    except (OSError, ValueError):
        fail('terminal input is unavailable; installation cancelled')
    if not raw:
        fail('terminal input ended; installation cancelled')
    value = decode_reply(raw).strip() or default
    if value.lower() in CANCEL_REPLIES:
        fail('installation cancelled')
    return value

def ask(terminal, label, default, validate):
    while True:
        value = prompt(terminal, label, str(default) if default is not None else '')
        try:
            return validate(value)
        except InstallError as error:
            terminal.write('输入无效：' + str(error) + '。请重试，或输入 q 取消。\n')
        except (OSError, ValueError):
            terminal.write('输入格式不正确或路径不可读取。请重试，或输入 q 取消。\n')

def choice(terminal, label, default, choices):
    def validate(value):
        if value not in choices:
            fail('请选择 ' + '/'.join(choices))
        return value
    return ask(terminal, label, default, validate)

def admin_account(terminal):
    def username(value):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', value):
            fail('账号须以字母或数字开头，可含点、下划线和短横线，最多 64 个字符')
        return value
    def secret(label):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                value = getpass.getpass(label, stream=terminal)
        except (getpass.GetPassWarning, EOFError, KeyboardInterrupt):
            fail('无法从终端安全读取密码，安装已取消')
        if value.lower() in CANCEL_REPLIES:
            fail('installation cancelled')
        return value
    name = ask(terminal, '管理员账号', 'admin', username)
    while True:
        password = secret('管理员密码（12–72 个 UTF-8 字节，输入隐藏）: ')
        if 12 <= len(password.encode()) <= 72 and '\x00' not in password:
            check = secret('确认管理员密码: ')
            if password == check:
                return name, password
        terminal.write('密码长度不符或两次输入不一致，请重新输入。\n')

def access_addresses(control, endpoint, panel, https_port=443):
    local = 'http://127.0.0.1:' + str(control)
    host = '[' + panel.strip('[]') + ']' if panel and ':' in panel else panel
    base = 'https://' + host + (f':{https_port}' if https_port != 443 else '') if host else local
    return f'服务端地址（Control）：{base}\n管理后台地址：{base}/admin/\nRelay 地址：{endpoint}'

@contextlib.contextmanager
def show_failed_addresses(addresses):
    try:
        yield
    except Exception:
        print('本次部署未完成。以下为计划地址，可用性尚未确认。\n' + addresses(), file=sys.stderr, flush=True)
        raise

def require_edge_port(port):
    if not port_available(port):
        fail(f'主机 TCP {port} 已被占用。请用 sudo ss -ltnp 查看监听进程。'
             'Certbot standalone 签发证书时需要公网 TCP 80。')

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
        fail('该端口已用于此部署，请另选端口')
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

EDGE_NGINX = '''# Managed by the P2WLAN installer: public HTTPS/WSS entry for Control.
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
server {
    listen 8080;
    server_name __DOMAIN__;
    location = /healthz {
        add_header Content-Type text/plain;
        return 200 'ok';
    }
    location / {
        return 301 https://$host__HTTPS_SUFFIX__$request_uri;
    }
}
server {
    listen 8443 ssl;
    http2 on;
    server_name __DOMAIN__;
    ssl_certificate /run/secrets/p2wlan_tls_cert;
    ssl_certificate_key /run/secrets/p2wlan_tls_key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1h;
    client_max_body_size 8m;
    location / {
        proxy_pass http://control:__CONTROL_PORT__;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Port __HTTPS_PORT__;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
'''

def certificate_domain(value):
    if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}', value):
        fail('证书域名必须是公网域名，不能是 IP 地址')
    return value.lower()

def optional_email(value):
    return certificate_email(value) if value else ''

def certificate_email(value):
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[A-Za-z]{2,}', value):
        fail('请输入有效的 ACME 账户邮箱')
    return value

def port_without_bind_privilege(port):
    # The caller can use a rootful daemon without permission to bind privileged
    # ports itself. The kernel still exposes its TCP listening sockets.
    if shutil.which('ss'):
        return not run(['ss', '-H', '-ltn', f'sport = :{port}'])
    tables = [path for path in (Path('/proc/net/tcp'), Path('/proc/net/tcp6')) if path.is_file()]
    if not tables:
        fail(f'无法检查主机 TCP {port}，请安装 ss 或使用 sudo 运行安装器。')
    for table in tables:
        for line in table.read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == '0A' and int(fields[1].rsplit(':', 1)[1], 16) == port:
                return False
    return True

def port_available(port):
    for family, host in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                probe.bind((host, port))
        except OSError as error:
            if error.errno == errno.EADDRINUSE:
                return False
            if error.errno in (errno.EACCES, errno.EPERM):
                return port_without_bind_privilege(port)
            if error.errno not in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EADDRNOTAVAIL):
                raise
    return True

def check_edge_ports(control, relay, http=80, https=443):
    if len({http, https, control, relay}) != 4:
        fail(f'网页 HTTP/HTTPS 端口 {http}/{https}、Control 和 Relay 的主机端口必须各不相同')

def docker_port_bindings(ports, project):
    # Published ports can exist only in Docker's NAT rules, without a listening PID.
    bindings = {port: [] for port in ports}
    fields = ('{{.Id}}\t{{.Name}}\t{{json .HostConfig.AutoRemove}}\t{{json (index .Config.Labels "com.docker.compose.project")}}\t'
              '{{json (index .Config.Labels "com.docker.compose.service")}}\t{{json .NetworkSettings.Ports}}')
    def inspect_running():
        ids = run(['docker', 'ps', '--quiet', '--no-trunc']).splitlines()
        return '\n'.join(run(['docker', 'container', 'inspect', '--format', fields] + ids[start:start + 32])
                         for start in range(0, len(ids), 32))
    try:
        rows = inspect_running()
    except InstallError:
        # An unrelated, short-lived container may have disappeared after docker ps.
        rows = inspect_running()
    for row in rows.splitlines():
        identity, name, removable, owner, service, mapping = row.split('\t', 5)
        own = json.loads(owner) == project and json.loads(service) == 'edge'
        for target, entries in (json.loads(mapping) or {}).items():
            if not target.endswith('/tcp'):
                continue
            for entry in entries or []:
                port = int(entry['HostPort'])
                if port in bindings:
                    bindings[port].append((identity, name.lstrip('/'), own, entry['HostIp'], json.loads(removable)))
    return bindings

def web_port_conflicts(ports, project):
    conflicts = {}
    for port, bindings in docker_port_bindings(ports, project).items():
        foreign = {(identity, name, removable) for identity, name, own, _, removable in bindings if not own}
        own_wildcard = any(own and address in ('', '0.0.0.0', '::') for _, _, own, address, _ in bindings)
        if foreign or (not own_wildcard and not port_available(port)):
            conflicts[port] = foreign
    return conflicts

def listener_owner(port, containers):
    if containers:
        targets = sorted(containers)
        names = ', '.join(name + ('（停止即删除）' if removable else '') for _, name, removable in targets)
        target = ('docker', targets[0][1], targets[0][0]) if len(targets) == 1 and not targets[0][2] else None
        return 'Docker ' + names, target
    if not shutil.which('ss'):
        return '请在主机上查看监听服务', None
    try:
        listeners = run(['ss', '-H', '-ltnp', f'sport = :{port}'])
    except InstallError:
        return '请用 sudo ss -ltnp 查看监听服务', None
    pids = set(re.findall(r'pid=(\d+)', listeners))
    units = set()
    for pid in pids:
        try:
            groups = Path('/proc', pid, 'cgroup').read_text()
        except OSError:
            return listeners, None
        match = re.search(r'/((?:nginx|apache2|httpd|caddy|haproxy)\.service)(?:/|$)', groups, re.MULTILINE)
        if not match:
            return listeners, None
        units.add(match[1])
    if len(units) == 1 and shutil.which('systemctl'):
        unit = units.pop()
        try:
            invocation = run(['systemctl', 'show', '--property=InvocationID', '--value', unit])
        except InstallError:
            return unit, None
        if re.fullmatch(r'[a-f0-9]{32}', invocation):
            return unit, ('systemd', unit, invocation)
    return listeners or '请用 sudo ss -ltnp 查看监听服务', None

def edit_web_ports(terminal, plan, busy):
    used = (plan['control_port'], plan['relay_port'])
    for field, label, alternate in [('http_port', '网页 HTTP 端口', 8080), ('https_port', '网页 HTTPS 端口', 8443)]:
        default = plan[field]
        if default in busy or default in used:
            default = alternate
            while default in busy or default in used:
                default += 1
        plan[field] = ask(terminal, label, default, lambda value: port_number(value, used))
        used += (plan[field],)

def resolve_web_ports(terminal, plan, project, *, issue_certificate=False):
    while True:
        http, https = plan['http_port'], plan['https_port']
        check_edge_ports(plan['control_port'], plan['relay_port'], http, https)
        required = [] if plan['no_start'] else [http, https]
        acme = plan['tls_mode'] == 'auto' and issue_certificate
        if acme and 80 not in required:
            required.append(80)
        conflicts = web_port_conflicts(required, project) if required else {}
        if not conflicts:
            return
        port = next(iter(conflicts))
        message = f'主机 TCP {port} 已被占用。'
        if not terminal:
            fail(message + '可用 --http-port 和 --https-port 修改网页端口。' +
                 ('HTTP-01 签发时需要公网 TCP 80。' if acme and port == 80 else ''))
        description, target = listener_owner(port, conflicts[port])
        terminal.write(message + '\n占用者：' + description + '\n'
                       '  1) 给 P2WLAN 更换网页端口\n  2) 手动处理后重新检测\n')
        if target:
            terminal.write('  3) 正常停止占用服务 ' + target[1] + '（该服务会中断）\n')
        terminal.write('  q) 取消并退出\n')
        action = choice(terminal, '处理端口冲突', '1', ('1', '2', '3') if target else ('1', '2'))
        if action == '1':
            if acme and 80 in conflicts:
                terminal.write('独立 HTTP-01 仍需公网 TCP 80。可改用已有证书，或选择客户端需信任的自签名证书。\n'
                               '  1) 已有证书文件  2) 自签名证书  3) 返回端口冲突菜单\n')
                certificate = choice(terminal, '更换证书方式', '', ('1', '2', '3'))
                if certificate == '3':
                    continue
                plan['tls_mode'] = 'files' if certificate == '1' else 'selfsigned'
                plan['tls_domain'] = endpoint_parts(plan['endpoint'], False)[0]
                if certificate == '1':
                    plan['tls_cert'] = ask(terminal, '证书链路径', '', tls_path)
                    plan['tls_key'] = ask(terminal, '私钥路径', '', tls_path)
            edit_web_ports(terminal, plan, conflicts)
        elif action == '3':
            if prompt(terminal, '确认停止请完整输入 ' + target[1] + '，回车返回') != target[1]:
                continue
            current = web_port_conflicts([port], project)
            if port not in current or listener_owner(port, current[port])[1] != target:
                terminal.write('占用者已变化，重新检测。\n')
                continue
            command = ['docker', 'stop', '--timeout', '30', target[2]] if target[0] == 'docker' else ['systemctl', 'stop', target[1]]
            try:
                run(command, timeout=120)
            except InstallError:
                terminal.write('未能停止 ' + target[1] + '。重新检测后可更换网页端口或退出。\n')
                continue
            restart = 'docker start ' + target[2][:12] if target[0] == 'docker' else 'systemctl start ' + target[1]
            terminal.write(f'已停止 {target[1]}。如需恢复该服务，可执行 sudo {restart}。\n')

def check_panel(host, config, mode, port=443):
    authority = '[' + host.strip('[]') + ']' if ':' in host else host
    command = ['curl', '--silent', '--show-error', '--fail', '--noproxy', '*',
               '--connect-timeout', '3', '--max-time', '10', '--connect-to',
               f'{authority}:{port}:127.0.0.1:{port}', '--output', os.devnull, '--write-out', '%{http_code}']
    if mode == 'selfsigned':
        command += ['--cacert', str(config / 'relay-ca.crt')]
    elif mode == 'files':
        command += ['--cacert', str(config / 'tls.crt')]
    try:
        url = 'https://' + authority + (f':{port}' if port != 443 else '') + '/health'
        if run(command + [url]) == '200':
            return
    except InstallError:
        pass
    fail('HTTPS edge verification failed: check the certificate chain, hostname and Control /health')

def atomic_write(path, content, mode=0o600):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        name = Path(temporary.name)
        try:
            temporary.write(content)
            temporary.flush()
            os.fchmod(temporary.fileno(), mode)
            name.replace(path)
        finally:
            name.unlink(missing_ok=True)

def database_path(config):
    raw = next((line[8:] for line in (config / 'control.env').read_text().splitlines()
                if line.startswith('DB_PATH=')), '/data/p2pnet.db')
    try:
        relative = Path(raw).relative_to('/data')
    except ValueError:
        fail('cannot snapshot DB_PATH outside the mounted /data directory')
    data = config / 'data'
    result = data / relative
    if '..' in relative.parts or result.resolve() != result:
        fail('unsafe DB_PATH for upgrade recovery')
    return result

def sqlite_schema(connection):
    version = connection.execute('PRAGMA user_version').fetchone()
    app = connection.execute('PRAGMA application_id').fetchone()
    rows = connection.execute('SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name')
    return version, app, tuple(rows)

def snapshot_database(database, directory):
    if not database.exists():
        return None, None
    recovery = Path(tempfile.mkdtemp(prefix='.upgrade-', dir=directory))
    snapshot = recovery / 'database.sqlite'
    try:
        with contextlib.closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as source, \
                contextlib.closing(sqlite3.connect(str(snapshot))) as copy:
            source.backup(copy)
            if copy.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                fail('SQLite upgrade snapshot failed integrity_check')
            return snapshot, sqlite_schema(copy)
    except (sqlite3.Error, InstallError, OSError):
        shutil.rmtree(recovery)
        fail('could not verify the pre-upgrade SQLite snapshot; current deployment files were preserved')

def same_schema(database, previous):
    if not database.exists():
        return previous is None
    try:
        with contextlib.closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as connection:
            connection.execute('BEGIN')
            return sqlite_schema(connection) == previous
    except sqlite3.Error:
        return False

def activate_compose(directory, stage, settings, previous_env, no_start, wait):
    config = directory / 'config'
    env_file, compose_file = directory / '.env', directory / 'compose.yml'
    receipt = directory / '.last-healthy.json'
    blocked = directory / '.recovery-required'
    recovery_pending = blocked.exists()
    previous = None
    if receipt.exists():
        protected(receipt)
        previous = json.loads(receipt.read_text())
    elif previous_env is not None:
        previous = [previous_env.decode(), compose_file.read_text()]
    command = ['docker', 'compose', '--project-name', settings['COMPOSE_PROJECT_NAME'],
               '--env-file', str(env_file), '-f', str(compose_file)]
    candidate = [(stage / '.env').read_text(), (stage / 'compose.yml').read_text()]
    starting = ['up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', str(wait)]
    environment = dict(os.environ, **settings)
    snapshot = database = schema = None
    running, stopped = [], []
    if previous:
        old = read_env(env_file, previous[0].encode())
        old_environment = dict(os.environ, **old)
        if not receipt.exists():
            atomic_write(receipt, json.dumps(previous).encode())
        if not no_start:
            running = run(command + ['ps', '--status', 'running', '--services'], env=old_environment).splitlines()
            present = run(command + ['ps', '--all', '--services'], env=old_environment).splitlines()
            stopped = sorted(set(present) - set(running))
            if (set(running) | set(present)) - {'control', 'relay', 'edge'}:
                fail('unexpected service in the deployment')
            if old['P2WLAN_IMAGE'] != settings['P2WLAN_IMAGE'] and not recovery_pending:
                database = database_path(config)
                snapshot, schema = snapshot_database(database, directory)
                atomic_write(blocked, f'Activation in progress. Snapshot: {snapshot or "no prior database"}\n'.encode())
    (stage / 'compose.yml').replace(compose_file)
    (stage / '.env').replace(env_file)
    if no_start:
        return
    try:
        run(command + starting, timeout=wait + 60, capture=False, env=environment)
        if settings.get('COMPOSE_PROFILES') == 'edge':
            check_panel(settings['P2WLAN_TLS_DOMAIN'], config, settings['P2WLAN_TLS_MODE'], int(settings.get('P2WLAN_HTTPS_PORT', 443)))
    except InstallError as error:
        if snapshot:
            print(f'Pre-upgrade SQLite snapshot: {snapshot}', file=sys.stderr)
        run(command + ['stop'], timeout=120, env=environment)
        if previous:
            if recovery_pending:
                fail(f'{error}; services stopped. Prior upgrade recovery record and snapshot preserved: {blocked}')
            if database and not same_schema(database, schema):
                fail(f'{error}; services stopped after database schema changed. Snapshot: {snapshot or "no prior database"}')
            run(command + ['rm', '--force'], env=environment)
            atomic_write(compose_file, previous[1].encode())
            atomic_write(env_file, previous[0].encode())
            if stopped:
                run(command + ['up', '--no-start', '--no-deps', '--no-build', '--pull', 'never'] + stopped,
                    timeout=wait + 60, env=old_environment)
            if running:
                run(command + starting + ['--no-deps'] + running, timeout=wait + 60, env=old_environment)
                if 'edge' in running:
                    check_panel(old['P2WLAN_TLS_DOMAIN'], config, old['P2WLAN_TLS_MODE'], int(old.get('P2WLAN_HTTPS_PORT', 443)))
            blocked.unlink(missing_ok=True)
            print('Restored the prior deployment files and previously running services.', file=sys.stderr)
        raise
    atomic_write(receipt, json.dumps(candidate).encode())
    blocked.unlink(missing_ok=True)
    if snapshot:
        snapshot.unlink()
        snapshot.parent.rmdir()

def ensure_certbot():
    if shutil.which('certbot'):
        return
    print('[TLS] Installing certbot with apt-get')
    environment = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
    try:
        run(['apt-get', 'update', '-qq'], timeout=600, capture=False, env=environment)
        run(['apt-get', 'install', '-y', '-qq', 'certbot'], timeout=600, capture=False, env=environment)
    except InstallError:
        fail('installing certbot failed; install it with apt-get, or use --tls-mode files')

def request_certificate(domain, contact, hooks):
    require_edge_port(80)
    ensure_certbot()
    print('[TLS] Requesting a certificate for ' + domain)
    contact_arguments = (['-m', contact, '--no-eff-email'] if contact
                         else ['--register-unsafely-without-email'])
    try:
        run(['certbot', 'certonly', '--standalone', '--non-interactive', '--agree-tos',
             '--keep-until-expiring', '--cert-name', domain, '--pre-hook', str(hooks / 'pre'),
             '--post-hook', str(hooks / 'post'), '--deploy-hook', str(hooks / 'deploy')] + contact_arguments + ['-d', domain], timeout=900, capture=False)
    except InstallError:
        fail('certificate request failed; verify DNS, inbound TCP 80 and ACME rate limits')
    live = ACME_LIVE_DIR / domain
    chain, key = live / 'fullchain.pem', live / 'privkey.pem'
    if not chain.is_file() or not key.is_file():
        fail('certbot did not create the expected certificate files')
    return str(chain), str(key)

def self_signed_certificate(work, host):
    work = work / 'selfsigned'
    work.mkdir(mode=0o700, exist_ok=True)
    openssl = shutil.which('openssl')
    if not openssl:
        fail('openssl is required for a self-signed certificate')
    try:
        address = ipaddress.ip_address(host.strip('[]'))
    except ValueError:
        san = 'DNS:' + host
    else:
        san = 'IP:' + str(address)
    ca_config = work / 'ca.cnf'
    ca_config.write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=v3\n'
                         '[dn]\nCN=P2WLAN Relay CA\n'
                         '[v3]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
    san_config = work / 'san.cnf'
    san_config.write_text('[ext]\nsubjectAltName=' + san +
                          '\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n')
    ca_key, ca_crt = work / 'relay-ca.key', work / 'relay-ca.crt'
    cert, key, csr = work / 'input.crt', work / 'input.key', work / 'server.csr'
    try:
        run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
             '-config', str(ca_config), '-keyout', str(ca_key), '-out', str(ca_crt)])
        run([openssl, 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + host,
             '-keyout', str(key), '-out', str(csr)])
        run([openssl, 'x509', '-req', '-in', str(csr), '-CA', str(ca_crt), '-CAkey', str(ca_key),
             '-CAcreateserial', '-days', '825', '-extfile', str(san_config), '-extensions', 'ext',
             '-out', str(cert)])
    except InstallError:
        fail('self-signed certificate generation failed; install openssl and retry')
    for path in (ca_key, key):
        path.chmod(0o600)
    for path in (ca_config, san_config, csr):
        path.unlink()
    return str(cert), str(key), str(ca_crt)

def write_edge_config(config, domain, control_port, https_port):
    edge = config / 'edge'
    edge.mkdir(mode=0o700, exist_ok=True)
    if protected(edge, directory=True).st_uid != os.geteuid():
        fail('unexpected owner of the managed HTTPS configuration directory')
    name = 'nginx.conf' if https_port == 443 else f'nginx-{https_port}.conf'
    target = edge / name
    try:
        info = target.lstat()
    except FileNotFoundError:
        content = EDGE_NGINX.replace('__DOMAIN__', domain).replace('__CONTROL_PORT__', str(control_port))
        suffix = f':{https_port}' if https_port != 443 else ''
        content = content.replace('__HTTPS_SUFFIX__', suffix).replace('__HTTPS_PORT__', str(https_port))
        atomic_write(target, content.encode(), 0o644)
    else:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022:
            fail('unsafe managed HTTPS configuration file')
    return name

def install_renewal_hooks(directory, domain, uid, gid, publish, relay_port):
    # Certbot runs these commands as root. Keep all executables and state in its
    # own directory, outside the bind mounts writable by application containers.
    name = 'p2wlan-' + hashlib.sha256(str(directory).encode()).hexdigest()[:12]
    hooks = RENEWAL_HOOKS_DIR / name
    hooks.mkdir(parents=True, exist_ok=True, mode=0o700)
    if protected(hooks, directory=True).st_uid != os.geteuid():
        fail('renewal hook directory has an unexpected owner')
    address = ipaddress.ip_address(publish)
    if address.is_unspecified:
        address = ipaddress.ip_address('127.0.0.1' if address.version == 4 else '::1')
    relay = f'[{address}]:{relay_port}' if address.version == 6 else f'{address}:{relay_port}'
    header = ('#!/bin/sh\nset -eu\numask 077\n'
              + 'directory=' + shlex.quote(str(directory)) + '\n'
              + 'live=' + shlex.quote(str(ACME_LIVE_DIR / domain)) + '\n'
              + 'marker=' + shlex.quote(str(hooks / 'edge-stopped')) + '\n'
              + 'domain=' + shlex.quote(domain) + '\n'
              + 'relay=' + shlex.quote(relay) + '\n'
              + f'uid={int(uid)}\ngid={int(gid)}\n'
              + """[ -f "$directory/.env" ] && [ -f "$directory/compose.yml" ] || exit 0
http_port=$(sed -n 's/^P2WLAN_HTTP_PORT=//p' "$directory/.env")
https_port=$(sed -n 's/^P2WLAN_HTTPS_PORT=//p' "$directory/.env")
http_port=${http_port:-80}
https_port=${https_port:-443}
case "$http_port:$https_port" in *[!0-9:]*) exit 1 ;; esac
https="127.0.0.1:$https_port"
compose() { docker compose --env-file "$directory/.env" -f "$directory/compose.yml" "$@"; }
recreate() { compose up -d --no-deps --force-recreate --no-build --pull never --wait --wait-timeout 90 "$1"; }
verify() {
    expected=$(openssl x509 -in "$directory/config/tls.crt" -noout -fingerprint -sha256)
    served=$(timeout 8 openssl s_client -connect "$1" -servername "$domain" </dev/null 2>/dev/null |
             openssl x509 -noout -fingerprint -sha256)
    [ "$served" = "$expected" ] || { echo "renewed certificate is not served on $1" >&2; return 1; }
}
""")
    scripts = {
        'pre': """running=$(compose ps --status running --services)
if [ "$http_port" = 80 ] && echo "$running" | grep -Fxq edge; then
    : > "$marker"
    compose stop edge
fi
""",
        'post': """[ -f "$marker" ] || exit 0
recreate edge
verify "$https"
rm -f "$marker"
""",
        'deploy': """[ "${RENEWED_LINEAGE:-}" = "$live" ] || exit 0
running=$(compose ps --status running --services)
stage=$(mktemp -d "$directory/.renew-XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
install -m 0600 -o "$uid" -g "$gid" "$live/fullchain.pem" "$stage/tls.crt"
install -m 0600 -o "$uid" -g "$gid" "$live/privkey.pem" "$stage/tls.key"
python3 - "$stage" "$directory/config" <<'REPLACE'
from pathlib import Path
import sys
source, destination = map(Path, sys.argv[1:])
for name in ('tls.crt', 'tls.key'):
    (source / name).replace(destination / name)
REPLACE
if echo "$running" | grep -Fxq relay; then recreate relay; verify "$relay"; fi
if echo "$running" | grep -Fxq edge; then recreate edge; verify "$https"; fi
""",
    }
    for kind, script in scripts.items():
        atomic_write(hooks / kind, (header + script).encode(), 0o700)
    return hooks

def bind_renewal_hooks(directory, domain, hooks):
    # Older releases used three global symlinks. Move just this registration
    # to its own lineage while preserving Certbot's comments and other options.
    renewal = ACME_LIVE_DIR.parent / 'renewal' / (domain + '.conf')
    original = renewal.read_text()
    match = re.search(r'(?m)^\[renewalparams\][ \t]*$', original)
    if not match:
        fail('missing [renewalparams] in ' + str(renewal))
    start = match.end()
    next_section = re.search(r'(?m)^\[', original[start:])
    end = start + next_section.start() if next_section else len(original)
    section = original[start:end]
    add = []
    for kind, key in (('pre', 'pre_hook'), ('post', 'post_hook'), ('deploy', 'renew_hook')):
        value = str(hooks / kind)
        existing = re.findall(r'(?m)^[ \t]*' + key + r'[ \t]*=[ \t]*(.*?)[ \t]*$', section)
        if existing and existing != [value]:
            fail(f'custom Certbot {key} in {renewal}; integrate the hook at {value} before upgrading')
        if not existing:
            add.append(key + ' = ' + value)
    if add:
        backup = hooks / 'renewal.conf.before-p2wlan'
        if not backup.exists():
            atomic_write(backup, original.encode())
        atomic_write(renewal, (original[:start] + '\n' + '\n'.join(add) + original[start:]).encode())
    for kind in ('pre', 'post', 'deploy'):
        legacy = RENEWAL_HOOKS_DIR / kind / (hooks.name + '.sh')
        if legacy.is_symlink() and Path(os.readlink(legacy)) == (directory / 'config/edge' / (kind + '.sh')):
            legacy.unlink()

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
    terminal.write('\n[2/7] 部署模式\n  1) 公网部署（内置 HTTPS/WSS，网页端口默认 80 和 443）\n  2) 本机测试（24 小时测试证书，仅 loopback）\n')
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
        relay_name = endpoint_parts(plan['endpoint'], False)[0]
        if edit or not plan['tls_mode']:
            terminal.write("  1) 自动申请 Let's Encrypt 证书（需要域名，自动续期；邮箱可留空）\n"
                           '  2) 自签名证书（IP 或主机名，无需域名和邮箱；客户端需信任生成的 CA）\n'
                           '  3) 使用已有证书文件\n')
            default = {'auto': '1', 'selfsigned': '2', 'files': '3'}[plan['tls_mode'] or 'auto']
            plan['tls_mode'] = {'1': 'auto', '2': 'selfsigned', '3': 'files'}[
                choice(terminal, '证书来源', default, ('1', '2', '3'))]
        if plan['tls_mode'] == 'auto':
            try:
                ipaddress.ip_address(relay_name.strip('[]'))
            except ValueError:
                pass
            else:
                fail('Relay 是 IP，自动申请需要域名；请选 2 自签名或 3 已有证书')
            plan['tls_domain'] = ask(terminal, '证书域名', plan['tls_domain'] or relay_name, certificate_domain)
            if plan['tls_domain'] != relay_name.lower():
                fail('证书域名必须与 Relay 主机名一致：' + relay_name)
            plan['tls_email'] = ask(terminal, 'ACME 邮箱（留空跳过）', plan['tls_email'] or '', optional_email)
            plan['tls_cert'] = plan['tls_key'] = None
            terminal.write('将签发证书并自动续期：' + plan['tls_domain'] + '\n')
        elif plan['tls_mode'] == 'selfsigned':
            plan['tls_cert'] = plan['tls_key'] = None
            terminal.write('将生成本地 CA 和覆盖 ' + relay_name +
                           ' 的自签名证书；客户端需信任 config/relay-ca.crt。\n')
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
        terminal.write('P2WLAN Docker 服务端安装向导；所有步骤可输入 q 取消。\n\n[1/7] 部署目录\n')
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
    def initial_web_ports(saved):
        http = port_number(args.http_port if args.http_port is not None else saved.get('P2WLAN_HTTP_PORT', 80))
        https = port_number(args.https_port if args.https_port is not None else saved.get('P2WLAN_HTTPS_PORT', 443), (http,))
        return {'http_port': http, 'https_port': https}
    web = initial_web_ports(settings)
    if (args.http_port is not None or args.https_port is not None) and (
            args.dev_localhost or (existing and settings.get('COMPOSE_PROFILES') != 'edge')):
        fail('网页端口只适用于启用公网 HTTPS 入口的 Docker 部署')
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
            relay_port = endpoint_parts(endpoint, args.dev_localhost)[1] if endpoint else 18081
            port_number(control_port, (relay_port,))
            port_number(metrics_port, (relay_port, control_port))
            if not args.dev_localhost:
                check_edge_ports(control_port, relay_port, web['http_port'], web['https_port'])
        elif settings.get('COMPOSE_PROFILES') == 'edge':
            check_edge_ports(int(settings['CONTROL_PORT']), int(settings['RELAY_PORT']), web['http_port'], web['https_port'])
        if source_bundle is not None:
            print('Would build source ' + expected['version'] + ' commit=' + expected['source_sha'] + ' with Docker Compose')
        else:
            print('Would deploy ' + (args.image or args.local_image or args.version or settings.get('P2WLAN_IMAGE', 'a fixed server release')))
        if not args.dev_localhost and (not existing or settings.get('COMPOSE_PROFILES') == 'edge'):
            print(f"网页端口：HTTP {web['http_port']} / HTTPS {web['https_port']}")
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
            return dict(**initial_web_ports(saved), dev=saved['P2WLAN_DEV_LOCALHOST'] == 'true', endpoint=endpoint,
                        tls_cert=str(directory / 'config/tls.crt'), tls_key=str(directory / 'config/tls.key'),
                        tls_mode=saved.get('P2WLAN_TLS_MODE', 'files'),
                        tls_domain=saved.get('P2WLAN_TLS_DOMAIN') or '',
                        tls_email=None,
                        control_port=port_number(saved.get('CONTROL_PORT', '')),
                        metrics_port=port_number(saved.get('METRICS_PORT', '')),
                        relay_port=port_number(saved.get('RELAY_PORT', '')),
                        publish_host=saved.get('RELAY_PUBLISH_HOST', ''), no_start=args.no_start)
        return dict(**initial_web_ports(saved), dev=args.dev_localhost, endpoint=args.relay_endpoint or '',
                    tls_cert=args.tls_cert, tls_key=args.tls_key,
                    tls_mode=args.tls_mode or ('files' if args.tls_cert and args.tls_key else None),
                    tls_domain=args.tls_domain, tls_email=args.tls_email,
                    control_port=args.control_port if args.control_port is not None else 18080,
                    metrics_port=args.metrics_port if args.metrics_port is not None else 18082,
                    publish_host=args.publish_host, no_start=args.no_start)

    plan = plan_for(settings)
    edit = False
    if terminal:
        while True:
            if existing:
                terminal.write('\n[2-5/7] 检测到已有部署，将升级/重装选定版本并沿用凭据、证书和数据库。\n')
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
                ('证书来源', '本机测试证书' if plan['dev'] else
                 {'auto': '自动申请（自动续期）', 'selfsigned': '自签名（本地 CA）',
                  'files': '已有证书文件'}[plan['tls_mode']]),
                ('启动方式', '只准备' if plan['no_start'] else '安装并启动'),
            ):
                terminal.write(f'  {label}：{value}\n')
            if plan['tls_cert'] and plan['tls_key']:
                terminal.write(f'  证书链路径：{plan["tls_cert"]}\n  私钥路径：{plan["tls_key"]}\n')
            if plan['dev']:
                terminal.write('Control 仅监听 loopback；本机测试不配置公网 HTTPS。\n')
            elif not existing or settings.get('COMPOSE_PROFILES') == 'edge':
                panel = plan['tls_domain'] or endpoint_parts(plan['endpoint'], False)[0]
                terminal.write(f"网页端口：HTTP {plan['http_port']} / HTTPS {plan['https_port']}\n")
                terminal.write('计划访问地址\n' + access_addresses(plan['control_port'], plan['endpoint'], panel, plan['https_port']) + '\n')
            terminal.write('  1) 确认部署  2) 重新填写' + ('启动方式' if existing else '配置') + '  0/q) 取消\n')
            public_edge = not plan['dev'] and (not existing or settings.get('COMPOSE_PROFILES') == 'edge')
            if public_edge:
                terminal.write('  3) 更改网页 HTTP/HTTPS 端口\n')
            action = choice(terminal, '确认部署', '1', ('1', '2', '3', '0') if public_edge else ('1', '2', '0'))
            while action == '3':
                edit_web_ports(terminal, plan, {})
                terminal.write('计划访问地址\n' + access_addresses(plan['control_port'], plan['endpoint'], panel, plan['https_port']) + '\n')
                action = choice(terminal, '确认部署', '1', ('1', '2', '3', '0'))
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
        if not plan['dev'] and plan['tls_mode'] not in ('auto', 'selfsigned'):
            plan['tls_cert'], plan['tls_key'] = tls_path(plan['tls_cert'] or ''), tls_path(plan['tls_key'] or '')
    if not plan['dev']:
        if plan['tls_mode'] is None:
            plan['tls_mode'] = 'auto' if (args.tls_domain or args.tls_email) else 'files'
        if plan['tls_mode'] == 'auto':
            if not plan['tls_domain']:
                fail('--tls-mode auto requires --tls-domain')
            plan['tls_domain'] = certificate_domain(plan['tls_domain'])
            plan['tls_email'] = optional_email(plan['tls_email'] or '')
            relay_name = endpoint_parts(plan['endpoint'], False)[0]
            try:
                ipaddress.ip_address(relay_name.strip('[]'))
            except ValueError:
                pass
            else:
                fail('Relay 是 IP，自动申请需要域名；请选 2 自签名或 3 已有证书')
            if plan['tls_domain'] != relay_name.lower():
                fail('--tls-domain must equal the Relay host')
            plan['tls_cert'] = plan['tls_key'] = None
        elif plan['tls_mode'] == 'selfsigned':
            plan['tls_cert'] = plan['tls_key'] = None
    args.dev_localhost, args.relay_endpoint = plan['dev'], plan['endpoint']
    edge_enabled = (not args.dev_localhost) and (not existing or settings.get('COMPOSE_PROFILES') == 'edge')
    panel = (plan['tls_domain'] or endpoint_parts(plan['endpoint'], False)[0]) if edge_enabled else None
    def addresses():
        return access_addresses(plan['control_port'], plan['endpoint'], panel, plan['https_port'])
    resources.enter_context(show_failed_addresses(addresses))
    if edge_enabled:
        check_edge_ports(plan['control_port'], plan['relay_port'], plan['http_port'], plan['https_port'])
        if not existing and not terminal and plan['tls_mode'] == 'auto':
            require_edge_port(80)
    elif args.http_port is not None or args.https_port is not None:
        fail('网页端口只适用于启用公网 HTTPS 入口的 Docker 部署')
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
    project = 'p2wlan-' + hashlib.sha256(str(directory).encode()).hexdigest()[:12]
    if edge_enabled:
        previous_ports = plan['http_port'], plan['https_port']
        resolve_web_ports(terminal, plan, project, issue_certificate=not existing)
        if terminal and previous_ports != (plan['http_port'], plan['https_port']):
            terminal.write(f"将使用 HTTP {plan['http_port']} / HTTPS {plan['https_port']}\n" + addresses() + '\n')
            if choice(terminal, '确认使用这些网页端口（1 继续，0 退出）', '1', ('1', '0')) == '0':
                fail('installation cancelled')
        if existing and plan['tls_mode'] == 'auto' and plan['http_port'] != 80 and web_port_conflicts([80], project):
            print('现有证书将继续使用。Certbot HTTP-01 自动续期时仍须释放公网 TCP 80。', file=sys.stderr)
    args.tls_mode, args.tls_domain, args.tls_email = plan['tls_mode'], plan['tls_domain'], plan['tls_email']
    args.tls_cert, args.tls_key = plan['tls_cert'], plan['tls_key']
    account = admin_account(terminal) if terminal and not existing else None
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
            metadata = None
            if source_bundle:
                saved_source = persist_source(directory, source_bundle, resources)
                build_image = source_image(directory, expected['source_sha'])
                build_env = dict(os.environ, P2WLAN_BUILD_CONTEXT=str(saved_source / 'server'),
                                 P2WLAN_BUILD_IMAGE=build_image, P2WLAN_VERSION=expected['version'],
                                 P2WLAN_COMMIT=expected['source_sha'])
                arch = info.get('Architecture', '')
                arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(arch, arch)
                platform = os.environ.get('DOCKER_DEFAULT_PLATFORM') or 'linux/' + arch
                previous_id = settings.get('P2WLAN_IMAGE', '')
                if (existing and settings.get('P2WLAN_INSTALL_MODE') == 'source'
                        and settings.get('P2WLAN_BUILD_MANIFEST') == source_bundle['metadata_hash']
                        and arch and settings.get('P2WLAN_BUILD_PLATFORM') == platform
                        and re.fullmatch(r'sha256:[a-f0-9]{64}', previous_id)):
                    try:
                        cached = json.loads(run(['docker', 'image', 'inspect', previous_id, '--format', '{{json .}}']))
                    except InstallError:
                        cached = {}
                    actual = '/'.join(filter(None, (cached.get('Os'), cached.get('Architecture'), cached.get('Variant'))))
                    if cached.get('Id') == previous_id and (actual == platform or
                            ('/'.join(actual.split('/')[:2]) == platform and platform.count('/') == 1)):
                        metadata = cached
                if metadata is None:
                    print('[1/3] Building the verified source with Docker Compose')
                    try:
                        run(['docker', 'compose', '--project-name', project + '-build', '--env-file', '/dev/null',
                             '-f', str(saved_source / 'deploy/selfhost/compose.build.yml'), 'build', 'builder'],
                            timeout=1800, capture=False, env=build_env)
                    except InstallError:
                        fail('source build failed; existing runtime configuration and data were preserved')
                else:
                    print('[1/3] Verifying the previously built image by immutable ID')
                image = build_image
            elif not args.local_image:
                print('[1/3] Pulling the fixed image digest')
                try:
                    run(['docker', 'pull', image], timeout=600, capture=False)
                except InstallError:
                    fail('image pull failed; check registry access/network and docker login if the image is private')
            if metadata is None:
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
                self_signed_ca = None
                if args.tls_mode == 'auto':
                    hooks = install_renewal_hooks(directory, args.tls_domain, os.geteuid() or 10001,
                                                  os.getegid() if os.geteuid() else 10001,
                                                  args.publish_host, plan['relay_port'])
                    args.tls_cert, args.tls_key = request_certificate(args.tls_domain, args.tls_email, hooks)
                elif args.tls_mode == 'selfsigned':
                    args.tls_cert, args.tls_key, self_signed_ca = self_signed_certificate(
                        stage, endpoint_parts(endpoint, False)[0])
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
                if account:
                    generator += ['--admin-user', account[0]]
                try:
                    run(common + (['--interactive'] if account else []) + ['--user', f'{uid}:{gid}', '--mount',
                        f'type=bind,src={stage},dst=/output', '--entrypoint', '/usr/local/bin/p2wlan-config', image]
                        + generator, timeout=60, input_text=account[1] + '\n' if account else None)
                except InstallError:
                    fail('configuration generation failed; verify Relay endpoint, matching TLS chain/key and certificate hostname/validity')
                if self_signed_ca is not None:
                    shutil.copyfile(self_signed_ca, stage / 'config/relay-ca.crt')
                    (stage / 'config/relay-ca.crt').chmod(0o644)
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
            settings.update(P2WLAN_IMAGE=image, P2WLAN_CONFIG_DIR=str(config), COMPOSE_PROJECT_NAME=project,
                            P2WLAN_VERSION=version, P2WLAN_COMMIT=commit,
                            P2WLAN_DEV_LOCALHOST='true' if args.dev_localhost else 'false',
                            P2WLAN_INSTALL_MODE='source' if source_bundle else 'image')
            if not args.dev_localhost and not existing:
                settings.update(COMPOSE_PROFILES='edge', P2WLAN_TLS_MODE=args.tls_mode or 'files',
                                P2WLAN_TLS_DOMAIN=args.tls_domain or endpoint_parts(args.relay_endpoint, False)[0])
            if edge_enabled:
                settings.update(P2WLAN_HTTP_PORT=str(plan['http_port']), P2WLAN_HTTPS_PORT=str(plan['https_port']),
                                P2WLAN_EDGE_CONF=write_edge_config(candidate, panel, args.control_port, plan['https_port']))
            if source_bundle:
                settings.update(P2WLAN_SOURCE_DIR=str(saved_source), P2WLAN_BUILD_IMAGE=build_image,
                                P2WLAN_BUILD_MANIFEST=source_bundle['metadata_hash'], P2WLAN_BUILD_PLATFORM=platform)
            else:
                for field in ('P2WLAN_SOURCE_DIR', 'P2WLAN_BUILD_IMAGE', 'P2WLAN_BUILD_MANIFEST', 'P2WLAN_BUILD_PLATFORM'):
                    settings.pop(field, None)
            staged_compose = stage / 'compose.yml'
            shutil.copyfile(template, staged_compose)
            staged_env = stage / '.env'
            write_env(staged_env, settings)
            # Validate against the candidate mounts before committing files.
            validation_env = dict(os.environ, **settings)
            validation_env['P2WLAN_CONFIG_DIR'] = str(candidate)
            base = ['docker', 'compose', '--project-name', project]
            if edge_enabled:
                base += ['--profile', 'edge']
            run(base + ['--env-file', str(staged_env), '-f', str(staged_compose), 'config', '--quiet'], env=validation_env)
            if edge_enabled and not args.no_start:
                print('[3/3] Pulling the HTTPS edge image')
                run(['docker', 'pull', os.environ.get('P2WLAN_EDGE_IMAGE', EDGE_IMAGE_DEFAULT)],
                    timeout=600, capture=False)
            if edge_enabled and args.tls_mode == 'auto':
                if existing:
                    hooks = install_renewal_hooks(directory, args.tls_domain, settings['P2WLAN_UID'],
                                                  settings['P2WLAN_GID'], settings['RELAY_PUBLISH_HOST'],
                                                  settings['RELAY_PORT'])
                bind_renewal_hooks(directory, args.tls_domain, hooks)
            if edge_enabled and not args.no_start:
                resolve_web_ports(None, plan, project)
            if not existing:
                (candidate / 'compose.env').unlink()
                candidate.rename(config)
            if not args.no_start:
                print('[3/3] Starting Control/Relay and waiting for health')
            activate_compose(directory, stage, settings, settings_snapshot, args.no_start, args.wait_timeout)
            if not args.no_start:
                print('P2WLAN Docker deployment is healthy locally.')
            else:
                print('P2WLAN Docker deployment prepared; services were not started or recreated.')
            print(f'Deployment: {directory}; persistent database and private configuration: {config}')
            print(f'Manage: cd {directory} && docker compose ps')
            print(f'Logs: cd {directory} && docker compose logs --tail 100 control relay')
            print(f'Restart: cd {directory} && docker compose restart')
            if args.dev_localhost:
                print('Local test only: the generated certificate expires in 24 hours and is not publicly trusted.')
            if account:
                print('管理员账号：' + account[0])
            print('管理令牌保存在 ' + str(config / 'control.env') + ' 的 CONTROL_ADMIN_TOKEN 字段。')
            print('配置已就绪，本次未启动服务。计划访问地址' if args.no_start else '健康检查通过，访问地址')
            print(addresses())
    if terminal:
        terminal.close()

try:
    with contextlib.ExitStack() as resources:
        install(resources)
except (InstallError, OSError, ValueError, KeyError, sqlite3.Error) as error:
    sys.exit('install-server-docker: ' + str(error))
PY
