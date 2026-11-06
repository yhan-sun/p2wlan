#!/usr/bin/env python3
"""Install public release artifacts on an ephemeral GitHub-hosted Linux VM.

This is a real deployment acceptance check, not a source-build or mocked test.
It deliberately refuses to run on developer machines or self-hosted runners.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import pty
import pwd
import re
import selectors
import signal
import socket
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


MAX_COMMAND_OUTPUT = 4 * 1024 * 1024
MAX_HTTP_RESPONSE = 32 * 1024


class SmokeFailure(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise SmokeFailure(reason)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def environment_file(path):
    values = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        require(separator and key not in values, 'invalid_deployment_environment')
        values[key] = value
    return values


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


class PublishedServerSmoke:
    def __init__(self, args):
        self.args = args
        self.secrets = set()
        self.attempted_install = False
        self.bootstrap_digest = None
        self.image = None
        self.image_id = None
        self.first_bootstrap_output = b''
        self.last_command_output = b''
        self.child_env = {key: value for key, value in os.environ.items() if key not in (
            'GITHUB_TOKEN', 'GH_TOKEN', 'GH_ENTERPRISE_TOKEN', 'DOCKER_AUTH_CONFIG',
            'DOCKER_CONFIG', 'DOCKER_HOST', 'DOCKER_CONTEXT',
        )}
        self.evidence = dict(schema_version=1, method=args.method, version=args.version,
                             expected_source_sha=args.expected_source_sha, checks={},
                             started_at=datetime.datetime.now(datetime.timezone.utc).isoformat())

    def command(self, label, arguments, *, timeout=30, input_bytes=None):
        """Bound time, output and descendants without publishing captured output."""
        process = subprocess.Popen(arguments, cwd='/', env=self.child_env,
                                   stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + timeout
        output, sent = bytearray(), 0
        try:
            with selectors.DefaultSelector() as selector:
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ, 'output')
                if input_bytes is not None:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, 'input')
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, label + '_timed_out')
                    ready = selector.select(remaining)
                    require(ready, label + '_timed_out')
                    for key, _ in ready:
                        if key.data == 'input':
                            try:
                                sent += os.write(key.fileobj.fileno(), input_bytes[sent:sent + 65536])
                            except BrokenPipeError:
                                sent = len(input_bytes)
                            if sent == len(input_bytes):
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                        else:
                            chunk = os.read(key.fileobj.fileno(), 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            output.extend(chunk)
                            require(len(output) <= MAX_COMMAND_OUTPUT, label + '_output_limit')
            result = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            self.last_command_output = bytes(output)
            self.scan_output(output)
            require(result == 0, label + '_failed')
            return bytes(output)
        except subprocess.TimeoutExpired:
            raise SmokeFailure(label + '_timed_out') from None
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            process.stdout.close()
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()

    def scan_output(self, content):
        require(not any(secret in content for secret in self.secrets), 'credential_found_in_command_output')

    def preflight(self):
        require(platform.system() == 'Linux' and os.geteuid() == 0, 'linux_root_required')
        require(os.environ.get('GITHUB_ACTIONS') == 'true'
                and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'ephemeral_github_runner_required')
        require(re.fullmatch(r'server-v[A-Za-z0-9._-]+', self.args.version), 'invalid_release_version')
        require(re.fullmatch(r'[a-f0-9]{40}', self.args.expected_source_sha), 'invalid_expected_source_sha')
        require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', self.args.repo), 'invalid_repository')
        run_id, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
        require(run_id.isdigit() and attempt.isdigit(), 'github_run_identity_required')
        suffix = run_id + '-' + attempt
        # Each matrix entry owns a fresh VM. Use the actual wizard defaults so
        # the first deployment is precisely the public no-argument experience.
        self.program = Path('/opt/p2wlan-server')
        self.config = Path('/etc/p2wlan')
        self.data = Path('/var/lib/p2wlan')
        self.deployment = Path('/opt/p2wlan-docker')
        self.docker_config = Path(os.environ['RUNNER_TEMP']) / ('p2wlan-anonymous-docker-' + suffix)
        targets = (self.program, self.config, self.data) if self.args.method == 'native' else (self.deployment, self.docker_config)
        require(all(not path.exists() and not path.is_symlink() for path in targets), 'fresh_deployment_paths_required')
        for port in (18080, 18081, 18082):
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', port))
        if self.args.method == 'native':
            require(Path('/run/systemd/system').is_dir(), 'running_systemd_required')
            require(not self.native_unit_files(), 'existing_p2wlan_service_found')
            require(not Path('/usr/local/bin/p2wlan-server').exists(), 'existing_server_manager_found')
        else:
            self.docker_config.mkdir(mode=0o700)
            self.child_env['DOCKER_CONFIG'] = str(self.docker_config)
            self.command('docker_engine', ['docker', 'info'], timeout=30)
            self.command('docker_compose', ['docker', 'compose', 'version'], timeout=30)
        self.evidence['checks']['fresh_ephemeral_environment'] = True
        self.evidence['runner_architecture'] = platform.machine()

    def public_download(self, url, limit):
        content = self.command('public_download', ['curl', '-fsSL', '--retry', '3', '--connect-timeout', '15',
                                                  '--max-time', '120', '--max-filesize', str(limit), url], timeout=150)
        require(len(content) <= limit, 'public_download_size_limit')
        return content

    def prepare_image(self):
        base = f'https://github.com/{self.args.repo}/releases/download/{self.args.version}'
        raw = self.public_download(base + '/SERVER-IMAGE.json', 64 * 1024)
        checksum = self.public_download(base + '/SERVER-IMAGE.json.sha256', 1024).decode('ascii')
        match = re.fullmatch(r'([a-fA-F0-9]{64}) [ *]SERVER-IMAGE.json', checksum.strip())
        require(match and hashlib.sha256(raw).hexdigest() == match[1].lower(), 'public_image_manifest_checksum')
        metadata = json.loads(raw)
        self.image = metadata.get('image', '')
        require(metadata.get('schema_version') == 1 and metadata.get('version') == self.args.version
                and metadata.get('source_sha') == self.args.expected_source_sha, 'public_image_manifest_identity')
        prefix = 'ghcr.io/' + self.args.repo.lower() + '/server@'
        require(self.image.startswith(prefix)
                and re.fullmatch(r'sha256:[a-f0-9]{64}', self.image[len(prefix):]), 'public_ghcr_digest_required')
        require(metadata.get('digest') == self.image.split('@')[1]
                and metadata.get('platforms') == ['linux/amd64', 'linux/arm64'], 'public_image_manifest_platforms')
        # Leave the image absent: the real wizard must perform the initial
        # anonymous pull itself, after its final deployment confirmation.
        digests = self.command('fresh_image_check', ['docker', 'image', 'ls', '--digests', '--no-trunc',
                                                    '--format', '{{.Digest}}']).decode().splitlines()
        require(metadata['digest'] not in digests, 'published_image_must_not_be_cached_before_installation')
        self.require_anonymous_config()
        self.evidence['image'] = self.image

    def inspect_image(self):
        self.require_anonymous_config()
        metadata = json.loads(self.command('image_identity', ['docker', 'image', 'inspect', self.image,
                                                             '--format', '{{json .}}']))
        labels = metadata.get('Config', {}).get('Labels') or {}
        require(labels.get('org.opencontainers.image.version') == self.args.version
                and labels.get('org.opencontainers.image.revision') == self.args.expected_source_sha
                and self.image in metadata.get('RepoDigests', []), 'published_image_identity_mismatch')
        self.image_id = metadata.get('Id', '')
        require(re.fullmatch(r'sha256:[a-f0-9]{64}', self.image_id), 'invalid_published_image_id')
        self.evidence.update(image=self.image, image_id=self.image_id)
        self.evidence['checks']['anonymous_fixed_digest_pull'] = True

    def require_anonymous_config(self):
        settings = self.docker_config / 'config.json'
        if settings.exists():
            values = json.loads(settings.read_text())
            require(not values.get('auths') and not values.get('credsStore') and not values.get('credHelpers'),
                    'registry_credentials_must_remain_absent')

    def bootstrap(self, first):
        url = f'https://raw.githubusercontent.com/{self.args.repo}/main/scripts/bootstrap-server.sh'
        source = self.public_download(url, 256 * 1024)
        digest = hashlib.sha256(source).hexdigest()
        if self.bootstrap_digest is not None:
            require(digest == self.bootstrap_digest, 'public_main_bootstrap_changed_during_acceptance')
        self.bootstrap_digest = digest
        self.evidence['bootstrap_url'] = url
        self.evidence['bootstrap_sha256'] = digest
        arguments = ['bash', '-s', '--', '--method', self.args.method, '--version', self.args.version,
                     '--repo', self.args.repo, '--non-interactive']
        if self.args.method == 'native':
            arguments += ['--root', str(self.program), '--config-dir', str(self.config), '--data-dir', str(self.data)]
        else:
            arguments += ['--dir', str(self.deployment), '--wait-timeout', '120']
        if first:
            arguments += ['--dev-localhost']
        self.attempted_install = True
        output = (self.wizard(source) if first else self.command('public_bootstrap_reinstall',
                  arguments, timeout=900, input_bytes=source))
        if first:
            self.first_bootstrap_output = output

    def native_unit_files(self):
        output = self.command('native_unit_files', ['systemctl', 'list-unit-files', '--no-legend', '--no-pager'])
        expected = {'p2wlan-control.service', 'p2wlan-relay.service'}
        return {fields[0] for line in output.decode().splitlines()
                if (fields := line.split()) and fields[0] in expected}

    def before_confirmation(self):
        targets = (self.program, self.config, self.data) if self.args.method == 'native' else (self.deployment,)
        require(all(not path.exists() and not path.is_symlink() for path in targets),
                'persistent_paths_appeared_before_confirmation')
        if self.args.method == 'native':
            require(not self.native_unit_files(), 'native_unit_appeared_before_confirmation')
        else:
            containers = self.command('preconfirmation_containers', ['docker', 'ps', '-aq', '--filter', 'ancestor=' + self.image])
            require(not containers.strip(), 'container_appeared_before_confirmation')
        self.evidence['checks']['confirmation_precedes_runtime_or_persistent_paths'] = True

    def wizard(self, source):
        steps = [('安装方式', '1' if self.args.method == 'native' else '2'), ('请选择版本编号', '1')]
        steps += ([('程序目录', ''), ('配置目录', ''), ('数据目录', '')] if self.args.method == 'native'
                  else [('部署目录', '')])
        steps += [('部署模式', '2'), ('Relay主机', ''), ('Relay端口', ''),
                  ('Control端口', ''), ('metrics端口', '')]
        if self.args.method == 'docker':
            steps += [('Relay绑定IP', '')]
        steps += [('启动方式', '1'), ('确认部署', '1')]
        source_read, source_write = os.pipe()
        pid, terminal = pty.fork()
        if pid == 0:
            os.close(source_write)
            os.dup2(source_read, 0)
            os.close(source_read)
            os.chdir('/')
            os.execve('/bin/bash', ['bash', '-s'], self.child_env)
        os.close(source_read)
        output, cursor, sent, status = bytearray(), 0, 0, None
        total_steps = len(steps)
        deadline, prompt_deadline = time.monotonic() + 900, time.monotonic() + 90
        try:
            with selectors.DefaultSelector() as selector:
                os.set_blocking(source_write, False)
                selector.register(source_write, selectors.EVENT_WRITE, 'source')
                selector.register(terminal, selectors.EVENT_READ, 'terminal')
                while status is None:
                    waited, child_status = os.waitpid(pid, os.WNOHANG)
                    if waited:
                        status = child_status
                        break
                    remaining = min(deadline, prompt_deadline if steps else deadline) - time.monotonic()
                    require(remaining > 0, 'public_wizard_prompt_timed_out' if steps else 'public_wizard_timed_out')
                    for key, _ in selector.select(min(remaining, 1)):
                        if key.data == 'source':
                            try:
                                sent += os.write(source_write, source[sent:sent + 65536])
                            except BrokenPipeError:
                                sent = len(source)
                            if sent == len(source):
                                selector.unregister(source_write)
                                os.close(source_write)
                                source_write = None
                            continue
                        try:
                            chunk = os.read(terminal, 65536)
                        except OSError:
                            chunk = b''
                        if not chunk:
                            selector.unregister(terminal)
                            continue
                        output.extend(chunk)
                        require(len(output) <= MAX_COMMAND_OUTPUT, 'public_wizard_output_limit')
                        text = output.decode(errors='replace')
                        while steps:
                            needle, reply = steps[0]
                            found = text.find(needle, cursor)
                            if found < 0:
                                break
                            if needle == '请选择版本编号':
                                version = re.search(r'(?m)^\s*1\)\s+(server-v[A-Za-z0-9._-]+)\s+发布于', text)
                                require(version is not None, 'public_default_release_not_displayed')
                                self.evidence['observed_default_version'] = version[1]
                                require(version[1] == self.args.version, 'public_default_release_is_not_the_expected_tag')
                                self.evidence['checks']['default_release_matches_requested'] = True
                            if needle == '确认部署':
                                self.before_confirmation()
                            os.write(terminal, (reply + '\n').encode())
                            cursor = found + len(needle)
                            steps.pop(0)
                            prompt_deadline = time.monotonic() + 90
            # A fast exit can leave final output in the PTY buffer. Include it
            # in the credential scan instead of stopping at waitpid alone.
            os.set_blocking(terminal, False)
            while True:
                try:
                    chunk = os.read(terminal, 65536)
                except (BlockingIOError, OSError):
                    break
                if not chunk:
                    break
                output.extend(chunk)
                require(len(output) <= MAX_COMMAND_OUTPUT, 'public_wizard_output_limit')
            self.last_command_output = bytes(output)
            self.scan_output(output)
            require(not steps and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, 'public_wizard_failed')
            self.evidence['checks']['public_no_argument_wizard'] = True
            return bytes(output)
        finally:
            self.last_command_output = bytes(output)
            self.evidence['wizard_completed_steps'] = total_steps - len(steps)
            if steps:
                self.evidence['wizard_pending_prompt'] = steps[0][0]
            if status is None:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
            os.close(terminal)
            if source_write is not None:
                os.close(source_write)

    def compose(self, arguments, label='compose_operation', timeout=30):
        return self.command(label, ['docker', 'compose', '--env-file', str(self.deployment / '.env'),
                                    '-f', str(self.deployment / 'compose.yml')] + arguments, timeout=timeout)

    def manager(self, arguments, label='native_manager', timeout=30):
        return self.command(label, ['env', 'P2WLAN_SERVER_ROOT=' + str(self.program),
                                    'P2WLAN_SERVER_CONFIG=' + str(self.config), 'P2WLAN_SERVER_DATA=' + str(self.data),
                                    '/usr/local/bin/p2wlan-server'] + arguments, timeout=timeout)

    def credential_fingerprint(self):
        config = self.config if self.args.method == 'native' else self.deployment / 'config'
        result = {}
        for name in ('control.env', 'relay.env', 'tls.crt', 'tls.key'):
            path = config / name
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077 and info.st_nlink == 1,
                    'credentials_must_remain_private_regular_files')
            result[name] = sha256(path)
        self.protect_known_credentials()
        self.scan_output(self.first_bootstrap_output)
        self.admin_token = environment_file(config / 'control.env')['CONTROL_ADMIN_TOKEN']
        return result

    def protect_known_credentials(self):
        config = self.config if self.args.method == 'native' else self.deployment / 'config'
        for name in ('control.env', 'relay.env'):
            path = config / name
            if not path.is_file() or path.stat().st_size > 128 * 1024:
                continue
            for key, value in environment_file(path).items():
                if ('SECRET' in key or 'TOKEN' in key) and len(value) >= 16:
                    self.secrets.add(value.encode())
                if key == 'RELAY_TICKET_SIGNER_JSON':
                    try:
                        secret = json.loads(value).get('active', {}).get('private_key', '')
                    except (ValueError, AttributeError):
                        secret = ''
                    if len(secret) >= 16:
                        self.secrets.add(secret.encode())
        key_path = config / 'tls.key'
        if key_path.is_file() and key_path.stat().st_size <= 128 * 1024:
            for line in key_path.read_bytes().splitlines():
                if len(line) >= 32 and not line.startswith(b'-----'):
                    self.secrets.add(line)

    def http(self, path, *, body=None, token=None):
        data = None if body is None else json.dumps(body).encode()
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        request = urllib.request.Request('http://127.0.0.1:18080' + path, data=data, headers=headers)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            with opener.open(request, timeout=10) as response:
                require(response.status == 200, 'local_http_status')
                content = response.read(MAX_HTTP_RESPONSE + 1)
            require(len(content) <= MAX_HTTP_RESPONSE, 'local_http_response_limit')
            return content
        except (OSError, urllib.error.URLError):
            raise SmokeFailure('local_http_request_failed') from None

    def verify_tls(self):
        config = self.config if self.args.method == 'native' else self.deployment / 'config'
        context = ssl.create_default_context(cafile=str(config / 'tls.crt'))
        with socket.create_connection(('127.0.0.1', 18081), timeout=10) as connection:
            with context.wrap_socket(connection, server_hostname='localhost') as secure:
                require(secure.getpeercert(), 'relay_tls_certificate_missing')
                self.evidence['relay_tls_version'] = secure.version()

    def verify_native(self):
        metadata = environment_file_text((self.program / 'current/BUILD-METADATA.txt').read_bytes())
        arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
        require(metadata.get('version') == self.args.version and metadata.get('commit') == self.args.expected_source_sha
                and metadata.get('arch') == arch, 'installed_native_release_identity')
        account = pwd.getpwnam('p2wlan')
        require(account.pw_uid > 0, 'native_service_account_must_not_be_root')
        manifest = (self.program / 'current/SHA256SUMS').read_text().splitlines()
        require(len(manifest) == 4 and {line.split()[-1] for line in manifest}
                == {'p2wlan-control', 'p2wlan-relay', 'p2wlan-config', 'p2wlan-db'}, 'native_binary_checksum_manifest')
        for line in manifest:
            digest, name = line.split()
            require(name in ('p2wlan-control', 'p2wlan-relay', 'p2wlan-config', 'p2wlan-db')
                    and sha256(self.program / 'current' / name) == digest, 'native_binary_checksum_mismatch')
        for component in ('control', 'relay'):
            binary = self.program / 'current' / ('p2wlan-' + component)
            identity = self.command('native_binary_identity', [str(binary), '--version']).decode().strip()
            require(identity == f'p2wlan-{component} {self.args.version} ({self.args.expected_source_sha})',
                    'native_binary_identity_mismatch')
            unit = 'p2wlan-' + component + '.service'
            state = environment_file_text(self.command('native_systemd_state', ['systemctl', 'show', unit,
                '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID', '-p', 'ExecMainStatus']))
            require(state.get('ActiveState') == 'active' and state.get('SubState') == 'running'
                    and state.get('ExecMainStatus') == '0', 'native_systemd_service_not_running')
            pid = int(state.get('MainPID', '0'))
            require(pid > 0 and Path(f'/proc/{pid}/exe').resolve() == binary.resolve(), 'native_process_executable_mismatch')
            status = Path(f'/proc/{pid}/status').read_text().splitlines()
            uids = next(line.split()[1:] for line in status if line.startswith('Uid:'))
            require(len(uids) == 4 and all(int(uid) == account.pw_uid for uid in uids), 'native_process_uid_mismatch')
        self.manager(['check', '--service', 'all'], timeout=60)
        self.http('/health')
        self.command('native_database_integrity', ['runuser', '-u', 'p2wlan', '--',
            str(self.program / 'current/p2wlan-db'), '--verify', str(self.data / 'p2pnet.db')])
        self.verify_tls()
        self.evidence['checks'].update(real_systemd_services=True, native_source_identity=True,
                                       nonroot_service_processes=True, database_integrity=True, real_relay_tls=True)

    def verify_docker(self):
        settings = environment_file(self.deployment / '.env')
        require(settings.get('P2WLAN_IMAGE') == self.image and settings.get('P2WLAN_VERSION') == self.args.version
                and settings.get('P2WLAN_COMMIT') == self.args.expected_source_sha, 'installed_compose_identity')
        expected_uid = int(settings.get('P2WLAN_UID', '0'))
        require(expected_uid > 0, 'container_uid_must_not_be_root')
        for component in ('control', 'relay'):
            container = self.compose(['ps', '-q', component], 'container_identity').decode().strip()
            require(re.fullmatch(r'[a-f0-9]{12,64}', container), 'running_container_missing')
            fields = self.command('container_state', ['docker', 'inspect', '--format',
                '{{.State.Status}} {{.State.Health.Status}} {{.Image}} {{.Config.Image}} {{.Path}}', container]).decode().split()
            require(fields == ['running', 'healthy', self.image_id, self.image, '/usr/local/bin/p2wlan-' + component],
                    'container_health_or_image_mismatch')
            uid = self.compose(['exec', '-T', component, 'id', '-u'], 'container_uid').decode().strip()
            require(uid == str(expected_uid), 'container_runtime_uid_mismatch')
            identity = self.compose(['exec', '-T', component, '/usr/local/bin/p2wlan-' + component, '--version'],
                                    'container_binary_identity').decode().strip()
            require(identity == f'p2wlan-{component} {self.args.version} ({self.args.expected_source_sha})',
                    'container_binary_identity_mismatch')
        self.http('/health')
        self.compose(['exec', '-T', 'relay', 'curl', '-fsS', '--connect-timeout', '3', '--max-time', '10',
                      'http://127.0.0.1:18082/readyz'], 'container_relay_readiness')
        self.compose(['exec', '-T', 'control', '/usr/local/bin/p2wlan-db', '--verify', '/data/p2pnet.db'],
                     'container_database_integrity')
        self.verify_tls()
        self.require_anonymous_config()
        self.evidence['checks'].update(real_healthy_compose_containers=True, fixed_container_image_identity=True,
                                       nonroot_service_processes=True, database_integrity=True, real_relay_tls=True)

    def verify(self):
        self.verify_native() if self.args.method == 'native' else self.verify_docker()
        self.http('/admin/api/v1/overview', token=self.admin_token)

    def stop(self):
        if self.args.method == 'native':
            self.manager(['stop', '--service', 'all'], timeout=60)
        else:
            self.compose(['down', '--remove-orphans'], 'compose_down', timeout=60)

    def cleanup(self):
        if not self.attempted_install:
            return
        if self.args.method == 'native':
            installed_units = self.native_unit_files()
            for unit in ('p2wlan-control.service', 'p2wlan-relay.service'):
                if unit in installed_units:
                    self.command('cleanup_native', ['systemctl', 'disable', '--now', unit], timeout=60)
        elif (self.deployment / 'compose.yml').is_file() and (self.deployment / '.env').is_file():
            self.compose(['down', '--remove-orphans'], 'cleanup_compose', timeout=60)

    def exercise(self):
        self.preflight()
        if self.args.method == 'docker':
            self.prepare_image()
        self.bootstrap(first=True)
        if self.args.method == 'docker':
            self.inspect_image()
        original = self.credential_fingerprint()
        self.verify()
        self.evidence['checks']['real_initial_deployment'] = True
        import secrets
        account = dict(email='release-smoke-' + secrets.token_hex(8) + '@example.test', password=secrets.token_hex(24))
        self.secrets.add(account['password'].encode())
        registration = json.loads(self.http('/api/v1/register', body=account))
        token = registration.get('token')
        require(isinstance(token, str) and token, 'account_registration_failed')
        self.secrets.add(token.encode())
        self.http('/api/v1/profile', token=token)
        self.stop()
        self.bootstrap(first=False)
        require(self.credential_fingerprint() == original, 'credentials_changed_during_reinstallation')
        self.verify()
        self.http('/api/v1/profile', token=token)
        login = json.loads(self.http('/api/v1/login', body=account))
        require(isinstance(login.get('token'), str) and login['token'], 'account_did_not_survive_reinstallation')
        self.evidence['checks'].update(credentials_preserved=True, database_account_preserved=True,
                                       existing_jwt_preserved=True, real_reinstallation=True,
                                       command_output_contains_no_credentials=True)

    def failure_diagnostics(self):
        """Report state only: never systemd environment, container env or raw logs."""
        if not self.attempted_install:
            return
        try:
            self.protect_known_credentials()
        except (SmokeFailure, OSError, ValueError):
            pass
        states = {}
        if self.args.method == 'native':
            for component in ('control', 'relay'):
                try:
                    raw = self.command('diagnostic_state', ['systemctl', 'show', 'p2wlan-' + component + '.service',
                        '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState', '-p', 'ExecMainStatus'])
                    states[component] = environment_file_text(raw)
                except (SmokeFailure, OSError, ValueError):
                    states[component] = {'diagnostic': 'unavailable'}
        elif (self.deployment / 'compose.yml').is_file() and (self.deployment / '.env').is_file():
            try:
                rows = json.loads(self.compose(['ps', '-a', '--format', 'json'], 'diagnostic_compose'))
                for row in rows:
                    states[row.get('Service', 'unknown')] = {
                        key: row.get(key) for key in ('State', 'Health', 'ExitCode')}
            except (SmokeFailure, OSError, ValueError):
                states['diagnostic'] = 'unavailable'
        self.evidence['failure_diagnostics'] = states


def environment_file_text(content):
    return dict(line.split('=', 1) for line in content.decode().splitlines() if '=' in line)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--method', choices=('native', 'docker'), required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--expected-source-sha', required=True)
    parser.add_argument('--repo', default='yhan-sun/p2wlan')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output
    require(os.environ.get('RUNNER_TEMP') and output.parent.resolve() == Path(os.environ['RUNNER_TEMP']).resolve()
            and output.name == 'server-release-smoke-' + args.method + '.json' and not output.is_symlink(),
            'evidence_must_be_in_the_runner_temporary_directory')
    smoke = PublishedServerSmoke(args)
    error = None
    try:
        smoke.exercise()
    except (SmokeFailure, OSError, ValueError, KeyError, StopIteration, TypeError, AttributeError) as caught:
        error = str(caught) if isinstance(caught, SmokeFailure) else 'acceptance_' + type(caught).__name__
        smoke.failure_diagnostics()
    finally:
        try:
            smoke.cleanup()
            smoke.evidence['checks']['services_cleaned_up'] = True
        except (SmokeFailure, OSError, ValueError) as caught:
            error = error or ('cleanup_' + str(caught) if isinstance(caught, SmokeFailure) else 'cleanup_failed')
        smoke.evidence.update(status='failed' if error else 'passed', failure_reason=error,
                              finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
        with tempfile.NamedTemporaryFile(mode='w', prefix='.server-release-smoke-', dir=output.parent, delete=False) as stream:
            json.dump(smoke.evidence, stream, indent=2)
            stream.write('\n')
            temporary = Path(stream.name)
        temporary.chmod(0o644)  # The evidence contains public identity and booleans only.
        temporary.replace(output)
    print(('FAIL' if error else 'PASS') + ': public ' + args.method + ' deployment ' + args.version)
    return 1 if error else 0


if __name__ == '__main__':
    raise SystemExit(main())
