"""Exercise the SSH helper's receiving side without a remote server."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


class RemoteDeploymentTests(unittest.TestCase):
    def test_upload_and_fetch_use_the_selected_bundle_role_paths_and_start_intent(self):
        helper = (Path(__file__).resolve().parents[2] / 'scripts/deploy-server.sh').read_text()
        received = helper.split("<<'REMOTE_UPLOAD'\n", 1)[1].split('\nREMOTE_UPLOAD', 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            remote = Path(temporary)
            (remote / 'root/current').mkdir(parents=True)
            source = remote / 'assets'
            source.mkdir()
            name = 'p2wlan-server-linux-amd64.tar.gz'
            version = 'server-v9.9.9'
            manager = b'#!/bin/sh\nprintf "%s|%s|%s|%s\\n" "$P2WLAN_SERVER_ROOT" "$P2WLAN_SERVER_CONFIG" "$P2WLAN_SERVER_DATA" "$*" >> "$CALLS"\n'
            with tarfile.open(source / name, 'w:gz') as archive:
                for key, body in [('p2wlan-server', manager), ('install-server.sh', b'#!/bin/sh\nexit 77\n'),
                                  ('BUILD-METADATA.txt', f'version={version}\n'.encode())]:
                    info = tarfile.TarInfo(key)
                    info.size = len(body)
                    archive.addfile(info, io.BytesIO(body))
            digest = hashlib.sha256((source / name).read_bytes()).hexdigest()
            (source / (name + '.sha256')).write_text(f'{digest}  {name}\n')
            tools = remote / 'bin'
            tools.mkdir()
            for key, body in [('sudo', b'#!/bin/sh\nexec "$@"\n'), ('p2wlan-server', manager),
                              ('curl', b'#!/bin/sh\nprintf "%s\\n" "$6" >> "$URLS"\ncp "$ASSETS/$5" "$5"\n')]:
                (tools / key).write_bytes(body)
                (tools / key).chmod(0o755)
            log, urls = remote / 'calls', remote / 'urls'
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'], CALLS=str(log),
                       URLS=str(urls), ASSETS=str(source))
            paths = [str(remote / key) for key in ('root', 'config', 'data')]
            for mode in ('upload', 'fetch'):
                for start in ('0', '1'):
                    with self.subTest(mode=mode, start=start):
                        destination = remote / (mode + start)
                        destination.mkdir()
                        log.write_text('')
                        urls.write_text('')
                        if mode == 'upload':
                            for path in source.iterdir():
                                (destination / path.name).write_bytes(path.read_bytes())
                        args = [str(destination), name, 'relay', start, *paths, mode, 'owner/fork', version]
                        result = subprocess.run(['bash', '-s', '--', *args], input=received, env=env,
                                                capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        prefix = '|'.join(paths) + '|'
                        update = f'update --archive {destination / name} --service relay'
                        expected = [update, 'verify --service relay']
                        if start == '0':
                            expected[0] += ' --no-restart'
                        else:
                            expected.extend(['start --service relay', 'check --service relay'])
                        self.assertEqual(log.read_text().splitlines(), [prefix + call for call in expected])
                        url = f'https://github.com/owner/fork/releases/download/{version}/{name}'
                        self.assertEqual(urls.read_text().splitlines(), [url, url + '.sha256'] if mode == 'fetch' else [])
