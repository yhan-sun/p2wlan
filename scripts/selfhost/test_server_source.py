"""Exercise released source packages against real committed Git objects."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name('package_server_source.py')
SPEC = importlib.util.spec_from_file_location('package_server_source', SCRIPT)
PACKAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGER)
VERSION = 'server-v0.0.0-test'
SOURCE_NAMES = {
    'server/Dockerfile', 'server/.dockerignore', 'server/go.mod', 'server/go.sum',
    'server/admin-ui/package.json', 'server/admin-ui/package-lock.json',
    'scripts/install-server-docker.sh', 'deploy/selfhost/compose.production.yml',
    'deploy/selfhost/compose.build.yml', 'server/run.sh',
}


class SourcePackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / 'repository'
        self.repo.mkdir()
        self.output = self.root / 'output'
        self.git('init', '-q')
        for name in sorted(SOURCE_NAMES):
            target = self.repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('committed ' + name + '\n')
        (self.repo / 'server/run.sh').chmod(0o755)
        self.source_sha = self.commit()

    def git(self, *args):
        return subprocess.check_output(
            ['git', '-C', str(self.repo), *args], stderr=subprocess.DEVNULL,
        ).decode().strip()

    def commit(self):
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.com',
                 'commit', '-qm', 'source fixture')
        return self.git('rev-parse', 'HEAD')

    def package(self, sha=None, version=VERSION, output=None):
        destination = output or self.output
        PACKAGER.package_source(self.repo, sha or self.source_sha, version, destination)
        return destination / 'p2wlan-server-source.tar.gz'

    def test_committed_snapshot_has_complete_identity_and_checksums(self):
        (self.repo / 'server/go.mod').write_text('new committed version\n')
        self.commit()
        (self.repo / 'server/go.mod').write_text('dirty private value\n')
        untracked = self.repo / 'server/admin-ui/node_modules/untracked.js'
        untracked.parent.mkdir(parents=True)
        untracked.write_text('untracked private value\n')
        archive = self.package()
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.assertEqual(archive.with_name(archive.name + '.sha256').read_text(),
                         digest + '  ' + archive.name + '\n')
        with tarfile.open(archive) as bundle:
            members = bundle.getmembers()
            self.assertEqual(len(members), len(SOURCE_NAMES) + 2)
            self.assertTrue(all(member.isfile() for member in members))
            raw = bundle.extractfile('SERVER-SOURCE.json').read()
            metadata = json.loads(raw)
            self.assertEqual(set(metadata), {'schema_version', 'version', 'source_sha', 'context', 'files'})
            self.assertEqual((metadata['schema_version'], metadata['version'], metadata['source_sha'], metadata['context']),
                             (1, VERSION, self.source_sha, 'server'))
            self.assertEqual(set(metadata['files']), SOURCE_NAMES)
            for name, expected in metadata['files'].items():
                self.assertEqual(hashlib.sha256(bundle.extractfile(name).read()).hexdigest(), expected)
            self.assertEqual(bundle.extractfile('SERVER-SOURCE.json.sha256').read(),
                             (hashlib.sha256(raw).hexdigest() + '  SERVER-SOURCE.json\n').encode())
            self.assertEqual(bundle.extractfile('server/go.mod').read(), b'committed server/go.mod\n')
            self.assertEqual(bundle.getmember('server/run.sh').mode, 0o755)

    def test_cli_and_repeat_builds_bind_the_same_commit_and_version(self):
        process = subprocess.run(
            ['python3', str(SCRIPT), '--repo-root', str(self.repo), '--source-sha', self.source_sha,
             '--version', VERSION, '--output-dir', str(self.output)],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        first = (self.output / 'p2wlan-server-source.tar.gz').read_bytes()
        second = self.package(output=self.root / 'second').read_bytes()
        self.assertEqual(first, second)
        self.assertEqual(first[4:8], b'\0\0\0\0', 'gzip timestamp must not vary the package')

    def test_invalid_tag_or_non_commit_identity_is_rejected(self):
        for version, sha in [('latest', self.source_sha), ('server-v1/other', self.source_sha),
                             (VERSION, 'HEAD'), (VERSION, 'f' * 40)]:
            with self.subTest(version=version, sha=sha):
                with self.assertRaises((ValueError, subprocess.SubprocessError)):
                    self.package(sha=sha, version=version)
                self.assertFalse(self.output.exists())

    def test_tracked_symlink_and_unsafe_names_are_rejected(self):
        cases = ['server/link', 'server/bad\\name', 'server/bad\nname',
                 'server/admin-ui/node_modules/tracked.js']
        for name in cases:
            with self.subTest(name=name):
                target = self.repo / name
                target.parent.mkdir(parents=True, exist_ok=True)
                if name == 'server/link':
                    target.symlink_to('go.mod')
                else:
                    target.write_text('must never ship\n')
                sha = self.commit()
                with self.assertRaises(ValueError):
                    self.package(sha=sha)
                self.assertFalse(self.output.exists())
                target.unlink()
                self.commit()

    def test_missing_build_entry_point_is_rejected(self):
        (self.repo / 'deploy/selfhost/compose.build.yml').unlink()
        with self.assertRaises(ValueError):
            self.package(sha=self.commit())
        self.assertFalse(self.output.exists())

    def test_source_count_and_payload_size_limits_reject_before_output(self):
        for limit, value in [('MAX_FILES', len(SOURCE_NAMES) - 1),
                             ('MAX_FILE_BYTES', 1), ('MAX_TOTAL_BYTES', 1)]:
            with self.subTest(limit=limit), mock.patch.object(PACKAGER, limit, value):
                with self.assertRaises(ValueError):
                    self.package()
                self.assertFalse(self.output.exists())

    def test_expanded_limit_includes_metadata_and_failed_retry_preserves_package(self):
        archive = self.package()
        original = archive.read_bytes()
        with tarfile.open(archive) as bundle:
            expanded_size = sum(member.size for member in bundle.getmembers())
        with mock.patch.object(PACKAGER, 'MAX_TOTAL_BYTES', expanded_size - 1):
            with self.assertRaises(ValueError):
                self.package()
        self.assertEqual(archive.read_bytes(), original)
        self.assertEqual({path.name for path in self.output.iterdir()},
                         {archive.name, archive.name + '.sha256'})


if __name__ == '__main__':
    unittest.main()
