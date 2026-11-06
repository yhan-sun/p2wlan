#!/usr/bin/env python3
"""Package one committed server tree, independently of the working directory."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile


ARCHIVE_NAME = 'p2wlan-server-source.tar.gz'
MAX_FILES = 4096
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
SOURCE_PATHS = (
    'server',
    'scripts/install-server-docker.sh',
    'deploy/selfhost/compose.production.yml',
    'deploy/selfhost/compose.build.yml',
)
REQUIRED_FILES = {
    'server/Dockerfile', 'server/.dockerignore', 'server/go.mod', 'server/go.sum',
    'server/admin-ui/package.json', 'server/admin-ui/package-lock.json',
    *SOURCE_PATHS[1:],
}


def git(repo, *args, **kwargs):
    return subprocess.run(
        ['git', '-C', str(repo), *args], check=True, timeout=120,
        stderr=subprocess.PIPE, **kwargs,
    )


def source_files(repo, source_sha):
    resolved = git(repo, 'rev-parse', '--verify', source_sha + '^{commit}',
                   stdout=subprocess.PIPE).stdout.decode().strip()
    if resolved != source_sha:
        raise ValueError('source SHA must identify the exact commit')
    tree = git(repo, 'ls-tree', '-r', '-l', '-z', '--full-tree', source_sha,
               '--', *SOURCE_PATHS, stdout=subprocess.PIPE).stdout
    files = []
    total = 0
    names = set()
    for record in tree.split(b'\0'):
        if not record:
            continue
        details, raw_name = record.split(b'\t', 1)
        mode, kind, oid, raw_size = details.split()
        name = raw_name.decode('utf-8')
        path = PurePosixPath(name)
        if (path.is_absolute() or str(path) != name or '..' in path.parts
                or '\\' in name or any(ord(c) < 32 or ord(c) == 127 for c in name)
                or 'node_modules' in path.parts or name in names):
            raise ValueError('source tree contains an unsupported file path')
        if kind != b'blob' or mode not in (b'100644', b'100755'):
            raise ValueError('source tree must contain only regular tracked files')
        size = int(raw_size)
        total += size
        if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES or len(files) >= MAX_FILES:
            raise ValueError('source tree exceeds the package size limits')
        names.add(name)
        files.append((name, oid.decode('ascii'), size, 0o755 if mode == b'100755' else 0o644))
    if not REQUIRED_FILES.issubset(names):
        raise ValueError('source commit is missing required deployment or build files')
    return files


def add_file(archive, name, content, mode=0o644):
    member = tarfile.TarInfo(name)
    member.size = len(content)
    member.mode = mode
    member.mtime = 0
    archive.addfile(member, io.BytesIO(content))


def package_source(repo, source_sha, version, output_dir):
    if not re.fullmatch(r'[0-9a-f]{40}', source_sha):
        raise ValueError('source SHA must be 40 lowercase hexadecimal characters')
    if not re.fullmatch(r'server-v[A-Za-z0-9._-]+', version):
        raise ValueError('version must be a fixed server-v release tag')
    files = source_files(repo, source_sha)
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.server-source-', dir=output_dir) as temp:
        temporary = Path(temp)
        objects = temporary / 'objects'
        # Git reads committed blobs, never generated UI, untracked files, or dirty
        # worktree bytes. Batch output goes to disk under the checked total bound.
        with objects.open('wb') as stream:
            git(repo, 'cat-file', '--batch',
                input=''.join(oid + '\n' for _, oid, _, _ in files).encode('ascii'),
                stdout=stream)
        metadata = {
            'schema_version': 1, 'version': version, 'source_sha': source_sha,
            'context': 'server', 'files': {},
        }
        archive_path = temporary / ARCHIVE_NAME
        with (objects.open('rb') as stream, archive_path.open('wb') as output,
              gzip.GzipFile(filename='', fileobj=output, mode='wb', mtime=0) as compressed,
              tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive):
            for name, oid, size, mode in files:
                header = stream.readline(256)
                if header != f'{oid} blob {size}\n'.encode('ascii'):
                    raise ValueError('Git returned an unexpected source object')
                content = stream.read(size)
                if len(content) != size or stream.read(1) != b'\n':
                    raise ValueError('Git returned an incomplete source object')
                metadata['files'][name] = hashlib.sha256(content).hexdigest()
                add_file(archive, name, content, mode)
            if stream.read(1):
                raise ValueError('Git returned unexpected extra source objects')
            raw_metadata = (json.dumps(metadata, indent=2, sort_keys=True) + '\n').encode('utf-8')
            if len(raw_metadata) > MAX_METADATA_BYTES:
                raise ValueError('source metadata exceeds its size limit')
            metadata_checksum = hashlib.sha256(raw_metadata).hexdigest() + '  SERVER-SOURCE.json\n'
            if sum(size for _, _, size, _ in files) + len(raw_metadata) + len(metadata_checksum) > MAX_TOTAL_BYTES:
                raise ValueError('source package exceeds its expanded size limit')
            add_file(archive, 'SERVER-SOURCE.json', raw_metadata)
            add_file(archive, 'SERVER-SOURCE.json.sha256', metadata_checksum.encode('ascii'))
        checksum = hashlib.sha256()
        with archive_path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                checksum.update(block)
        checksum_path = temporary / (ARCHIVE_NAME + '.sha256')
        checksum_path.write_text(checksum.hexdigest() + '  ' + ARCHIVE_NAME + '\n', encoding='ascii')
        os.replace(archive_path, output_dir / ARCHIVE_NAME)
        os.replace(checksum_path, output_dir / checksum_path.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        package_source(args.repo_root, args.source_sha, args.version, args.output_dir)
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, f'Cannot package server source: {error}\n')
    print(args.output_dir / ARCHIVE_NAME)


if __name__ == '__main__':
    main()
