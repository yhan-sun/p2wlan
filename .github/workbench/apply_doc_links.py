import hashlib
import json
import subprocess
import sys
from pathlib import Path

BASE = '48654b20f78adb5d7b90d12aed734a5bfaf05b20'
ALLOWED = {
    'client/daemon/src/control.rs',
    'client/daemon/src/peer/connection/core.rs',
    'client/daemon/src/relay/transport.rs',
    'client/daemon/src/config/types.rs',
    '.github/workflows/ci.yml',
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    root = Path(sys.argv[1]).resolve()
    plan = json.loads(Path(__file__).with_name('doc-links.json').read_text())
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    if head != BASE or plan['base'] != BASE:
        raise ValueError('documentation patch requires the exact validated candidate')
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=root):
        raise ValueError('refusing a dirty checkout')
    if {item['path'] for item in plan['files']} != ALLOWED or len(plan['files']) != len(ALLOWED):
        raise ValueError('documentation patch writes outside its allowed set')
    outputs = []
    for item in plan['files']:
        path = root / item['path']
        raw = path.read_bytes()
        if digest(raw) != item['before']:
            raise ValueError('documentation source digest mismatch: ' + item['path'])
        text = raw.decode('utf-8')
        for old, new in item['replacements']:
            if old not in text:
                raise ValueError('documentation replacement is missing: ' + item['path'])
            text = text.replace(old, new)
        raw = text.encode('utf-8')
        if digest(raw) != item['after']:
            raise ValueError('documentation result digest mismatch: ' + item['path'])
        outputs.append((path, raw))
    for path, raw in outputs:
        path.write_bytes(raw)
    print('PASS exact documentation and rustdoc gate patch: 5 files')


if __name__ == '__main__':
    main()
