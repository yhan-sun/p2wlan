import base64
import hashlib
import json
import lzma
import os
from pathlib import Path
import subprocess

base = 'd100ea89f3cd4aa5ec75105220dcc419ff9b8bfc'
parts = ''.join(Path(f'.room-connectivity-workbench/patch.{i}').read_text().strip() for i in range(5))
patch = lzma.decompress(base64.b64decode(parts, validate=True))
assert hashlib.sha256(patch).hexdigest() == '6e83144e378a5867ed168fd5d788fcc56f9249c766395de62cbc4fdb4cc6455a'
temp = Path(os.environ['RUNNER_TEMP'])
(temp / 'repair.patch').write_bytes(patch)
subprocess.run(['git', 'checkout', '--detach', base], check=True)
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == base
subprocess.run(['git', 'apply', '--check', str(temp / 'repair.patch')], check=True)
subprocess.run(['git', 'apply', '--index', str(temp / 'repair.patch')], check=True)
files = subprocess.check_output(['git', 'diff', '--cached', '--name-only'], text=True).splitlines()
assert files and all(f.startswith(('client/daemon/', 'apps/flutter_client/', 'scripts/room-connectivity/', 'docs/room-connectivity-', '.github/workflows/room-connectivity.yml')) for f in files)
(temp / 'repair-files.json').write_text(json.dumps(files))
print(f'Applied checked patch to {base}: {len(files)} paths')
