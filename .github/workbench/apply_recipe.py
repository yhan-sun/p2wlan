import base64
import gzip
import hashlib
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath

BASE = 'f2f601dbb47a705b490491996d16af2e3324d16d'
RECIPE_SHA256 = 'f12ee97cb37806862d250e6d8d3a5cceae201ae534820895c5021500e40f4345'
HERE = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked_path(root, value):
    relative = PurePosixPath(value)
    if relative.is_absolute() or '..' in relative.parts or not relative.parts:
        raise ValueError('invalid relative path: ' + value)
    path = root.joinpath(*relative.parts)
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise ValueError('path escapes checkout: ' + value)
    return path


def shift(line, amount):
    if not line.strip():
        return line
    if amount < 0:
        if not line.startswith(' ' * -amount):
            raise ValueError('invalid indentation removal')
        return line[-amount:]
    return ' ' * amount + line


def payload():
    corrections_path = HERE / 'transport_corrections.json'
    corrections = json.loads(corrections_path.read_text()) if corrections_path.exists() else {}
    parts = []
    for index in range(5):
        name = f'recipe.part{index}.txt'
        text = (HERE / name).read_text().strip()
        if name in corrections:
            entry = corrections[name]
            if digest(text.encode()) != entry['before']:
                raise ValueError('transport correction source mismatch: ' + name)
            for start, end, replacement in sorted(entry['edits'], reverse=True):
                text = text[:start] + replacement + text[end:]
            if digest(text.encode()) != entry['after']:
                raise ValueError('transport correction result mismatch: ' + name)
        parts.append(text)
    raw = gzip.decompress(base64.b64decode(''.join(parts), validate=True))
    if digest(raw) != RECIPE_SHA256:
        raise ValueError('reviewed recipe digest mismatch')
    return json.loads(raw)


def main():
    root = Path(sys.argv[1]).resolve()
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    if head != BASE:
        raise ValueError('source checkout does not match reviewed baseline')
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=root):
        raise ValueError('refusing to modify a dirty checkout')
    plan = payload()
    if plan['base'] != BASE:
        raise ValueError('recipe baseline mismatch')
    sources = []
    for name, expected in plan['sources']:
        data = checked_path(root, name).read_bytes()
        if digest(data) != expected:
            raise ValueError('copy source digest mismatch: ' + name)
        sources.append(data.decode('utf-8').splitlines(keepends=True))
    outputs = []
    seen = set()
    for item in plan['files']:
        name = item['path']
        if name in seen:
            raise ValueError('duplicate target: ' + name)
        seen.add(name)
        path = checked_path(root, name)
        before = digest(path.read_bytes()) if path.exists() else None
        if before != item['before']:
            raise ValueError('target baseline mismatch: ' + name)
        if item.get('delete'):
            outputs.append((path, None))
            continue
        chunks = []
        for operation in item['ops']:
            if isinstance(operation, str):
                chunks.append(operation)
            else:
                source, start, end, amount = operation
                if start < 0 or end < start or end > len(sources[source]):
                    raise ValueError('copy range out of bounds: ' + name)
                chunks.append(''.join(shift(line, amount) for line in sources[source][start:end]))
        data = ''.join(chunks).encode('utf-8')
        if digest(data) != item['after']:
            raise ValueError('reconstructed source digest mismatch: ' + name)
        outputs.append((path, data))
    for path, data in outputs:
        if data is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    print(f'PASS exact reviewed reconstruction: {len(outputs)} files; recipe={RECIPE_SHA256}')


if __name__ == '__main__':
    main()
