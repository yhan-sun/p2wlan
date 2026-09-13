"""Start one self-hosted service from literal environment values; never eval/source JSON."""
import argparse
import os
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=('control', 'relay'))
    parser.add_argument('--config-dir', required=True, type=Path)
    parser.add_argument('--bin-dir', required=True, type=Path)
    args = parser.parse_args()
    env = os.environ.copy()
    for line in (args.config_dir / (args.role + '.env')).read_text(encoding='utf-8-sig').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or not re.fullmatch('[A-Z][A-Z0-9_]*', key):
            parser.error('Invalid environment entry; expected NAME=literal-value')
        env[key] = value
    binary = (args.bin_dir / ('p2wlan-' + args.role + ('.exe' if os.name == 'nt' else ''))).resolve()
    process = subprocess.Popen([str(binary)], env=env)
    try:
        return process.wait()
    except KeyboardInterrupt:
        process.terminate()
        try:
            return process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            return 1


if __name__ == '__main__':
    raise SystemExit(main())
