#!/usr/bin/env python3
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def install(bundle: Path) -> None:
    executable = bundle.resolve() / 'p2wlan_flutter_client'
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError('Run this installer from the extracted P2WLAN Linux bundle.')
    value = str(executable)
    if any(character in value for character in '\r\n\x00'):
        raise ValueError('The bundle path contains unsupported characters.')
    escaped = re.sub(r'([\\"`$])', r'\\\1', value).replace('%', '%%')
    data_home = Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share')))
    if not data_home.is_absolute():
        raise ValueError('XDG_DATA_HOME must be an absolute path.')
    directory = data_home / 'applications'
    directory.mkdir(parents=True, exist_ok=True)
    entry = directory / 'com.p2wlan.diagnostics.desktop'
    contents = (
        '[Desktop Entry]\nType=Application\nName=P2WLAN\n'
        f'Exec="{escaped}" %u\nIcon=network-workgroup\nTerminal=false\n'
        'Categories=Network;\nMimeType=x-scheme-handler/p2wlan;\n'
        'StartupWMClass=com.p2wlan.diagnostics\n'
    )
    temporary = entry.with_suffix('.desktop.tmp')
    temporary.write_text(contents, encoding='utf-8')
    temporary.chmod(0o644)
    temporary.replace(entry)
    if shutil.which('update-desktop-database'):
        subprocess.run(['update-desktop-database', str(directory)], check=True)
    if shutil.which('xdg-mime'):
        subprocess.run(['xdg-mime', 'default', entry.name, 'x-scheme-handler/p2wlan'], check=True)
    print(f'Installed P2WLAN room link handler: {entry}')


if __name__ == '__main__':
    try:
        install(Path(__file__).parent)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
