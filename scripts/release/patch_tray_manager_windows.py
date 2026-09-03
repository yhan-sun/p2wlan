#!/usr/bin/env python3
"""Patch the Windows initialization bug in the pinned tray_manager package.

tray_manager 0.5.3 declares NOTIFYICONDATA without value-initializing it.
Its first Windows setIcon call reads nid.hIcon before assigning it, which can
turn a clean tray startup into STATUS_FATAL_USER_CALLBACK_EXCEPTION.  Keep the
workaround narrow and auditable: resolve the exact package selected by
.dart_tool/package_config.json, require the known source shape, and change only
that declaration in the pub cache used for the current build.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname


NEEDLE = "  NOTIFYICONDATA nid;"
REPLACEMENT = "  NOTIFYICONDATA nid{};"


def package_root(config_path: Path) -> Path:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    for package in config.get("packages", []):
        if package.get("name") != "tray_manager":
            continue
        root_uri = package.get("rootUri")
        if not isinstance(root_uri, str):
            break
        parsed = urlparse(root_uri)
        if parsed.scheme == "file":
            path = unquote(parsed.path)
            if (
                os.name == "nt"
                and len(path) >= 3
                and path[0] == "/"
                and path[2] == ":"
            ):
                path = path[1:]
            if parsed.netloc:
                path = f"//{parsed.netloc}{path}"
            return Path(url2pathname(path)).resolve()
        if parsed.scheme:
            break
        return (config_path.parent / root_uri).resolve()
    raise RuntimeError("tray_manager was not resolved in package_config.json")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <flutter-client-root>")

    client_root = Path(sys.argv[1]).resolve()
    config_path = client_root / ".dart_tool" / "package_config.json"
    if not config_path.is_file():
        raise RuntimeError(f"Flutter package config not found: {config_path}")

    source_path = package_root(config_path) / "windows" / "tray_manager_plugin.cpp"
    if not source_path.is_file():
        raise RuntimeError(f"tray_manager Windows source not found: {source_path}")

    source = source_path.read_text(encoding="utf-8")
    if REPLACEMENT in source:
        print(f"tray_manager Windows initialization already patched: {source_path}")
        return 0
    if source.count(NEEDLE) != 1:
        raise RuntimeError(
            "unexpected tray_manager Windows source; refusing an unreviewed patch "
            f"in {source_path}"
        )

    patched = source.replace(NEEDLE, REPLACEMENT)
    source_path.write_text(patched, encoding="utf-8", newline="")
    print(f"patched tray_manager Windows initialization: {source_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        print(f"tray_manager Windows patch failed: {error}", file=sys.stderr)
        raise SystemExit(1)
