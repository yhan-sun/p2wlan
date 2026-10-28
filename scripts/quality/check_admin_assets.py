#!/usr/bin/env python3
"""Verify the content-hashed entry assets referenced by the embedded admin page."""

import argparse
from html.parser import HTMLParser
from pathlib import Path
import re
from urllib.parse import urlsplit


class EntryAssets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.references = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and attrs.get("type") == "module":
            self.references.append(("js", attrs.get("src", "")))
        if tag == "link" and "stylesheet" in attrs.get("rel", "").split():
            self.references.append(("css", attrs.get("href", "")))


def verify_assets(root):
    parser = EntryAssets()
    parser.feed((root / "index.html").read_text(encoding="utf-8"))
    found = set()
    for kind, reference in parser.references:
        url = urlsplit(reference)
        name = url.path.removeprefix("/admin/")
        if (
            url.scheme or url.netloc or url.query or url.fragment
            or not url.path.startswith("/admin/")
            or not re.fullmatch(r"app-[A-Za-z0-9_-]{8,}\." + kind, name)
        ):
            raise ValueError(f"invalid hashed admin {kind} entry: {reference!r}")
        asset = root / name
        if not asset.is_file() or not asset.stat().st_size:
            raise ValueError(f"missing or empty admin entry: {name}")
        found.add(kind)
    if found != {"js", "css"}:
        raise ValueError("admin index must reference hashed JavaScript and CSS entries")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    try:
        verify_assets(args.root)
    except (OSError, ValueError) as error:
        parser.exit(1, f"admin assets: {error}\n")


if __name__ == "__main__":
    main()
