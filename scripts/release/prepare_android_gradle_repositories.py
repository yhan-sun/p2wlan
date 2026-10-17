#!/usr/bin/env python3
"""Install scoped Flutter plugin repositories into a new, isolated Gradle home."""

import argparse
import hashlib
import json
import os
from pathlib import Path


INIT_SOURCE = Path(__file__).with_name("android_kotlin_repositories.init.gradle")


def prepare(gradle_user_home: Path, flutter_sdk: Path) -> dict:
    if not gradle_user_home.is_absolute():
        raise ValueError("Gradle user home must be absolute")
    if gradle_user_home.exists() or gradle_user_home.is_symlink():
        raise ValueError("Gradle user home must be new")
    parent = gradle_user_home.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("Gradle user home parent must be a directory")
    if any((ancestor / ".git").exists() for ancestor in (parent, *parent.parents)):
        raise ValueError("Gradle user home must be outside Git checkouts")
    sdk = flutter_sdk.resolve(strict=True)
    settings = sdk / "packages/flutter_tools/gradle/settings.gradle.kts"
    if not sdk.is_dir() or not settings.is_file():
        raise ValueError("Flutter SDK Gradle settings are missing")
    source = INIT_SOURCE.read_bytes()
    home = parent / gradle_user_home.name
    home.mkdir(mode=0o700)  # Exclusive creation also rejects a late symlink/replacement.
    init_dir = home / "init.d"
    init_dir.mkdir(mode=0o700)
    target = init_dir / INIT_SOURCE.name
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(source)
    return {
        "gradle_user_home": str(home),
        "flutter_sdk": str(sdk),
        "init_sha256": hashlib.sha256(source).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gradle-user-home", type=Path, required=True)
    parser.add_argument("--flutter-sdk", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = prepare(args.gradle_user_home, args.flutter_sdk)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Android Gradle repository setup failed: {error}\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
