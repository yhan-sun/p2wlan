#!/usr/bin/env python3
"""Verify every downloaded GitHub Release asset against API metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
from pathlib import Path
from typing import Any

from report_common import make_report

REQUIRED_ASSET_PATTERNS = {
    "android_arm64": re.compile(r"android-arm64.*\.apk$"),
    "ios_arm64": re.compile(r"ios-arm64.*\.ipa$"),
    "linux_flutter_x64": re.compile(r"flutter-linux-x64.*\.tar\.gz$"),
    "macos_arm64": re.compile(r"macos-arm64.*\.dmg$"),
    "macos_x64": re.compile(r"macos-x64.*\.dmg$"),
    "windows_x64": re.compile(r"windows-x64.*\.(?:exe|zip)$"),
    "linux_cli_arm64": re.compile(r"linux-arm64-cli.*\.tar\.gz$"),
    "linux_cli_x64": re.compile(r"linux-x64-cli.*\.tar\.gz$"),
}
SHA256_RE = re.compile(r"sha256:([0-9a-fA-F]{64})")
SIDECAR_RE = re.compile(r"([0-9a-fA-F]{64})\s+\*?([^\s]+)\s*")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _path_is_safe(name: str) -> bool:
    path = Path(name)
    return bool(name) and not path.is_absolute() and path.name == name and "\\" not in name


def _report(
    *,
    release: dict[str, Any],
    assets: list[dict[str, Any]],
    verified: list[dict[str, object]],
    findings: list[dict[str, str]],
    head_sha: str | None,
    repository: str | None,
    workflow_sha: str | None,
    asset_classes: dict[str, bool],
    assets_dir: Path,
) -> dict[str, object]:
    counts = {
        "asset_count": len(assets),
        "verified_asset_count": len(verified),
        "mismatch_count": len(findings),
    }
    return make_report(
        component="release_asset_verification",
        head_sha=head_sha,
        workflow_sha=workflow_sha,
        repository=repository,
        result="pass" if not findings else "fail",
        findings=findings,
        tool="verify_release_assets.py",
        tools={
            "python": platform.python_version(),
            "hash": "sha256",
        },
        command=[
            "verify_release_assets.py",
            "--release-json",
            str(release.get("tag_name", "")),
            "--assets-dir",
            assets_dir.as_posix(),
        ],
        evidence_summary={
            **counts,
            "required_asset_classes": asset_classes,
            "release_id": release.get("id"),
            "tag": str(release.get("tag_name", "")),
        },
        digest_source="GitHub Release asset digest metadata",
        release_id=release.get("id"),
        tag=str(release.get("tag_name", "")),
        **counts,
        required_asset_classes=asset_classes,
        assets=verified,
    )


def run(
    release_json: Path,
    assets_dir: Path,
    head_sha: str | None = None,
    *,
    repository: str | None = None,
    workflow_sha: str | None = None,
) -> dict[str, object]:
    findings: list[dict[str, str]] = []
    try:
        raw_release = json.loads(release_json.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raw_release = {}
        findings.append({"code": "invalid_release_json", "message": str(error)})
    release = raw_release if isinstance(raw_release, dict) else {}

    tag = str(release.get("tag_name", ""))
    if release.get("id") is None:
        findings.append({"code": "missing_release_id", "message": "release id is required"})
    if release.get("draft") is not False:
        findings.append(
            {"code": "draft_release", "message": "release is draft or the draft field is missing"}
        )
    if release.get("prerelease") is not False:
        findings.append(
            {"code": "prerelease", "message": "release is a prerelease or the field is missing"}
        )
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", tag):
        findings.append({"code": "invalid_tag", "message": f"unexpected release tag {tag!r}"})

    raw_assets = release.get("assets")
    assets = (
        [item for item in raw_assets if isinstance(item, dict)]
        if isinstance(raw_assets, list)
        else []
    )
    if not isinstance(raw_assets, list):
        findings.append(
            {"code": "assets_missing", "message": "release assets field is missing or not a list"}
        )
    if not assets:
        findings.append({"code": "no_assets", "message": "release has no assets"})
    if isinstance(raw_assets, list) and len(assets) != len(raw_assets):
        findings.append(
            {"code": "invalid_asset_record", "message": "release assets contain a non-object record"}
        )

    metadata_names: list[str] = []
    for asset in assets:
        name = asset.get("name")
        if not isinstance(name, str) or not name:
            findings.append(
                {"code": "invalid_asset_name", "message": "asset name is missing or not a string"}
            )
            continue
        metadata_names.append(name)
        if not _path_is_safe(name):
            findings.append({"code": "unsafe_asset_name", "message": f"unsafe asset name {name!r}"})
    if len(metadata_names) != len(set(metadata_names)):
        findings.append(
            {"code": "duplicate_asset_name", "message": "release metadata contains duplicate names"}
        )

    downloaded_names: list[str] = []
    if assets_dir.is_dir():
        for path in sorted(assets_dir.iterdir()):
            if path.is_symlink() or not path.is_file():
                findings.append({"code": "unsafe_downloaded_entry", "message": path.name})
                continue
            downloaded_names.append(path.name)
    else:
        findings.append({"code": "assets_directory_missing", "message": assets_dir.as_posix()})
    if sorted(metadata_names) != sorted(downloaded_names):
        findings.append(
            {
                "code": "asset_set_mismatch",
                "message": f"metadata={sorted(metadata_names)!r} downloaded={sorted(downloaded_names)!r}",
            }
        )

    verified: list[dict[str, object]] = []
    for asset in sorted(assets, key=lambda item: str(item.get("name", ""))):
        name = asset.get("name")
        if not isinstance(name, str) or not _path_is_safe(name):
            continue
        path = assets_dir / name
        expected_size = asset.get("size")
        digest_value = asset.get("digest")
        digest_match = SHA256_RE.fullmatch(str(digest_value or ""))
        valid = True
        if asset.get("state") != "uploaded":
            findings.append({"code": "asset_not_uploaded", "message": name})
            valid = False
        if not isinstance(expected_size, int) or expected_size <= 0:
            findings.append({"code": "invalid_asset_size", "message": name})
            valid = False
        if digest_match is None:
            findings.append({"code": "missing_asset_digest", "message": name})
            valid = False
        if path.is_symlink() or not path.is_file():
            findings.append({"code": "asset_missing", "message": name})
            continue
        actual_size = path.stat().st_size
        actual_digest = sha256(path)
        if isinstance(expected_size, int) and actual_size != expected_size:
            findings.append(
                {"code": "asset_size_mismatch", "message": f"{name}: expected {expected_size}, got {actual_size}"}
            )
            valid = False
        if digest_match and actual_digest.lower() != digest_match.group(1).lower():
            findings.append(
                {"code": "asset_digest_mismatch", "message": f"{name}: expected {digest_match.group(1)}, got {actual_digest}"}
            )
            valid = False

        sidecar = assets_dir / f"{name}.sha256"
        if sidecar.is_symlink():
            findings.append({"code": "unsafe_checksum_sidecar", "message": sidecar.name})
            valid = False
        elif sidecar.is_file():
            try:
                sidecar_text = sidecar.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as error:
                findings.append(
                    {"code": "invalid_checksum_sidecar", "message": f"{sidecar.name}: {error}"}
                )
                valid = False
            else:
                sidecar_match = SIDECAR_RE.fullmatch(sidecar_text.strip())
                if sidecar_match is None or sidecar_match.group(2) != name:
                    findings.append({"code": "invalid_checksum_sidecar", "message": sidecar.name})
                    valid = False
                elif sidecar_match.group(1).lower() != actual_digest.lower():
                    findings.append({"code": "checksum_sidecar_mismatch", "message": sidecar.name})
                    valid = False

        if valid:
            verified.append({"name": name, "size": actual_size, "sha256": actual_digest})

    pattern_results: dict[str, bool] = {}
    for label, pattern in REQUIRED_ASSET_PATTERNS.items():
        matched = any(
            pattern.search(name)
            for name in metadata_names
            if not name.endswith(".sha256")
        )
        pattern_results[label] = matched
        if not matched:
            findings.append({"code": "required_asset_class_missing", "message": label})

    return _report(
        release=release,
        assets=assets,
        verified=verified,
        findings=findings,
        head_sha=head_sha,
        repository=repository,
        workflow_sha=workflow_sha,
        asset_classes=pattern_results,
        assets_dir=assets_dir,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-json", type=Path, required=True)
    parser.add_argument("--assets-dir", type=Path, required=True)
    parser.add_argument("--head-sha")
    parser.add_argument("--workflow-sha")
    parser.add_argument("--repository")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    evidence = run(
        args.release_json,
        args.assets_dir,
        args.head_sha,
        repository=args.repository,
        workflow_sha=args.workflow_sha,
    )
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if evidence["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
