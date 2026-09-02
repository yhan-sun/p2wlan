#!/usr/bin/env python3
"""Fail-closed audit of GitHub Actions permission and secret ownership."""

from __future__ import annotations

import argparse
import json
import platform
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

VALID_LEVELS = {"read", "write", "none"}
WRITE_ALLOWLIST = {"release.yml": {"contents"}}
WRITE_ALLOWLIST_REASONS = {
    ".github/workflows/release.yml": {
        "contents": "create and populate the GitHub Release for an immutable v* tag"
    }
}
PRODUCTION_SECRET_NAMES = {
    "ANDROID_KEYSTORE_BASE64",
    "ANDROID_KEYSTORE_PASSWORD",
    "ANDROID_KEY_ALIAS",
    "ANDROID_KEY_PASSWORD",
    "APPLE_CERTIFICATE_BASE64",
    "APPLE_CERTIFICATE_PASSWORD",
    "APPLE_NOTARIZATION_PASSWORD",
    "WINDOWS_SIGNING_CERTIFICATE_BASE64",
    "WINDOWS_SIGNING_CERTIFICATE_PASSWORD",
}
SECRET_REFERENCE_RE = re.compile(
    r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}"
)


@dataclass(frozen=True)
class PermissionBlock:
    scope: str
    permissions: dict[str, str]
    scalar: str | None = None


@dataclass(frozen=True)
class Finding:
    path: str
    scope: str
    code: str
    message: str


def _meaningful_lines(text: str) -> list[tuple[int, int, str]]:
    result: list[tuple[int, int, str]] = []
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        result.append((number, indent, raw.strip()))
    return result


def _parse_mapping(
    lines: list[tuple[int, int, str]], start: int, parent_indent: int
) -> tuple[dict[str, str], int]:
    values: dict[str, str] = {}
    index = start
    while index < len(lines):
        _number, indent, content = lines[index]
        if indent <= parent_indent:
            break
        if indent == parent_indent + 2:
            match = re.fullmatch(
                r"([A-Za-z0-9_-]+):\s*([A-Za-z-]+)", content
            )
            if match:
                values[match.group(1)] = match.group(2).lower()
        index += 1
    return values, index


def parse_permission_blocks(text: str) -> list[PermissionBlock]:
    lines = _meaningful_lines(text)
    blocks: list[PermissionBlock] = []
    current_job: str | None = None
    inside_jobs = False
    index = 0
    while index < len(lines):
        _number, indent, content = lines[index]
        if indent == 0:
            inside_jobs = content == "jobs:"
            current_job = None
        elif inside_jobs and indent == 2:
            match = re.fullmatch(r"([A-Za-z0-9_-]+):", content)
            if match:
                current_job = match.group(1)

        match = re.fullmatch(r"permissions:\s*(.*)", content)
        if match and (
            indent == 0 or (inside_jobs and indent == 4 and current_job)
        ):
            scope = "workflow" if indent == 0 else f"job:{current_job}"
            scalar = match.group(1).strip().lower() or None
            if scalar is None:
                values, next_index = _parse_mapping(lines, index + 1, indent)
                blocks.append(PermissionBlock(scope, values))
                index = next_index
                continue
            blocks.append(PermissionBlock(scope, {}, scalar))
        index += 1
    return blocks


def _top_level_event(text: str, event: str) -> bool:
    lines = _meaningful_lines(text)
    in_on = False
    for _number, indent, content in lines:
        if indent == 0:
            in_on = content == "on:"
            continue
        if in_on and indent == 2 and content.split(":", 1)[0] == event:
            return True
    compact = re.search(r"(?m)^on:\s*\[(?P<events>[^]]+)]\s*$", text)
    return bool(
        compact
        and event
        in {part.strip() for part in compact.group("events").split(",")}
    )


def _has_release_only_trigger(text: str) -> bool:
    if _top_level_event(text, "release"):
        return True
    lines = _meaningful_lines(text)
    in_on = False
    in_push = False
    for _number, indent, content in lines:
        if indent == 0:
            in_on = content == "on:"
            in_push = False
            continue
        if not in_on:
            continue
        if indent == 2:
            in_push = content.split(":", 1)[0] == "push"
            continue
        if in_push and indent == 4 and content.split(":", 1)[0] == "tags":
            return True
    return False


def audit_workflow(
    path: Path, root: Path
) -> tuple[list[PermissionBlock], list[Finding]]:
    relative = path.relative_to(root).as_posix()
    text = path.read_text(encoding="utf-8")
    blocks = parse_permission_blocks(text)
    findings: list[Finding] = []
    workflow_blocks = [block for block in blocks if block.scope == "workflow"]
    if len(workflow_blocks) != 1:
        findings.append(
            Finding(
                relative,
                "workflow",
                "workflow_permissions_missing_or_ambiguous",
                "expected exactly one workflow-level permissions block, "
                f"found {len(workflow_blocks)}",
            )
        )

    if _top_level_event(text, "pull_request_target"):
        findings.append(
            Finding(
                relative,
                "workflow",
                "pull_request_target_forbidden",
                "pull_request_target combines base privilege with untrusted changes",
            )
        )

    secret_names = sorted(set(SECRET_REFERENCE_RE.findall(text)))
    production_names = [
        name for name in secret_names if name in PRODUCTION_SECRET_NAMES
    ]
    if production_names:
        if path.name != "release.yml":
            findings.append(
                Finding(
                    relative,
                    "workflow",
                    "production_secret_outside_release_workflow",
                    "production signing/release secrets are restricted to "
                    "release.yml: " + ", ".join(production_names),
                )
            )
        elif not _has_release_only_trigger(text):
            findings.append(
                Finding(
                    relative,
                    "workflow",
                    "production_secret_without_release_trigger",
                    "release.yml has no release event or push.tags filter",
                )
            )

    for block in blocks:
        if block.scalar:
            if block.scalar == "{}":
                continue
            findings.append(
                Finding(
                    relative,
                    block.scope,
                    "scalar_permissions_forbidden",
                    f"permission scalar {block.scalar!r} is not explicit",
                )
            )
            continue
        if not block.permissions:
            findings.append(
                Finding(
                    relative,
                    block.scope,
                    "empty_permissions_block",
                    "permissions block has no explicit entries",
                )
            )
            continue
        for name, level in sorted(block.permissions.items()):
            if level not in VALID_LEVELS:
                findings.append(
                    Finding(
                        relative,
                        block.scope,
                        "invalid_permission_level",
                        f"{name} uses unsupported level {level!r}",
                    )
                )
                continue
            if level != "write":
                continue
            if name not in WRITE_ALLOWLIST.get(path.name, set()):
                findings.append(
                    Finding(
                        relative,
                        block.scope,
                        "write_permission_not_allowlisted",
                        f"{name}: write is not allowed in {path.name}",
                    )
                )
            if _top_level_event(text, "pull_request") or _top_level_event(
                text, "pull_request_target"
            ):
                findings.append(
                    Finding(
                        relative,
                        block.scope,
                        "write_permission_on_pr_event",
                        f"{name}: write must not be available to PR events",
                    )
                )
    return blocks, findings


def workflow_paths(root: Path) -> Iterable[Path]:
    workflow_root = root / ".github" / "workflows"
    yield from sorted(
        [*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml")]
    )


def run(root: Path, head_sha: str | None = None) -> dict[str, object]:
    all_blocks: dict[str, list[dict[str, object]]] = {}
    all_findings: list[Finding] = []
    paths = list(workflow_paths(root))
    for path in paths:
        blocks, findings = audit_workflow(path, root)
        all_blocks[path.relative_to(root).as_posix()] = [
            asdict(block) for block in blocks
        ]
        all_findings.extend(findings)
    return {
        "schema_version": 1,
        "result": "pass" if not all_findings else "fail",
        "head_sha": head_sha,
        "tool_versions": {"python": platform.python_version()},
        "workflow_count": len(paths),
        "write_allowlist": {
            key: sorted(value) for key, value in WRITE_ALLOWLIST.items()
        },
        "allowlisted_exceptions": [
            {"path": path, "permission": permission, "reason": reason}
            for path, permissions in sorted(WRITE_ALLOWLIST_REASONS.items())
            for permission, reason in sorted(permissions.items())
        ],
        "production_secret_names": sorted(PRODUCTION_SECRET_NAMES),
        "workflows": all_blocks,
        "findings": [asdict(finding) for finding in all_findings],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--head-sha")
    args = parser.parse_args()
    evidence = run(args.root.resolve(), args.head_sha)
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if evidence["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
