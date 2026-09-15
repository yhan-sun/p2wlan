#!/usr/bin/env python3
"""Check source-size budgets against a real Git base, without hiding existing debt."""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUST_PRODUCTION_MAX_BYTES = 96 * 1024
RUST_TEST_MAX_BYTES = 192 * 1024


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class Finding:
    path: str
    category: str
    size: int
    budget: int
    base_size: int | None
    allowed: bool


def git(root: Path, *args: str, data: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", *args], cwd=root, input=data, capture_output=True, check=False
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise PolicyError(f"git {' '.join(args[:2])} failed: {detail}")
    return result.stdout


def normalized_size(content: bytes) -> int:
    return len(content.replace(b"\r\n", b"\n"))


def is_rust_test(path: Path, relative: str) -> bool:
    return (
        "tests" in Path(relative).parts
        or path.name == "tests.rs"
        or path.name.startswith("test_")
    )


def source_paths(root: Path) -> list[str]:
    paths = git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    return sorted(
        {os.fsdecode(raw) for raw in paths.split(b"\0") if raw.endswith(b".rs")}
    )


def base_sizes(root: Path, base_ref: str) -> tuple[str, dict[str, int]]:
    revision = git(root, "rev-parse", "--verify", "--end-of-options", f"{base_ref}^{{commit}}")
    revision_text = revision.decode("ascii").strip()
    entries: list[tuple[str, bytes]] = []
    for record in git(root, "ls-tree", "-r", "-z", revision_text).split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        if raw_path.endswith(b".rs") and kind == b"blob" and mode in (b"100644", b"100755"):
            entries.append((os.fsdecode(raw_path), oid))
    if not entries:
        return revision_text, {}
    output = io.BytesIO(git(root, "cat-file", "--batch", data=b"\n".join(oid for _, oid in entries) + b"\n"))
    sizes: dict[str, int] = {}
    for path, expected_oid in entries:
        header = output.readline().split()
        if len(header) != 3 or header[:2] != [expected_oid, b"blob"]:
            raise PolicyError(f"invalid Git blob response for {path}")
        size = int(header[2])
        content = output.read(size)
        if len(content) != size or output.read(1) != b"\n":
            raise PolicyError(f"incomplete Git blob response for {path}")
        sizes[path] = normalized_size(content)
    return revision_text, sizes


def evaluate(path: str, size: int, base_size: int | None) -> Finding | None:
    test = is_rust_test(Path(path), path)
    budget = RUST_TEST_MAX_BYTES if test else RUST_PRODUCTION_MAX_BYTES
    if size <= budget:
        return None
    return Finding(
        path, "test" if test else "production", size, budget, base_size,
        base_size is not None and base_size > budget and size <= base_size,
    )


def check(root: Path, base_ref: str) -> dict[str, object]:
    revision, previous = base_sizes(root, base_ref)
    findings: list[Finding] = []
    errors: list[str] = []
    scanned = 0
    for relative in source_paths(root):
        path = root / relative
        if path.is_symlink():
            errors.append(f"{relative}: Rust source symlinks cannot bypass the source-size policy")
            continue
        if not path.exists():
            continue
        if not path.is_file():
            errors.append(f"{relative}: expected a regular Rust source file")
            continue
        scanned += 1
        try:
            content = path.read_bytes()
            content.decode("utf-8")
        except (OSError, UnicodeDecodeError) as error:
            errors.append(f"{relative}: cannot inspect source: {error}")
            continue
        finding = evaluate(relative, normalized_size(content), previous.get(relative))
        if finding is not None:
            findings.append(finding)
            if not finding.allowed:
                prior = "new file" if finding.base_size is None else f"base {finding.base_size} bytes"
                errors.append(
                    f"{relative}: {finding.size} bytes exceeds {finding.category} budget "
                    f"{finding.budget} ({prior}); split responsibilities instead of growing debt"
                )
    return {
        "base_commit": revision,
        "scanned_rust_files": scanned,
        "production_budget_bytes": RUST_PRODUCTION_MAX_BYTES,
        "test_budget_bytes": RUST_TEST_MAX_BYTES,
        "debt": [asdict(finding) for finding in findings],
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", default="HEAD", help="trusted comparison commit; CI must provide the PR base or previous push SHA")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
    args = parser.parse_args(argv)
    try:
        report = check(ROOT, args.base_ref)
    except (PolicyError, OSError, ValueError) as error:
        print(f"FAIL code health policy: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, ensure_ascii=True, indent=2))
    else:
        state = "FAIL" if report["errors"] else "PASS"
        print(f"{state} code health policy ({report['scanned_rust_files']} Rust files; base {report['base_commit']})")
        for error in report["errors"]:
            print(f"- {error}")
        retained = [item for item in report["debt"] if item["allowed"]]
        print(f"Existing source-size debt: {len(retained)} files; this is not a complexity or correctness score")
        for item in retained:
            print(f"- {item['path']}: {item['size']} bytes (base {item['base_size']}, budget {item['budget']})")
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
