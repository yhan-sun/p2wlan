#!/usr/bin/env python3
"""Check the public documentation and repository governance contract."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
REQUIRED = (
    ROOT / "AGENTS.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "SECURITY.md",
    ROOT / "PRIVACY.md",
    DOCS / "README.md",
    DOCS / "quickstart.md",
    DOCS / "guides/self-hosting.md",
    DOCS / "guides/upgrade-and-recovery.md",
    DOCS / "reference/release-contract.md",
)
FORBIDDEN_VALUES = (
    "47" + ".109.40.237",
    "ali" + ".pem",
    "docs/staging-validation.md",
    "docs/self-hosting-and-notifications-plan.md",
    "docs/server-deployment.md",
    "docs/server-upgrade.md",
    "docs/linux-cli.md",
)
LEGACY_DOC_NAMES = {
    "cross-task-integration.md",
    "friend-rooms-handoff.md",
    "friend-rooms-acceptance.md",
    "self-hosting-and-notifications-plan.md",
    "staging-validation.md",
    "relay-room-audit-remediation.md",
    "room-connectivity-repair.md",
    "rekey-maintenance-reliability.md",
    "mobile-lifecycle-device-matrix.md",
    "mobile-lifecycle-identity.md",
    "security-audit.md",
    "server-deployment.md",
    "server-upgrade.md",
    "linux-cli.md",
    "parallel-rooms.md",
    "room-device-controls.md",
    "dplpmtud-business-budget.md",
    "dplpmtud-live-dataplane-acceptance.md",
    "dplpmtud-runtime-foundation.md",
    "nat-traversal-matrix.en.md",
    "nat-traversal-matrix.zh.md",
    "hard-nat-post-fix-validation-plan.zh.md",
    "staging-mini-air.md",
    "production-hardening.en.md",
    "production-hardening.zh.md",
    "audit-remediation-commit-workflow.md",
    "audit-remediation-todo.md",
    "remove-react-unify-flutter-commit-workflow.md",
    "remove-react-unify-flutter-todo.md",
}
LINK_RE = re.compile(r"\]\(([^)#]+)(?:#[^)]+)?\)")
PERSONAL_PATH_RE = re.compile(r"/(?:Users|home)/[A-Za-z0-9_.-]+")
WINDOWS_HOME_RE = re.compile(r"[A-Za-z]:\\Users\\[A-Za-z0-9_.-]+")
PRIVATE_KEY_NAME_RE = re.compile(r"(?:^|[/\\])(?:id_(?:rsa|dsa|ecdsa|ed25519)|[^/\\\s]+\.pem)(?:$|[\s'\"`])", re.IGNORECASE)
TEXT_SCAN_EXEMPTIONS = {
    "scripts/docs/verify_repository.py",
}


def markdown_files() -> list[Path]:
    return sorted(
        path
        for path in DOCS.rglob("*.md")
        if path.is_file() and "docs/adr/" not in path.as_posix()
    )


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    paths = []
    for raw in result.stdout.split(b"\0"):
        if raw:
            paths.append(ROOT / raw.decode("utf-8"))
    return paths


def read_tracked_text(path: Path) -> str | None:
    data = path.read_bytes()
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def check_links(path: Path, text: str, errors: list[str]) -> None:
    for target in LINK_RE.findall(text):
        if target.startswith(("http://", "https://", "mailto:", "codex://")):
            continue
        if target.startswith(("<", "#")):
            continue
        resolved = (path.parent / target).resolve()
        if not resolved.exists():
            errors.append(f"{path.relative_to(ROOT)}: broken link {target}")


def check_repository_text(errors: list[str]) -> int:
    scanned = 0
    for path in tracked_files():
        relative = path.relative_to(ROOT).as_posix()
        if relative in TEXT_SCAN_EXEMPTIONS or not path.is_file():
            continue
        text = read_tracked_text(path)
        if text is None:
            continue
        scanned += 1
        for value in FORBIDDEN_VALUES:
            if value in text:
                errors.append(f"{relative}: forbidden infrastructure reference {value}")
        match = PERSONAL_PATH_RE.search(text) or WINDOWS_HOME_RE.search(text)
        if match:
            errors.append(f"{relative}: personal filesystem path {match.group(0)}")
        if relative.startswith(("docs/", "README", "deploy/staging/", ".github/workflows/")):
            key_match = PRIVATE_KEY_NAME_RE.search(text)
            if key_match and "example" not in key_match.group(0).lower():
                errors.append(f"{relative}: private key filename reference {key_match.group(0).strip()}")
    return scanned


def main() -> int:
    if "--list" in sys.argv:
        for path in markdown_files():
            print(path.relative_to(ROOT))
        return 0

    errors: list[str] = []
    for path in REQUIRED:
        if not path.exists():
            errors.append(f"missing required file: {path.relative_to(ROOT)}")

    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    if "docs/*" in gitignore:
        errors.append(".gitignore hides the public docs tree")
    if any(line.strip() == "deploy/staging/*.env.example" for line in gitignore.splitlines()):
        errors.append(".gitignore hides redacted staging templates")

    for path in markdown_files() + [ROOT / "README.md", ROOT / "README.en.md"]:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        check_links(path, text, errors)

    for path in markdown_files():
        if path.name in LEGACY_DOC_NAMES or "docs/superpowers/" in path.as_posix():
            errors.append(f"process-oriented document remains: {path.relative_to(ROOT)}")

    template_dir = ROOT / "deploy/staging"
    for name in ("control.env.example", "relay.env.example"):
        path = template_dir / name
        if not path.exists():
            errors.append(f"missing public staging template: {path.relative_to(ROOT)}")

    scanned = check_repository_text(errors)

    if errors:
        print("FAIL repository policy")
        for error in errors:
            print(f"- {error}")
        return 1

    print(
        f"PASS repository policy ({len(markdown_files())} public Markdown documents; "
        f"{scanned} tracked text files scanned)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
