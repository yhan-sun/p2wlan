#!/usr/bin/env python3
"""High-confidence tracked-source and generated-artifact credential scanner."""

from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from report_common import make_report

TEXT_SUFFIXES = {
    ".bash",
    ".c",
    ".cc",
    ".cpp",
    ".dart",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".json",
    ".jsonl",
    ".kt",
    ".kts",
    ".log",
    ".md",
    ".ps1",
    ".py",
    ".rs",
    ".stderr",
    ".sh",
    ".swift",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SENSITIVE_BASENAMES = {
    ".env",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "key.properties",
}
SENSITIVE_SUFFIXES = {".jks", ".key", ".keystore", ".p12", ".pfx", ".pem"}
TOKEN_PATTERNS = {
    "github_token": re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
    ),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "stripe_secret": re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    "openai_style_key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
}
BINARY_TOKEN_PATTERNS = {
    name: re.compile(pattern.pattern.encode("ascii"))
    for name, pattern in TOKEN_PATTERNS.items()
}
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r"(?P<body>[\s\S]*?)"
    r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)
BINARY_PRIVATE_KEY_PATTERN = re.compile(
    rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    rb"(?P<body>[\s\S]*?)"
    rb"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)
SAFE_LOG_TERMS = {
    "configured",
    "fingerprint",
    "hash",
    "length",
    "missing",
    "present",
    "redact",
    "redacted",
    "status",
    "type",
}
BEHAVIORAL_SCAN_PREFIXES = (
    ".github/actions/",
    ".github/workflows/",
    "apps/",
    "client/",
    "scripts/",
    "server/",
)
POLICY_FIXTURE_PATHS = {
    "scripts/security/credential_scan.py",
    "scripts/security/tests/test_security_audit.py",
}
SHELL_SUFFIXES = {".sh", ".bash", ".ps1"}
REMOTE_SHELL_PIPE_RE = re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    code: str
    message: str


def tracked_paths(root: Path) -> list[Path]:
    try:
        output = subprocess.check_output(
            ["git", "-C", str(root), "ls-files", "-z"],
            stderr=subprocess.DEVNULL,
        )
        names = [name for name in output.decode().split("\0") if name]
        if names:
            return [root / name for name in names]
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError):
        pass
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and ".git" not in path.parts
    )


def is_text_candidate(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES or path.name in {
        "Cargo.lock",
        "Dockerfile",
        "LICENSE",
        "Makefile",
        "pubspec.lock",
    }


def read_text(path: Path) -> str | None:
    if not is_text_candidate(path):
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _looks_like_real_private_key(body: str) -> bool:
    compact = re.sub(r"\s+", "", body)
    return len(compact) >= 160 and bool(
        re.fullmatch(r"[A-Za-z0-9+/=]+", compact)
    )


def _looks_like_real_private_key_bytes(body: bytes) -> bool:
    compact = re.sub(rb"\s+", b"", body)
    return len(compact) >= 160 and bool(
        re.fullmatch(rb"[A-Za-z0-9+/=]+", compact)
    )


def _is_behavioral_scan_path(relative: str) -> bool:
    return relative.startswith(BEHAVIORAL_SCAN_PREFIXES) or Path(
        relative
    ).suffix.lower() in SHELL_SUFFIXES


def _is_policy_pattern_line(line: str) -> bool:
    lower = line.lower()
    return bool(
        re.search(r"\b(?:git\s+grep|grep|rg)\b", lower)
        or "re.compile(" in lower
        or "regexp(" in lower
    )


def _is_logging_call(line: str) -> bool:
    return bool(
        re.search(
            r"\b(?:debugPrint|print)\s*\("
            r"|\b(?:println|eprintln|trace|debug|info|warn|error)!\s*\("
            r"|\blog\.(?:Print|Printf|Println|Fatalf)\s*\(",
            line,
        )
    )


def _secret_interpolation_is_env_assignment(line: str) -> bool:
    return bool(
        re.fullmatch(
            r"\s+[A-Z][A-Z0-9_]*:\s*\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}\s*",
            line,
        )
    )


def scan_file(path: Path, root: Path, text: str) -> list[Finding]:
    relative = path.relative_to(root).as_posix()
    findings: list[Finding] = []

    for name, pattern in TOKEN_PATTERNS.items():
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    relative,
                    _line_number(text, match.start()),
                    name,
                    "high-confidence credential format found",
                )
            )

    for match in PRIVATE_KEY_PATTERN.finditer(text):
        if _looks_like_real_private_key(match.group("body")):
            findings.append(
                Finding(
                    relative,
                    _line_number(text, match.start()),
                    "private_key",
                    "private key block found",
                )
            )

    behavioral_scan = (
        _is_behavioral_scan_path(relative)
        and relative not in POLICY_FIXTURE_PATHS
    )
    is_actions_yaml = path.suffix.lower() in {".yml", ".yaml"}
    for line_number, line in enumerate(text.splitlines(), 1):
        lower = line.lower()
        stripped = line.lstrip()
        is_pattern_definition = _is_policy_pattern_line(line)
        if behavioral_scan and re.search(
            r"(?:^|[;&|]\s*)set\s+(?:-x|-o\s+xtrace)\b", line
        ):
            findings.append(
                Finding(
                    relative,
                    line_number,
                    "shell_xtrace",
                    "shell xtrace can disclose secrets",
                )
            )
        if (
            behavioral_scan
            and not is_pattern_definition
            and re.search(r"--token(?:[ =]|$)", line)
            and "--token-file" not in line
        ):
            findings.append(
                Finding(
                    relative,
                    line_number,
                    "credential_in_argv",
                    "token transported through process arguments",
                )
            )
        if (
            behavioral_scan
            and not is_pattern_definition
            and ("localstorage" in lower or "sessionstorage" in lower)
        ):
            findings.append(
                Finding(
                    relative,
                    line_number,
                    "browser_secret_storage",
                    "browser storage is forbidden for credentials",
                )
            )
        if (
            is_actions_yaml
            and "${{ secrets." in line
            and not _secret_interpolation_is_env_assignment(line)
        ):
            findings.append(
                Finding(
                    relative,
                    line_number,
                    "direct_actions_secret_interpolation",
                    "Actions secrets must enter commands through an env mapping",
                )
            )
        if (
            behavioral_scan
            and not is_pattern_definition
            and re.search(r"https?://[^\s/@:]+:[^\s/@]+@", line)
        ):
            findings.append(
                Finding(
                    relative,
                    line_number,
                    "credential_in_url",
                    "URL contains inline userinfo credentials",
                )
            )
        if behavioral_scan and not is_pattern_definition and REMOTE_SHELL_PIPE_RE.search(line):
            findings.append(
                Finding(
                    relative,
                    line_number,
                    "remote_shell_pipe",
                    "do not execute a remotely fetched script through a shell pipe",
                )
            )
        has_sensitive_word = bool(
            re.search(
                r"authorization|password|refresh[_-]?token|access[_-]?token|api[_-]?key|secret",
                lower,
            )
        )
        if (
            behavioral_scan
            and not stripped.startswith(("#", "//", "/*", "*"))
            and _is_logging_call(line)
            and has_sensitive_word
            and not any(term in lower for term in SAFE_LOG_TERMS)
        ):
            findings.append(
                Finding(
                    relative,
                    line_number,
                    "sensitive_logging",
                    "logging call references a sensitive value without a safe descriptor",
                )
            )
    return findings


def scan_binary_file(path: Path, root: Path) -> list[Finding]:
    """Scan opaque generated bytes for visible plaintext credentials."""
    relative = path.relative_to(root).as_posix()
    try:
        data = path.read_bytes()
    except OSError:
        return []
    findings: list[Finding] = []
    for name, pattern in BINARY_TOKEN_PATTERNS.items():
        for match in pattern.finditer(data):
            findings.append(
                Finding(
                    relative,
                    data.count(b"\n", 0, match.start()) + 1,
                    f"binary_{name}",
                    "plaintext credential format found in generated bytes",
                )
            )
    for match in BINARY_PRIVATE_KEY_PATTERN.finditer(data):
        if _looks_like_real_private_key_bytes(match.group("body")):
            findings.append(
                Finding(
                    relative,
                    data.count(b"\n", 0, match.start()) + 1,
                    "binary_private_key",
                    "plaintext private key block found in generated bytes",
                )
            )
    return findings


def run(
    root: Path,
    head_sha: str | None = None,
    *,
    scan_binary: bool = False,
    repository: str | None = None,
    workflow_sha: str | None = None,
    component: str | None = None,
) -> dict[str, object]:
    findings: list[Finding] = []
    scanned_text = 0
    scanned_binary = 0
    for path in tracked_paths(root):
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            findings.append(
                Finding(
                    str(path),
                    1,
                    "path_outside_scan_root",
                    "scan path escapes the configured root",
                )
            )
            continue
        if path.is_symlink():
            findings.append(
                Finding(
                    relative,
                    1,
                    "unsafe_symlink",
                    "symlinks are not followed by the credential scanner",
                )
            )
            continue
        text = read_text(path)
        if text is not None:
            scanned_text += 1
            findings.extend(scan_file(path, root, text))
            continue
        if path.name.lower() in SENSITIVE_BASENAMES or path.suffix.lower() in SENSITIVE_SUFFIXES:
            findings.append(
                Finding(
                    relative,
                    1,
                    "tracked_sensitive_file",
                    "sensitive key/config file is tracked",
                )
            )
        if scan_binary:
            scanned_binary += 1
            findings.extend(scan_binary_file(path, root))
    if scanned_text + scanned_binary == 0:
        findings.append(
            Finding(
                ".",
                1,
                "empty_scan_scope",
                "credential scan found no regular files to inspect",
            )
        )
    evidence_component = component or (
        "release_asset_plaintext_scan" if scan_binary else "credential_transport_scan"
    )
    return make_report(
        component=evidence_component,
        head_sha=head_sha,
        workflow_sha=workflow_sha,
        repository=repository,
        result="pass" if not findings else "fail",
        findings=[asdict(finding) for finding in findings],
        tool="credential_scan.py",
        tools={"python": platform.python_version()},
        command=[
            "credential_scan.py",
            "--root",
            root.as_posix(),
            *(["--scan-binary"] if scan_binary else []),
        ],
        evidence_summary={
            "scanned_text_files": scanned_text,
            "scanned_binary_files": scanned_binary,
            "finding_count": len(findings),
        },
        root=root.as_posix(),
        scanned_text_files=scanned_text,
        scanned_binary_files=scanned_binary,
        behavioral_scan_prefixes=list(BEHAVIORAL_SCAN_PREFIXES),
        shell_suffixes=sorted(SHELL_SUFFIXES),
        policy_fixture_paths_excluded_from_behavioral_checks=sorted(
            POLICY_FIXTURE_PATHS
        ),
        allowlisted_false_positives=[
            {
                "path": path,
                "reason": (
                    "scanner implementation or unit-test detector fixture; "
                    "still subject to high-confidence token/private-key patterns"
                ),
            }
            for path in sorted(POLICY_FIXTURE_PATHS)
        ],
        limitations=[
            "opaque proprietary containers are scanned for visible plaintext but are not recursively decoded"
        ]
        if scan_binary
        else [],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--head-sha")
    parser.add_argument("--workflow-sha")
    parser.add_argument("--repository")
    parser.add_argument("--component")
    parser.add_argument(
        "--scan-binary",
        action="store_true",
        help="scan non-text generated files for visible plaintext credentials",
    )
    args = parser.parse_args()
    evidence = run(
        args.root.resolve(),
        args.head_sha,
        scan_binary=args.scan_binary,
        repository=args.repository,
        workflow_sha=args.workflow_sha,
        component=args.component,
    )
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if evidence["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
