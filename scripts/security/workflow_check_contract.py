#!/usr/bin/env python3
"""Validate that workflow required-check consumers name real unique jobs."""

from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path


STRING_RE = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"")
REQUIRED_ARRAY_RE = re.compile(r"\brequiredNames\s*=\s*\[")
JOB_ID_RE = re.compile(r"([A-Za-z0-9_-]+):\s*$")


def _meaningful_lines(text: str) -> list[tuple[int, int, str]]:
    lines: list[tuple[int, int, str]] = []
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        content = raw.strip()
        if content.startswith("#"):
            continue
        lines.append((number, indent, content))
    return lines


def _scalar(value: str) -> str:
    value = value.split(" #", 1)[0].strip()
    if len(value) >= 2 and value[0] in "'\"" and value[-1] == value[0]:
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return value[1:-1]
        return parsed if isinstance(parsed, str) else value[1:-1]
    return value


def _declared_job_names(path: Path, text: str) -> list[dict[str, object]]:
    """Extract GitHub Actions job display names without a YAML dependency."""

    lines = _meaningful_lines(text)
    in_jobs = False
    current: dict[str, object] | None = None
    jobs: list[dict[str, object]] = []

    for number, indent, content in lines:
        if not in_jobs:
            if indent == 0 and content == "jobs:":
                in_jobs = True
            continue
        if indent == 0:
            break
        if indent == 2:
            match = JOB_ID_RE.fullmatch(content)
            if match:
                if current is not None:
                    jobs.append(current)
                current = {
                    "job_id": match.group(1),
                    "name": None,
                    "line": number,
                }
            continue
        if current is not None and indent == 4 and content.startswith("name:"):
            current["name"] = _scalar(content[len("name:") :])

    if current is not None:
        jobs.append(current)

    declared: list[dict[str, object]] = []
    for job in jobs:
        name = job["name"] or job["job_id"]
        if not isinstance(name, str) or not name:
            continue
        declared.append(
            {
                "path": path.as_posix(),
                "job_id": job["job_id"],
                "name": name,
                "line": job["line"],
                "dynamic": "${{" in name,
            }
        )
    return declared


def _matching_bracket(text: str, opening: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening, len(text)):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return index
    return None


def _required_arrays(path: Path, text: str) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    arrays: list[dict[str, object]] = []
    findings: list[dict[str, object]] = []
    for match in REQUIRED_ARRAY_RE.finditer(text):
        opening = text.find("[", match.start(), match.end())
        closing = _matching_bracket(text, opening)
        line = text.count("\n", 0, match.start()) + 1
        if closing is None:
            findings.append(
                {
                    "path": path.as_posix(),
                    "line": line,
                    "code": "required_check_parse_error",
                    "message": "requiredNames array is not closed",
                }
            )
            continue

        body = text[opening + 1 : closing]
        without_comments = re.sub(r"//[^\n]*|/\*.*?\*/", "", body, flags=re.S)
        strings = []
        for string_match in STRING_RE.finditer(without_comments):
            try:
                value = ast.literal_eval(string_match.group(0))
            except (SyntaxError, ValueError):
                value = None
            if not isinstance(value, str) or not value:
                findings.append(
                    {
                        "path": path.as_posix(),
                        "line": line,
                        "code": "required_check_parse_error",
                        "message": "requiredNames contains an invalid string literal",
                    }
                )
            else:
                strings.append(value)
        remainder = STRING_RE.sub("", without_comments)
        if re.sub(r"[\s,]", "", remainder):
            findings.append(
                {
                    "path": path.as_posix(),
                    "line": line,
                    "code": "required_check_parse_error",
                    "message": "requiredNames contains a non-literal entry",
                }
            )
        arrays.append({"path": path.as_posix(), "line": line, "names": strings})
    return arrays, findings


def run(root: Path) -> dict[str, object]:
    workflow_root = root / ".github" / "workflows"
    findings: list[dict[str, object]] = []
    declared: list[dict[str, object]] = []
    required_arrays: list[dict[str, object]] = []

    paths = sorted([*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml")])
    if not paths:
        findings.append(
            {
                "path": ".github/workflows",
                "line": None,
                "code": "workflow_scope_empty",
                "message": "no workflow files were found",
            }
        )

    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            findings.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "line": None,
                    "code": "workflow_read_failed",
                    "message": str(error),
                }
            )
            continue
        relative_path = path.relative_to(root)
        jobs = _declared_job_names(relative_path, text)
        if not jobs:
            findings.append(
                {
                    "path": relative_path.as_posix(),
                    "line": None,
                    "code": "workflow_jobs_missing",
                    "message": "workflow has no statically readable jobs",
                }
            )
        declared.extend(jobs)
        arrays, array_findings = _required_arrays(relative_path, text)
        required_arrays.extend(arrays)
        findings.extend(array_findings)

    by_name: dict[str, list[dict[str, object]]] = {}
    for check in declared:
        by_name.setdefault(str(check["name"]), []).append(check)
    for name, occurrences in sorted(by_name.items()):
        if len(occurrences) > 1:
            findings.append(
                {
                    "path": ", ".join(str(item["path"]) for item in occurrences),
                    "line": None,
                    "code": "declared_check_ambiguous",
                    "message": f"job display name {name!r} is declared more than once",
                }
            )

    static_by_name = {
        name: occurrences
        for name, occurrences in by_name.items()
        if not any(bool(item["dynamic"]) for item in occurrences)
    }
    for array in required_arrays:
        names = [str(name) for name in array["names"]]
        seen: set[str] = set()
        for name in names:
            if name in seen:
                findings.append(
                    {
                        "path": str(array["path"]),
                        "line": array["line"],
                        "code": "required_check_duplicate",
                        "message": f"requiredNames repeats {name!r}",
                    }
                )
            seen.add(name)
            occurrences = static_by_name.get(name, [])
            if not occurrences:
                findings.append(
                    {
                        "path": str(array["path"]),
                        "line": array["line"],
                        "code": "required_check_missing",
                        "message": f"required check {name!r} has no unique literal job declaration",
                    }
                )
            elif len(occurrences) > 1:
                findings.append(
                    {
                        "path": str(array["path"]),
                        "line": array["line"],
                        "code": "required_check_ambiguous",
                        "message": f"required check {name!r} resolves to multiple jobs",
                    }
                )

    return {
        "result": "pass" if not findings else "fail",
        "declared_checks": declared,
        "required_arrays": required_arrays,
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    evidence = run(args.root.resolve())
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if evidence["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
