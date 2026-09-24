#!/usr/bin/env python3
"""Resolve Cargo's exact test artifact and reject empty or ignored-only selections."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[2]


class TestSelectionError(RuntimeError):
    pass


def test_executables(messages: Iterable[dict]) -> set[Path]:
    return {
        Path(message["executable"])
        for message in messages
        if message.get("reason") == "compiler-artifact"
        and "lib" in message.get("target", {}).get("kind", [])
        and message.get("profile", {}).get("test") is True
        and isinstance(message.get("executable"), str)
        and message["executable"]
    }


def build_test_binary(root: Path, package: str, transcript_path: Path | None = None) -> Path:
    messages = []
    command = ["cargo", "test", "--locked", "-p", package, "--lib", "--no-run", "--message-format=json"]
    with subprocess.Popen(
        command,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if transcript_path is not None else None,
        text=True,
    ) as process:
        assert process.stdout is not None
        if transcript_path is None:
            for line in process.stdout:
                _consume_build_line(line, messages)
        else:
            transcript_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with transcript_path.open("w", encoding="utf-8") as transcript:
                os.chmod(transcript_path, 0o600)
                for line in process.stdout:
                    transcript.write(line)
                    transcript.flush()
                    _consume_build_line(line, messages)
        returncode = process.wait()
    if returncode:
        raise TestSelectionError(f"Cargo test build failed ({returncode}); no existing binary will be reused")
    candidates = test_executables(messages)
    if len(candidates) != 1:
        raise TestSelectionError(f"expected exactly one Cargo library test executable, found {len(candidates)}")
    binary = candidates.pop()
    if not binary.is_file():
        raise TestSelectionError(f"Cargo reported a missing test executable: {binary}")
    return binary


def _consume_build_line(line: str, messages: list[dict]) -> None:
    try:
        message = json.loads(line)
    except ValueError:
        print(line, end="")
        return
    if not isinstance(message, dict):
        return
    messages.append(message)
    if message.get("reason") == "compiler-message":
        rendered = message.get("message", {}).get("rendered")
        if rendered:
            print(rendered, end="", file=sys.stderr)


def parse_run_plan(raw: str) -> list[dict]:
    try:
        plan = json.loads(raw)
    except ValueError as error:
        raise TestSelectionError(f"invalid run plan JSON: {error}") from error
    if not isinstance(plan, list) or not plan:
        raise TestSelectionError("run plan must be a non-empty JSON array")
    names: set[str] = set()
    normalized = []
    for index, group in enumerate(plan):
        if not isinstance(group, dict):
            raise TestSelectionError(f"run plan group {index} must be an object")
        if set(group) - {"name", "selector", "exact", "repeat"}:
            raise TestSelectionError(f"run plan group {index} has unknown fields")
        name = group.get("name")
        selector = group.get("selector")
        exact = group.get("exact", False)
        repeat = group.get("repeat", 1)
        if not isinstance(name, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", name) is None:
            raise TestSelectionError(f"run plan group {index} has an invalid name")
        if name in names:
            raise TestSelectionError(f"duplicate run plan group name: {name}")
        names.add(name)
        if not isinstance(selector, str) or not selector.strip():
            raise TestSelectionError(f"run plan group {name} has an empty selector")
        if not isinstance(exact, bool):
            raise TestSelectionError(f"run plan group {name} exact must be boolean")
        if type(repeat) is not int or not 1 <= repeat <= 20:
            raise TestSelectionError(f"run plan group {name} repeat must be between 1 and 20")
        if repeat > 1 and not exact:
            raise TestSelectionError(f"repeated run plan group {name} must use an exact selector")
        normalized.append({"name": name, "selector": selector, "exact": exact, "repeat": repeat})
    if sum(group["repeat"] for group in normalized) > 32:
        raise TestSelectionError("run plan exceeds the 32-process capacity limit")
    return normalized


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_identity(root: Path) -> dict:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    patch = subprocess.run(
        ["git", "diff", "--binary", "HEAD"], cwd=root, check=True, capture_output=True
    ).stdout
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    digest = hashlib.sha256()
    digest.update(patch)
    untracked_paths = [Path(path.decode("utf-8")) for path in untracked.split(b"\0") if path]
    for relative in sorted(untracked_paths):
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update((root / relative).read_bytes())
    return {
        "commit": head,
        "dirty": bool(status),
        "status_entry_count": len([entry for entry in status.split(b"\0") if entry]),
        "status_sha256": _sha256_bytes(status),
        "worktree_patch_sha256": digest.hexdigest(),
    }


def toolchain_identity() -> dict:
    rustc = subprocess.run(["rustc", "-Vv"], check=True, capture_output=True, text=True).stdout.strip()
    cargo = subprocess.run(["cargo", "-V"], check=True, capture_output=True, text=True).stdout.strip()
    variables = (
        "RUSTUP_TOOLCHAIN",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET",
        "CARGO_PROFILE_TEST_OPT_LEVEL",
        "CARGO_PROFILE_TEST_DEBUG",
    )
    return {"rustc_verbose": rustc, "cargo": cargo, "environment": {key: os.environ[key] for key in variables if key in os.environ}}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _private_text(path: Path, content: str) -> None:
    with path.open("w", encoding="utf-8") as output:
        output.write(content)
    os.chmod(path, 0o600)


def _mark_not_run(groups: list[dict], from_group: int, reason: str) -> None:
    for group in groups[from_group:]:
        if group.get("status") in {"pending", "ready", "running"}:
            group["status"] = "not_run"
            group["not_run_reason"] = reason
        for run in group.get("runs", []):
            if run.get("status") == "pending":
                run["status"] = "not_run"
                run["not_run_reason"] = reason


def run_plan(
    root: Path,
    package: str,
    plan: list[dict],
    evidence_dir: Path,
    test_timeout_seconds: int,
) -> int:
    root = root.resolve()
    evidence_dir = evidence_dir.resolve()
    if evidence_dir == root or root in evidence_dir.parents:
        raise TestSelectionError("evidence directory must be outside the repository")
    if evidence_dir.exists():
        raise TestSelectionError(f"evidence directory already exists: {evidence_dir}")
    evidence_dir.mkdir(parents=True, mode=0o700)
    os.chmod(evidence_dir, 0o700)
    log_dir = evidence_dir / "logs"
    log_dir.mkdir(mode=0o700)
    manifest_path = evidence_dir / "manifest.json"
    build_command = ["cargo", "test", "--locked", "-p", package, "--lib", "--no-run", "--message-format=json"]
    groups = [
        {
            **group,
            "status": "pending",
            "selected_tests": [],
            "runs": [
                {"iteration": iteration, "status": "pending"}
                for iteration in range(1, group["repeat"] + 1)
            ],
        }
        for group in plan
    ]
    manifest = {
        "schema_version": 1,
        "started_at": _utc_now(),
        "finished_at": None,
        "result": "running",
        "package": package,
        "source": None,
        "toolchain": None,
        "build": {
            "status": "pending",
            "command": build_command,
            "profile": "test",
            "features": "Cargo defaults; no feature override",
            "target": "native rustc host",
        },
        "binary": None,
        "test_timeout_seconds": test_timeout_seconds,
        "groups": groups,
    }

    def save() -> None:
        _atomic_json(manifest_path, manifest)

    save()
    active_group_index = 0
    try:
        starting_source = source_identity(root)
        manifest["source"] = starting_source
        manifest["toolchain"] = toolchain_identity()
        manifest["build"]["status"] = "running"
        manifest["build"]["started_at"] = _utc_now()
        save()
        build_log = log_dir / "build.stdout.log"
        binary = build_test_binary(root, package, transcript_path=build_log).resolve()
        manifest["build"].update({"status": "passed", "finished_at": _utc_now(), "returncode": 0})
        if source_identity(root) != starting_source:
            raise TestSelectionError("source tree changed while the test binary was building")
        manifest["binary"] = {"path": str(binary), "sha256": sha256_file(binary)}
        names = list_tests(binary)
        ignored = list_tests(binary, ignored=True)
        selection_error: tuple[int, str] | None = None
        for index, group in enumerate(groups):
            try:
                selected = select_tests(names, group["selector"], group["exact"], ignored)
                if group["repeat"] > 1 and len(selected) != 1:
                    raise TestSelectionError(
                        f"repeated exact selector must resolve to one runnable test, found {len(selected)}"
                    )
                group["selected_tests"] = selected
                group["status"] = "ready"
            except TestSelectionError as error:
                group["status"] = "failed"
                group["selection_error"] = str(error)
                selection_error = (index, str(error))
                break
        if selection_error:
            _mark_not_run(groups, selection_error[0] + 1, "another group selection was invalid")
            raise TestSelectionError(f"group {groups[selection_error[0]]['name']}: {selection_error[1]}")
        save()

        for active_group_index, group in enumerate(groups):
            group["status"] = "running"
            group["started_at"] = _utc_now()
            save()
            for run in group["runs"]:
                if source_identity(root) != starting_source:
                    run.update({"status": "failed", "error": "source tree changed during test plan"})
                    group["status"] = "failed"
                    raise TestSelectionError("source tree changed during test plan")
                if sha256_file(binary) != manifest["binary"]["sha256"]:
                    run.update({"status": "failed", "error": "test binary changed during test plan"})
                    group["status"] = "failed"
                    raise TestSelectionError("test binary changed during test plan")
                run["started_at"] = _utc_now()
                run["status"] = "running"
                selector = group["selector"]
                command = [str(binary), selector, "--test-threads=1"]
                if group["exact"]:
                    command.append("--exact")
                run["command"] = command
                run["expected_executed"] = len(group["selected_tests"])
                run["test_names"] = group["selected_tests"]
                save()
                prefix = f"{group['name']}-{run['iteration']:02d}"
                stdout_path = log_dir / f"{prefix}.stdout.log"
                stderr_path = log_dir / f"{prefix}.stderr.log"
                began = time.monotonic()
                try:
                    result = subprocess.run(
                        command,
                        cwd=root,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=test_timeout_seconds,
                    )
                    stdout = result.stdout
                    stderr = result.stderr
                    returncode = result.returncode
                    status = "passed" if returncode == 0 else "failed"
                    if status == "passed":
                        try:
                            assert_executed(stdout, len(group["selected_tests"]))
                        except TestSelectionError as error:
                            status = "failed"
                            run["error"] = str(error)
                except subprocess.TimeoutExpired as error:
                    stdout = error.stdout or ""
                    stderr = error.stderr or ""
                    returncode = None
                    status = "timed_out"
                    run["error"] = f"test process exceeded {test_timeout_seconds}s timeout"
                except OSError as error:
                    stdout = ""
                    stderr = str(error)
                    returncode = None
                    status = "failed"
                    run["error"] = f"could not start test process: {error}"
                if isinstance(stdout, bytes):
                    stdout = stdout.decode("utf-8", errors="replace")
                if isinstance(stderr, bytes):
                    stderr = stderr.decode("utf-8", errors="replace")
                _private_text(stdout_path, stdout)
                _private_text(stderr_path, stderr)
                elapsed_ms = round((time.monotonic() - began) * 1000)
                run.update(
                    {
                        "status": status,
                        "finished_at": _utc_now(),
                        "duration_ms": elapsed_ms,
                        "returncode": returncode,
                        "stdout_log": str(stdout_path.relative_to(evidence_dir)),
                        "stderr_log": str(stderr_path.relative_to(evidence_dir)),
                    }
                )
                counts = re.findall(
                    r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;",
                    stdout,
                )
                run["actual_executed"] = (
                    int(counts[-1][0]) + int(counts[-1][1]) if counts else None
                )
                run["ignored_reported"] = int(counts[-1][2]) if counts else None
                print(
                    f"{group['name']} iteration {run['iteration']}/{group['repeat']}: {status} "
                    f"({elapsed_ms} ms, expected {run['expected_executed']} tests)",
                    flush=True,
                )
                print(stdout, end="")
                if stderr:
                    print(stderr, end="", file=sys.stderr)
                if status != "passed":
                    group["status"] = "failed"
                    _mark_not_run(groups, active_group_index, f"stopped after {group['name']} iteration {run['iteration']} {status}")
                    save()
                    manifest["result"] = "failed"
                    manifest["finished_at"] = _utc_now()
                    save()
                    return 1
                if source_identity(root) != starting_source:
                    run["status"] = "failed"
                    run["error"] = "source tree changed during test process"
                    group["status"] = "failed"
                    _mark_not_run(groups, active_group_index, f"stopped after {group['name']} source changed")
                    save()
                    manifest["result"] = "failed"
                    manifest["error"] = run["error"]
                    manifest["finished_at"] = _utc_now()
                    save()
                    return 1
                if toolchain_identity() != manifest["toolchain"]:
                    run["status"] = "failed"
                    run["error"] = "toolchain identity changed during test plan"
                    group["status"] = "failed"
                    _mark_not_run(groups, active_group_index, f"stopped after {group['name']} toolchain changed")
                    save()
                    manifest["result"] = "failed"
                    manifest["error"] = run["error"]
                    manifest["finished_at"] = _utc_now()
                    save()
                    return 1
                if sha256_file(binary) != manifest["binary"]["sha256"]:
                    run["status"] = "failed"
                    run["error"] = "test binary changed during test process"
                    group["status"] = "failed"
                    _mark_not_run(groups, active_group_index, f"stopped after {group['name']} binary changed")
                    save()
                    manifest["result"] = "failed"
                    manifest["error"] = run["error"]
                    manifest["finished_at"] = _utc_now()
                    save()
                    return 1
                save()
            group["status"] = "passed"
            group["finished_at"] = _utc_now()
            save()
        manifest["result"] = "passed"
        manifest["finished_at"] = _utc_now()
        save()
        return 0
    except (OSError, subprocess.CalledProcessError, TestSelectionError) as error:
        if manifest["build"]["status"] in {"pending", "running"}:
            manifest["build"]["status"] = "failed"
            manifest["build"]["error"] = str(error)
            manifest["build"]["finished_at"] = _utc_now()
        if active_group_index < len(groups) and groups[active_group_index].get("status") == "running":
            groups[active_group_index]["status"] = "failed"
            groups[active_group_index]["error"] = str(error)
        _mark_not_run(groups, active_group_index, f"run plan stopped: {error}")
        manifest["result"] = "failed"
        manifest["error"] = str(error)
        manifest["finished_at"] = _utc_now()
        save()
        print(f"FAIL Rust test plan: {error}", file=sys.stderr)
        return 1


def parse_test_names(output: str) -> list[str]:
    return [line.removesuffix(": test") for line in output.splitlines() if line.endswith(": test")]


def select_tests(names: Iterable[str], selector: str, exact: bool, ignored: Iterable[str] = ()) -> list[str]:
    selected = sorted({name for name in names if name == selector or (not exact and selector in name)})
    runnable = sorted(set(selected) - set(ignored))
    if not runnable:
        detail = "only ignored tests matched" if selected else "no tests matched"
        raise TestSelectionError(f"{detail}: {selector!r}")
    return runnable


def list_tests(binary: Path, ignored: bool = False) -> list[str]:
    command = [str(binary), "--list", "--format=terse"]
    if ignored:
        command.append("--ignored")
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return parse_test_names(result.stdout)


def assert_executed(output: str, expected: int) -> None:
    summaries = re.findall(r"test result: ok\. (\d+) passed;", output)
    if len(summaries) != 1 or int(summaries[0]) != expected:
        raise TestSelectionError(f"expected {expected} executed tests; libtest reported {summaries}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("selector", nargs="?")
    parser.add_argument("--package", default="p2wlan-daemon")
    parser.add_argument("--exact", action="store_true")
    parser.add_argument("--each", action="store_true", help="run each selected test in its own process")
    parser.add_argument("--show-output", action="store_true")
    parser.add_argument("--nocapture", action="store_true")
    parser.add_argument("--plan", type=Path, help="JSON test groups to build once and execute in order")
    parser.add_argument("--evidence-dir", type=Path, help="new private directory outside the repository")
    parser.add_argument("--test-timeout-seconds", type=int, default=60)
    args = parser.parse_args(argv)
    if args.plan is not None:
        if any((args.selector, args.exact, args.each, args.show_output, args.nocapture)):
            parser.error("--plan cannot be combined with a positional selector or legacy run options")
        if args.evidence_dir is None:
            parser.error("--evidence-dir is required with --plan")
        if not 1 <= args.test_timeout_seconds <= 300:
            parser.error("--test-timeout-seconds must be between 1 and 300")
        try:
            plan = parse_run_plan(args.plan.read_text(encoding="utf-8"))
            return run_plan(ROOT, args.package, plan, args.evidence_dir, args.test_timeout_seconds)
        except (OSError, TestSelectionError) as error:
            print(f"FAIL Rust test plan: {error}", file=sys.stderr)
            return 1
    if args.selector is None:
        parser.error("selector is required unless --plan is used")
    try:
        binary = build_test_binary(ROOT, args.package)
        selected = select_tests(list_tests(binary), args.selector, args.exact, list_tests(binary, ignored=True))
        print(f"Selected {len(selected)} runnable tests from {binary.name}", flush=True)
        batches = [(name, True, 1) for name in selected] if args.each else [(args.selector, args.exact, len(selected))]
        for selector, exact, expected in batches:
            command = [str(binary), selector, "--test-threads=1"]
            if exact:
                command.append("--exact")
            if args.show_output:
                command.append("--show-output")
            if args.nocapture:
                command.append("--nocapture")
            result = subprocess.run(command, capture_output=True, text=True)
            print(result.stdout, end="")
            print(result.stderr, end="", file=sys.stderr)
            if result.returncode:
                raise TestSelectionError(f"test process failed ({result.returncode}): {selector}")
            assert_executed(result.stdout, expected)
    except (OSError, subprocess.CalledProcessError, TestSelectionError) as error:
        print(f"FAIL Rust test selection: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
