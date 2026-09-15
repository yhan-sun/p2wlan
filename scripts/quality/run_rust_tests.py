#!/usr/bin/env python3
"""Resolve Cargo's exact test artifact and reject empty or ignored-only selections."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
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


def build_test_binary(root: Path, package: str) -> Path:
    messages = []
    command = ["cargo", "test", "--locked", "-p", package, "--lib", "--no-run", "--message-format=json"]
    with subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, text=True) as process:
        assert process.stdout is not None
        for line in process.stdout:
            try:
                message = json.loads(line)
            except ValueError:
                print(line, end="")
                continue
            if not isinstance(message, dict):
                continue
            messages.append(message)
            if message.get("reason") == "compiler-message":
                rendered = message.get("message", {}).get("rendered")
                if rendered:
                    print(rendered, end="", file=sys.stderr)
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
    parser.add_argument("selector")
    parser.add_argument("--package", default="p2wlan-daemon")
    parser.add_argument("--exact", action="store_true")
    parser.add_argument("--each", action="store_true", help="run each selected test in its own process")
    parser.add_argument("--show-output", action="store_true")
    parser.add_argument("--nocapture", action="store_true")
    args = parser.parse_args(argv)
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
