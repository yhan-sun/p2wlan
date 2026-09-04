#!/usr/bin/env python3
"""Collect exact-test-derived DPLPMTUD live-dataplane evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

REPORT_SCHEMA_VERSION = 1
SHA40 = re.compile(r"^[0-9a-f]{40}$")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
MARKER_PREFIX = "DPLPMTUD_FINAL_EVIDENCE "
FORBIDDEN_IDENTITY_KEYS = {
    "peer_id",
    "remote_endpoint",
    "local_endpoint",
    "authenticated_remote_endpoint",
    "network_identity_hash",
    "path_cookie",
    "nonce",
}
IP_LIKE = re.compile(
    r"(?:\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b|\[[0-9a-fA-F:]+\]:\d+)"
)


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label}_invalid:{path}:{exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label}_not_object:{path}")
    return value


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _validate_sha(value: str, label: str) -> None:
    if SHA40.fullmatch(value) is None:
        raise ValueError(f"{label}_invalid")


def _walk_no_high_cardinality(value: Any, path: str = "record") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_IDENTITY_KEYS:
                raise ValueError(f"high_cardinality_key_forbidden:{path}.{key}")
            _walk_no_high_cardinality(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_no_high_cardinality(child, f"{path}[{index}]")
    elif isinstance(value, str) and IP_LIKE.search(value):
        raise ValueError(f"high_cardinality_value_forbidden:{path}")


def _test_status(log_text: str, test_id: str) -> str:
    clean = ANSI.sub("", log_text)
    exact = re.escape(test_id)
    if re.search(rf"^test {exact} \.\.\. ok(?: \([^)]*\))?$", clean, re.MULTILINE):
        return "pass"
    if re.search(rf"^test {exact} \.\.\. ignored(?: .*)?$", clean, re.MULTILINE):
        return "skipped"
    if re.search(rf"^test {exact} \.\.\. FAILED$", clean, re.MULTILINE):
        return "fail"
    return "missing"


def _marker_records(log_text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw_line in ANSI.sub("", log_text).splitlines():
        line = raw_line.strip()
        if MARKER_PREFIX not in line:
            continue
        payload = line.split(MARKER_PREFIX, 1)[1].strip()
        try:
            value = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError(f"marker_invalid_json:{exc}") from exc
        if not isinstance(value, dict):
            raise ValueError("marker_not_object")
        records.append(value)
    return records


def _summary_tokens(line: str) -> dict[str, str]:
    tokens: dict[str, str] = {}
    for token in line.split()[1:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if re.fullmatch(r"[a-z0-9_]+", key) is None:
            raise ValueError(f"summary_key_invalid:{key}")
        if any(fragment in key for fragment in ("endpoint", "peer_id", "address", "path_cookie", "nonce")):
            raise ValueError(f"summary_high_cardinality_key:{key}")
        if re.fullmatch(r"[A-Za-z0-9_.:-]+", value) is None:
            raise ValueError(f"summary_value_invalid:{key}")
        if IP_LIKE.search(value):
            raise ValueError(f"summary_high_cardinality_value:{key}")
        if key in tokens:
            raise ValueError(f"summary_duplicate_key:{key}")
        tokens[key] = value
    return tokens


def _extract_summary(
    log_text: str,
    prefix: str,
    required_tokens: list[str],
) -> dict[str, str]:
    clean = ANSI.sub("", log_text)
    lines = [line.strip() for line in clean.splitlines() if line.strip().startswith(prefix + " ")]
    if len(lines) != 1:
        raise ValueError(f"summary_line_count:{prefix}:{len(lines)}")
    line = lines[0]
    for token in required_tokens:
        if token not in line.split():
            raise ValueError(f"summary_required_token_missing:{prefix}:{token}")
    return _summary_tokens(line)


def collect(
    contract: dict[str, Any],
    log_root: Path,
    source_head_sha: str,
    workflow_sha: str,
) -> dict[str, Any]:
    _validate_sha(source_head_sha, "source_head_sha")
    _validate_sha(workflow_sha, "workflow_sha")
    if contract.get("schema_version") != 1:
        raise ValueError("contract_schema_unknown")
    if contract.get("repository") != "yhan-sun/p2wlan":
        raise ValueError("contract_repository_mismatch")
    scenarios = contract.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("contract_scenarios_missing")

    seen_scenarios: set[str] = set()
    seen_tests: set[str] = set()
    records: list[dict[str, Any]] = []
    for spec in scenarios:
        if not isinstance(spec, dict):
            raise ValueError("scenario_spec_not_object")
        scenario_id = spec.get("scenario_id")
        test_id = spec.get("test_id")
        log_file = spec.get("log_file")
        category = spec.get("category")
        decision = spec.get("expected_decision")
        if not all(isinstance(value, str) and value for value in (
            scenario_id,
            test_id,
            log_file,
            category,
            decision,
        )):
            raise ValueError("scenario_spec_field_invalid")
        if scenario_id in seen_scenarios:
            raise ValueError(f"duplicate_scenario:{scenario_id}")
        if test_id in seen_tests:
            raise ValueError(f"duplicate_test_mapping:{test_id}")
        seen_scenarios.add(scenario_id)
        seen_tests.add(test_id)

        log_path = log_root / log_file
        if not log_path.is_file() or log_path.stat().st_size == 0:
            raise ValueError(f"test_log_missing:{scenario_id}:{log_path}")
        log_text = log_path.read_text(encoding="utf-8", errors="strict")
        status = _test_status(log_text, test_id)
        if status != "pass":
            raise ValueError(f"test_not_passed:{scenario_id}:{test_id}:{status}")

        observed: dict[str, Any]
        marker_required = spec.get("marker_required")
        if not isinstance(marker_required, bool):
            raise ValueError(f"marker_required_not_boolean:{scenario_id}")
        if marker_required:
            candidates = [
                marker
                for marker in _marker_records(log_text)
                if marker.get("scenario_id") == scenario_id
            ]
            if len(candidates) != 1:
                raise ValueError(f"marker_count_invalid:{scenario_id}:{len(candidates)}")
            marker = candidates[0]
            if marker.get("test_id") != test_id:
                raise ValueError(f"marker_test_id_mismatch:{scenario_id}")
            if marker.get("decision") != decision:
                raise ValueError(f"marker_decision_mismatch:{scenario_id}")
            invariants = marker.get("invariants")
            if not isinstance(invariants, dict) or not invariants:
                raise ValueError(f"marker_invariants_missing:{scenario_id}")
            if any(value is not True for value in invariants.values()):
                raise ValueError(f"marker_invariant_failed:{scenario_id}")
            if scenario_id == "DP-01":
                if marker.get("boundaries") != contract.get("required_boundaries"):
                    raise ValueError("boundary_matrix_mismatch")
                rows = marker.get("rows")
                if not isinstance(rows, list) or len(rows) != 10:
                    raise ValueError("boundary_rows_invalid")
                seen_rows = {
                    (row.get("outer_ip_packet_size"), row.get("outer_ip_family"))
                    for row in rows
                    if isinstance(row, dict)
                }
                expected_rows = {
                    (boundary, family)
                    for boundary in contract["required_boundaries"]
                    for family in ("ipv4", "ipv6")
                }
                if seen_rows != expected_rows:
                    raise ValueError("boundary_rows_incomplete")
            _walk_no_high_cardinality(marker)
            observed = marker
        else:
            prefix = spec.get("summary_prefix")
            required_tokens = spec.get("required_summary_tokens")
            if not isinstance(prefix, str) or not prefix:
                raise ValueError(f"summary_prefix_missing:{scenario_id}")
            if not isinstance(required_tokens, list) or not all(
                isinstance(token, str) and token for token in required_tokens
            ):
                raise ValueError(f"summary_tokens_invalid:{scenario_id}")
            observed = {
                "scenario_id": scenario_id,
                "test_id": test_id,
                "decision": decision,
                "summary_prefix": prefix,
                "summary": _extract_summary(log_text, prefix, required_tokens),
            }
            _walk_no_high_cardinality(observed)

        records.append(
            {
                "scenario_id": scenario_id,
                "category": category,
                "exact_test_id": test_id,
                "executed": True,
                "skipped": False,
                "result": "pass",
                "decision": decision,
                "log_file": log_file,
                "observed": observed,
            }
        )

    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "repository": contract["repository"],
        "component": contract["component"],
        "source_head_sha": source_head_sha,
        "workflow_sha": workflow_sha,
        "contract_sha256": _canonical_sha256(contract),
        "result": "pass",
        "scenario_count": len(records),
        "scenarios": records,
    }
    report["report_digest"] = _canonical_sha256(report)
    return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True)
    parser.add_argument("--log-root", required=True)
    parser.add_argument("--source-head-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    contract = _load_object(Path(args.contract), "contract")
    report = collect(
        contract,
        Path(args.log_root),
        args.source_head_sha,
        args.workflow_sha,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "result": report["result"],
        "scenario_count": report["scenario_count"],
        "report_digest": report["report_digest"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
