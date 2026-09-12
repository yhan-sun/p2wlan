#!/usr/bin/env python3
"""Aggregate only actually executed NAT replica evidence.

The expected scenario set is generated here from the component contract. It is
not read from a user-controlled manifest, and no one record can fan out to
other scenarios. Every JSON record must identify its exact test invocation and
must independently satisfy the first-usable and revision-fence invariants.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
ATTEMPT_SCHEMA_VERSION = 1
REPOSITORY = "yhan-sun/p2wlan"
EXPECTED_TOPOLOGIES = {
    "direct-cold-start": {1},
    "relay-blackhole": {1, 2, 3, 4, 5},
}
EXPECTED_TEST_ID = re.compile(
    r"^nat-sim-smoke\.sh::(direct-cold-start|relay-blackhole)::replica-([1-5])::round-1$"
)
SHA1 = re.compile(r"^[0-9a-f]{40}$")


def _read_records(root: Path) -> list[tuple[Path, dict[str, Any]]]:
    records: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(root.rglob("nat-evidence.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid_record_json:{path}:{exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"record_not_object:{path}")
        records.append((path, value))
    return records


def _require_bool(value: Any, name: str) -> None:
    if not isinstance(value, bool):
        raise ValueError(f"{name}_must_be_boolean")


def _require_pass_side(
    observed: Any,
    collector: Any,
    invariants: Any,
    label: str,
    expected_path: str,
) -> None:
    if not isinstance(observed, dict) or not isinstance(collector, dict) or not isinstance(invariants, dict):
        raise ValueError(f"{label}_missing")
    first = observed.get("first_usable")
    if not isinstance(first, dict):
        raise ValueError(f"{label}_first_usable_missing")
    process_identity = observed.get("process_identity")
    if not isinstance(process_identity, dict):
        raise ValueError(f"{label}_process_identity_missing")
    baseline_identity = process_identity.get("baseline")
    final_identity = process_identity.get("final")
    if not isinstance(baseline_identity, dict) or not isinstance(final_identity, dict):
        raise ValueError(f"{label}_process_identity_shape_invalid")
    if type(baseline_identity.get("process_id")) is not int:
        raise ValueError(f"{label}_baseline_process_identity_missing")
    if type(final_identity.get("process_id")) is not int:
        raise ValueError(f"{label}_final_process_identity_missing")
    if baseline_identity["process_id"] != final_identity["process_id"]:
        raise ValueError(f"{label}_process_identity_changed")
    if type(final_identity.get("revision")) is not int:
        raise ValueError(f"{label}_final_revision_missing")
    if final_identity.get("captured_revision") != final_identity.get("revision"):
        raise ValueError(f"{label}_final_revision_not_captured")
    if final_identity.get("peer_snapshot_stale") is not False:
        raise ValueError(f"{label}_peer_snapshot_stale")
    path = first.get("path")
    if not isinstance(path, str) or path != expected_path:
        raise ValueError(f"{label}_first_usable_path_mismatch")
    for field in ("first_usable_at_ms", "transition_revision", "delta_ms"):
        if type(first.get(field)) is not int or first[field] < 0:
            raise ValueError(f"{label}_{field}_missing")
    if first["transition_revision"] == 0:
        raise ValueError(f"{label}_transition_revision_missing")
    if first["delta_ms"] > 3000:
        raise ValueError(f"{label}_delta_exceeded")
    source = first.get("source")
    if not isinstance(source, str) or source not in {"persistent_summary", "event"}:
        raise ValueError(f"{label}_collector_source_invalid")
    if not isinstance(first.get("baseline_after_transition"), bool):
        raise ValueError(f"{label}_baseline_order_missing")
    if first.get("baseline_after_transition") is True and first.get("source") != "persistent_summary":
        raise ValueError(f"{label}_baseline_after_transition_without_summary")
    if collector.get("revision_converged") is not True:
        raise ValueError(f"{label}_revision_not_converged")
    if collector.get("invalid_summary_present") is not False:
        raise ValueError(f"{label}_invalid_summary_present")
    if expected_path == "relay" and observed.get("relay_connected") is not True:
        raise ValueError(f"{label}_relay_not_connected")
    if expected_path == "relay":
        if observed.get("relay_peer_confirmed") is not True:
            raise ValueError(f"{label}_relay_peer_not_confirmed")
        if observed.get("first_business_received") is not True:
            raise ValueError(f"{label}_first_business_not_received")
        if not (observed.get("first_business_sent") is True or observed.get("first_business_exchange") is True):
            raise ValueError(f"{label}_first_business_send_missing")
    else:
        if not isinstance(observed.get("direct_promoted"), int) or observed["direct_promoted"] < 1:
            raise ValueError(f"{label}_direct_promotion_missing")
    if not isinstance(observed.get("overlay_verified"), int) or observed["overlay_verified"] < 1:
        raise ValueError(f"{label}_overlay_verification_missing")
    if observed.get("outbound_drop_packets") != 0:
        raise ValueError(f"{label}_outbound_drop")
    if observed.get("replay_rejected") != 0 or observed.get("overlay_invalid") != 0:
        raise ValueError(f"{label}_invalid_or_replay")
    for name, value in invariants.items():
        if value is not True:
            raise ValueError(f"{label}_invariant_failed:{name}")


def validate_record(
    record: dict[str, Any],
    source_head_sha: str,
    workflow_sha: str,
) -> tuple[str, str, int]:
    if not isinstance(source_head_sha, str) or SHA1.fullmatch(source_head_sha) is None:
        raise ValueError("source_head_sha_invalid")
    if not isinstance(workflow_sha, str) or SHA1.fullmatch(workflow_sha) is None:
        raise ValueError("workflow_sha_invalid")
    if type(record.get("schema_version")) is not int or record["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unknown_schema_version")
    if record.get("repository") != REPOSITORY:
        raise ValueError("repository_mismatch")
    if record.get("source_head_sha") != source_head_sha:
        raise ValueError("source_head_sha_mismatch")
    if record.get("workflow_sha") != workflow_sha:
        raise ValueError("workflow_sha_mismatch")
    _require_bool(record.get("executed"), "executed")
    _require_bool(record.get("skipped"), "skipped")
    if record.get("executed") is not True:
        raise ValueError("test_not_executed")
    if record.get("skipped") is not False:
        raise ValueError("test_skipped")
    if record.get("result") != "pass":
        raise ValueError("record_not_pass")

    topology = record.get("topology")
    replica = record.get("replica")
    round_number = record.get("round")
    if (
        not isinstance(topology, str)
        or topology not in EXPECTED_TOPOLOGIES
        or type(replica) is not int
        or type(round_number) is not int
    ):
        raise ValueError("scenario_identity_invalid")
    if replica not in EXPECTED_TOPOLOGIES[topology] or round_number != 1:
        raise ValueError("scenario_not_expected")
    expected_scenario = f"{topology}:replica-{replica}:round-1"
    if record.get("scenario_id") != expected_scenario:
        raise ValueError("scenario_id_mismatch")
    exact_test_id = record.get("exact_test_id")
    match = EXPECTED_TEST_ID.fullmatch(exact_test_id) if isinstance(exact_test_id, str) else None
    if match is None:
        raise ValueError("exact_test_id_invalid")
    if match.group(1) != topology or int(match.group(2)) != replica:
        raise ValueError("exact_test_id_scenario_mismatch")

    observed = record.get("observed")
    collector = record.get("collector")
    invariants = record.get("invariants")
    if not isinstance(observed, dict) or not isinstance(collector, dict) or not isinstance(invariants, dict):
        raise ValueError("record_evidence_shape_invalid")
    expected_path = "relay" if topology == "relay-blackhole" else "direct"
    _require_pass_side(
        observed.get("a"),
        collector.get("a"),
        invariants.get("a"),
        "a",
        expected_path,
    )
    _require_pass_side(
        observed.get("b"),
        collector.get("b"),
        invariants.get("b"),
        "b",
        expected_path,
    )
    if collector.get("revision_converged") is not True:
        raise ValueError("aggregate_revision_not_converged")
    if invariants.get("same_source_head") is not True or invariants.get("same_workflow_sha") is not True:
        raise ValueError("record_identity_invariant_failed")
    decision = record.get("decision")
    if (
        not isinstance(decision, dict)
        or decision.get("result") != "pass"
        or decision.get("reason_code") is not None
        or decision.get("observed_decision") != "first_usable_committed"
    ):
        raise ValueError("observed_decision_invalid")
    return expected_scenario, exact_test_id, replica


def validate_attempt_history(history: Any, record: dict[str, Any]) -> dict[str, Any]:
    if (
        not isinstance(history, dict)
        or type(history.get("schema_version")) is not int
        or history["schema_version"] != ATTEMPT_SCHEMA_VERSION
    ):
        raise ValueError("attempt_history_schema_invalid")
    for field in ("scenario_id", "source_head_sha", "workflow_sha"):
        if history.get(field) != record.get(field):
            raise ValueError(f"attempt_history_{field}_mismatch")
    attempts = history.get("attempts")
    if not isinstance(attempts, list) or not attempts:
        raise ValueError("attempt_history_missing")
    final = history.get("final_adjudication")
    if not isinstance(final, dict):
        raise ValueError("attempt_final_adjudication_missing")

    previous_failures: list[dict[str, Any]] = []
    for index, attempt in enumerate(attempts, start=1):
        if not isinstance(attempt, dict):
            raise ValueError("attempt_record_invalid")
        if type(attempt.get("attempt")) is not int or attempt["attempt"] != index:
            raise ValueError("attempt_sequence_invalid")
        if type(attempt.get("exit_code")) is not int:
            raise ValueError("attempt_exit_code_invalid")
        if not isinstance(attempt.get("business_validation_started"), bool):
            raise ValueError("attempt_business_phase_missing")
        reason_codes = attempt.get("reason_codes")
        readiness_paths = attempt.get("readiness_paths")
        if not isinstance(reason_codes, list) or any(not isinstance(value, str) for value in reason_codes):
            raise ValueError("attempt_reason_codes_invalid")
        if not isinstance(readiness_paths, list) or any(not isinstance(value, str) for value in readiness_paths):
            raise ValueError("attempt_readiness_paths_invalid")
        evidence_path = attempt.get("evidence_path")
        if evidence_path is not None and (not isinstance(evidence_path, str) or evidence_path.startswith("/")):
            raise ValueError("attempt_evidence_path_invalid")
        classification = attempt.get("classification")
        if not isinstance(classification, dict) or not isinstance(classification.get("retryable"), bool):
            raise ValueError("attempt_classification_invalid")
        if not isinstance(classification.get("reason"), str):
            raise ValueError("attempt_classification_reason_invalid")
        infrastructure = attempt.get("infrastructure_evidence")
        if attempt["exit_code"] != 0:
            if attempt["business_validation_started"]:
                previous_failures.append(attempt)
            elif not (
                classification["retryable"] is True
                and classification["reason"] == "pre_business_infrastructure_failure"
                and isinstance(infrastructure, dict)
                and infrastructure.get("verified") is True
                and isinstance(infrastructure.get("stage"), str)
                and infrastructure["stage"] in {"nat_simulator", "control_server", "runner_process"}
            ):
                previous_failures.append(attempt)
        elif not attempt["business_validation_started"]:
            raise ValueError("successful_attempt_business_phase_missing")

    if final.get("result") != "pass":
        raise ValueError("attempt_final_result_not_pass")
    if type(final.get("attempt")) is not int or final["attempt"] != len(attempts):
        raise ValueError("attempt_final_index_mismatch")
    if final.get("reason_code") is not None:
        raise ValueError("attempt_final_reason_conflict")
    last = attempts[-1]
    if last["exit_code"] != 0 or last.get("evidence_path") != "nat-evidence.json":
        raise ValueError("attempt_final_evidence_not_successful")
    if previous_failures:
        if any(attempt["business_validation_started"] for attempt in previous_failures):
            raise ValueError("business_failure_masked_by_later_attempt")
        raise ValueError("unverified_prebusiness_retry")
    if record.get("result") != "pass":
        raise ValueError("attempt_history_record_result_mismatch")
    return {
        "first_attempt_pass": attempts[0]["exit_code"] == 0,
        "attempt_count": len(attempts),
        "diagnostic_retry_count": len(attempts) - 1,
        "recovered": any(attempt["exit_code"] != 0 for attempt in attempts[:-1]),
    }


def aggregate_records(
    records: list[tuple[Path, dict[str, Any]]],
    source_head_sha: str,
    workflow_sha: str,
) -> dict[str, Any]:
    expected = {
        f"{topology}:replica-{replica}:round-1"
        for topology, replicas in EXPECTED_TOPOLOGIES.items()
        for replica in replicas
    }
    seen: dict[str, tuple[Path, str]] = {}
    validated: list[dict[str, Any]] = []
    attempt_stats: list[dict[str, Any]] = []
    for path, record in records:
        scenario, exact_test_id, _ = validate_record(record, source_head_sha, workflow_sha)
        manifest_path = path.with_name("nat-attempts.json")
        try:
            history = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"attempt_history_missing_or_invalid:{manifest_path}:{exc}") from exc
        attempt_stats.append(validate_attempt_history(history, record))
        if scenario in seen:
            previous_path, previous_test_id = seen[scenario]
            raise ValueError(
                f"duplicate_conflicting_record:{scenario}:{previous_path}:{path}:{previous_test_id}:{exact_test_id}"
            )
        seen[scenario] = (path, exact_test_id)
        validated.append(record)

    missing = sorted(expected - set(seen))
    if missing:
        raise ValueError("missing_scenario:" + ",".join(missing))
    extra = sorted(set(seen) - expected)
    if extra:
        raise ValueError("unknown_scenario:" + ",".join(extra))
    validated.sort(key=lambda record: (record["topology"], record["replica"], record["round"]))
    aggregate: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "repository": REPOSITORY,
        "source_head_sha": source_head_sha,
        "workflow_sha": workflow_sha,
        "result": "pass",
        "executed_record_count": len(validated),
        "relay_replica_count": sum(record["topology"] == "relay-blackhole" for record in validated),
        "attempt_stats": {
            "scenario_count": len(attempt_stats),
            "first_attempt_pass_count": sum(stat["first_attempt_pass"] for stat in attempt_stats),
            "first_attempt_pass_rate": (
                sum(stat["first_attempt_pass"] for stat in attempt_stats) / len(attempt_stats)
                if attempt_stats
                else 0.0
            ),
            "diagnostic_retry_count": sum(stat["diagnostic_retry_count"] for stat in attempt_stats),
            "recovery_count": sum(stat["recovered"] for stat in attempt_stats),
            "final_failure_count": 0,
        },
        "records": [
            {
                "scenario_id": record["scenario_id"],
                "exact_test_id": record["exact_test_id"],
                "topology": record["topology"],
                "replica": record["replica"],
                "round": record["round"],
                "result": record["result"],
            }
            for record in validated
        ],
    }
    canonical = json.dumps(aggregate, sort_keys=True, separators=(",", ":")).encode("utf-8")
    aggregate["aggregate_digest"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
    return aggregate


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", required=True)
    parser.add_argument("--source-head-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    result = aggregate_records(_read_records(Path(args.input_root)), args.source_head_sha, args.workflow_sha)
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
