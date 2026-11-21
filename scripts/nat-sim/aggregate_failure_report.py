"""Bounded failure-only projection; never a second NAT/pass adjudicator."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re

MAX_FILES = 64
MAX_BYTES = 128 * 1024
SHA1 = re.compile(r"[0-9a-f]{40}")
REASON = re.compile(r"[A-Za-z0-9_:-]{1,96}")
ARTIFACT = re.compile(r"nat-topology-(direct|relay)-(\d+)-(\d+)(?:-([1-5])-of-5)?")
RUNNER = re.compile(r"p2wlan-nat-topology-(\d+)-(\d+)-(direct|relay)-([1-5])-attempt-1")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def reason(value):
    return value if isinstance(value, str) and REASON.fullmatch(value) else "unknown"


def issue_code(error):
    return reason(str(error).split(":", 1)[0])


def read_file(path: Path, root: Path) -> tuple[dict | None, dict]:
    info = {"name": path.name, "input_locator_sha256": digest(path.relative_to(root).as_posix().encode()),
            "sha256": None, "error": None}
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError("input_not_regular")
        with path.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("input_size_exceeded")
        info["sha256"] = digest(data)
        value = json.loads(data)
        if not isinstance(value, dict):
            raise ValueError("input_not_object")
        return value, info
    except json.JSONDecodeError:
        info["error"] = "input_json_invalid"
        return None, info
    except (OSError, ValueError) as error:
        info["error"] = issue_code(error) if isinstance(error, ValueError) else "input_read_failed"
        return None, info


def attempt_binding(path: Path, root: Path, scenario: str, run_id, run_attempt) -> dict | None:
    if run_id is None or run_attempt is None:
        return None
    expected_topology, replica, _round = scenario.split(":")
    replica = int(replica.removeprefix("replica-"))
    identities = []
    for part in path.relative_to(root).parts[:-1]:
        artifact, runner = ARTIFACT.fullmatch(part), RUNNER.fullmatch(part)
        if artifact:
            kind, observed_run, attempt, observed_replica = artifact.groups()
            identities.append((kind, int(observed_run), int(attempt), int(observed_replica or 1)))
        elif runner:
            observed_run, attempt, kind, observed_replica = runner.groups()
            identities.append((kind, int(observed_run), int(attempt), int(observed_replica)))
    if not identities or any(row != identities[0] for row in identities):
        return None
    kind, observed_run, attempt, observed_replica = identities[0]
    expected_kind = "direct" if expected_topology == "direct-cold-start" else "relay"
    if kind != expected_kind or observed_replica != replica or observed_run != run_id or not 1 <= attempt <= run_attempt:
        return None
    return {"github_run_id": observed_run, "selected_github_run_attempt": attempt,
            "current_github_run_attempt": run_attempt, "scenario_attempt": 1}


def failure_projection(value):
    decision = value.get("decision")
    return (type(value.get("schema_version")) is int and value["schema_version"] == 1
            and value.get("result") == "fail" and type(value.get("executed")) is bool
            and "nat_terminal" in value and value["nat_terminal"] is None
            and isinstance(decision, dict) and decision.get("result") == "fail"
            and reason(decision.get("reason_code")) != "unknown"
            and decision["reason_code"].startswith("harness:"))


def public_observations(path: Path, value: dict, root: Path) -> dict:
    original = value.get("collector_observations") or {}
    original = original if isinstance(original, dict) else {}
    reference = original.get("reference")
    hidden = path.with_name(".collector-nat-evidence.json")
    public = path.with_name("collector-nat-evidence.json")
    declaration = value.get("collector_public_observations") or {}
    declaration = declaration if isinstance(declaration, dict) else {}
    observed = {"original_reference": reference if reference == hidden.name else None,
                "original_reference_present": hidden.is_file() and not hidden.is_symlink(),
                "public_alias_present": public.is_file() and not public.is_symlink(),
                "public_alias_sha256": None, "public_alias_digest_matches_declaration": None,
                "used_as_terminal": False}
    if observed["public_alias_present"]:
        _record, info = read_file(public, root)
        observed["public_alias_sha256"] = info["sha256"]
        observed["public_alias_digest_matches_declaration"] = (
            info["error"] is None and declaration.get("reference") == public.name
            and declaration.get("sha256") == info["sha256"])
    return observed


def project_attempts(history):
    # Publish only original stable typed fields, never extra/private argv or paths.
    return [{"attempt": row["attempt"], "exit_code": row["exit_code"],
             "business_validation_started": row["business_validation_started"],
             "reason_codes": [reason(code) for code in row["reason_codes"][:64]],
             "classification": {"retryable": row["classification"]["retryable"],
                                "reason": reason(row["classification"]["reason"])}}
             for row in history["attempts"]]


def history_paths(root):
    paths = []
    try:
        for path in root.rglob("nat-attempts.json"):
            if len(paths) == MAX_FILES:
                return paths, True, "input_capacity_exceeded"
            paths.append(path)
    except OSError:
        return paths, True, "input_scan_failed"
    return paths, False, None


def build_report(root: Path, source: str, workflow: str, issue: str, *, validate_record,
                 validate_attempt_history, expected_topologies, run_id=None, run_attempt=None) -> dict:
    expected = sorted(f"{topology}:replica-{replica}:round-1"
                      for topology, replicas in expected_topologies.items() for replica in replicas)
    grouped, inputs, errors = {}, [], []
    paths, capacity_exceeded, scan_error = history_paths(root)
    if scan_error:
        errors.append(scan_error)
    for path in paths:
        value, info = read_file(path, root)
        inputs.append(info)
        if value is None or value.get("scenario_id") not in expected:
            errors.append(info["error"] or "unexpected_attempt_scenario")
            continue
        grouped.setdefault(value["scenario_id"], []).append((path, value, info))
    rows, stats = [], []
    for scenario in expected:
        topology, replica_text, _round = scenario.split(":")
        row = {"scenario_id": scenario, "topology": topology, "replica": int(replica_text[8:]), "round": 1,
               "exact_test_id": None, "result": "unknown", "reason_code": "scenario_metadata_missing",
               "record_execution_verified": None, "record_executed_claim": None, "nat_terminal": None,
               "attempt_binding": None, "attempts": None, "final_adjudication": None,
               "evidence_result": None, "evidence_reason_code": None, "input_files": []}
        rows.append(row)
        matches = grouped.get(scenario, [])
        if capacity_exceeded or len(matches) != 1:
            row["reason_code"] = "input_capacity_exceeded" if capacity_exceeded else (
                "duplicate_attempt_history" if matches else "scenario_metadata_missing")
            continue
        path, history, info = matches[0]
        row["input_files"].append(info)
        record_path = path.with_name("nat-evidence.json")
        record, record_info = read_file(record_path, root)
        row["input_files"].append(record_info)
        if record is not None:
            decision = record.get("decision")
            row.update(evidence_result=record.get("result") if record.get("result") in ("pass", "fail") else None,
                       record_executed_claim=record.get("executed") if type(record.get("executed")) is bool else None,
                       evidence_reason_code=reason(decision.get("reason_code")) if isinstance(decision, dict) else None)
        projection = record is not None and failure_projection(record)
        try:
            binding = attempt_binding(path, root, scenario, run_id, run_attempt)
            if binding is None:
                raise ValueError("current_run_attempt_binding_unknown")
            row["attempt_binding"] = binding
            if len(history.get("attempts", [])) > 16:
                raise ValueError("attempt_history_capacity_exceeded")
            if record is not None and not projection:
                record_scenario, test_id, _replica = validate_record(record, source, workflow, allow_failure=True)
                if record_scenario != scenario:
                    raise ValueError("attempt_record_scenario_mismatch")
                row["exact_test_id"] = test_id
            current = validate_attempt_history(history, None if projection else record, source, workflow)
            if len(history["attempts"]) != 1 or history["final_adjudication"]["attempt"] != 1:
                raise ValueError("authoritative_scenario_attempt_budget_exceeded")
            if projection and current["final_result"] != "fail":
                raise ValueError("failure_projection_attempt_not_failed")
            if projection and record["decision"]["reason_code"].removeprefix("harness:") not in history["attempts"][0]["reason_codes"]:
                raise ValueError("failure_projection_original_reason_binding_unknown")
            row.update(result=current["final_result"], reason_code=current["final_reason_code"],
                       attempts=project_attempts(history), final_adjudication={
                           "attempt": history["final_adjudication"]["attempt"], "result": current["final_result"],
                           "reason_code": reason(current["final_reason_code"]) if current["final_reason_code"] else None})
            stats.append(current)
            if record is not None:
                row.update(evidence_result=record["result"], record_executed_claim=record.get("executed"),
                           evidence_reason_code=reason((record.get("decision") or {}).get("reason_code")))
                if projection:
                    row.update(record_kind="legacy_harness_failure_projection",
                               collector_observations=public_observations(record_path, record, root))
                else:
                    row.update(record_kind="validated_schema2", record_execution_verified=True)
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            row["reason_code"] = issue_code(error)
    counts = Counter(row["result"] for row in rows)
    return {"schema_version": 2, "repository": "yhan-sun/p2wlan", "result": "fail",
            "report_kind": "aggregate_validation_failure", "aggregate_validation_error": reason(issue),
            "source_head_sha": source if SHA1.fullmatch(source or "") else None,
            "workflow_sha": workflow if SHA1.fullmatch(workflow or "") else None,
            "github_run_id": run_id, "github_run_attempt": run_attempt,
            "scenario_count": len(expected), "scenario_denominator": "all_6_required_scenarios_including_missing_or_unknown",
            "executed_record_count": sum(row["record_execution_verified"] is True for row in rows),
            "executed_scenario_count": sum(row["record_execution_verified"] is True for row in rows),
            "bound_attempt_history_count": len(stats), "expected_relay_replica_count": 5,
            "relay_replica_count": sum(row["topology"] == "relay-blackhole" and row["record_execution_verified"] is True for row in rows),
            "configured_diagnostic_retry_budget": 0,
            "scenario_result_counts": {key: counts[key] for key in ("pass", "fail", "unknown")},
            "input_errors": errors[:MAX_FILES], "input_capacity_exceeded": capacity_exceeded,
            "attempt_input_observations": inputs[:MAX_FILES],
            "attempt_stats": {"scenario_count": len(expected), "first_attempt_pass_count": sum(s["first_attempt_pass"] for s in stats),
                              "first_attempt_pass_rate": sum(s["first_attempt_pass"] for s in stats)/len(expected),
                              "diagnostic_retry_count": None if counts["unknown"] else sum(s["diagnostic_retry_count"] for s in stats),
                              "observed_diagnostic_retry_count": sum(s["diagnostic_retry_count"] for s in stats),
                              "recovery_count": sum(s["recovered"] for s in stats),
                              "final_failure_count": counts["fail"], "unknown_scenario_count": counts["unknown"]},
            "records": rows}
