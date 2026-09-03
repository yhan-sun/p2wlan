#!/usr/bin/env python3
"""Fail-closed aggregate for the Windows lifecycle acceptance artifact.

The Windows runner is the source of truth for every Windows-specific result.
This module only validates the artifact emitted by that runner; it never turns
an omitted, force-killed, stale-SHA, or deferred operation into a verified pass.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 2
REPOSITORY = "yhan-sun/p2wlan"
SHA_RE = re.compile(r"[0-9a-fA-F]{40}")
VERIFIED = "verified"
DEFERRED = "deferred"
FAILED = "failed"
VALID_STATUSES = {VERIFIED, DEFERRED, FAILED}
EXPECTED_COMPONENTS = ("production_harness", "flutter_ui", "handler_mapping")
REQUIRED_CAPABILITIES = (
    "production_start_stop",
    "cli_stop",
    "ui_stop",
    "ctrl_c",
    "service_stop",
    "service_preshutdown",
    "logoff_hook",
    "shutdown_hook",
    "diagnostics_port_release",
    "child_process_cleanup",
    "wintun_ownership",
    "flutter_release_tray_no_adapter_exit",
    "wer_scan",
)
EXPECTED_CONSOLE_MAPPING = [
    {"event": "CTRL_C_EVENT", "reason": "CTRL_C"},
    {"event": "CTRL_BREAK_EVENT", "reason": "CTRL_BREAK"},
    {"event": "CTRL_CLOSE_EVENT", "reason": "CTRL_CLOSE"},
    {"event": "CTRL_LOGOFF_EVENT", "reason": "CTRL_LOGOFF"},
    {"event": "CTRL_SHUTDOWN_EVENT", "reason": "CTRL_SHUTDOWN"},
]
EXPECTED_SERVICE_MAPPING = [
    {"event": "SERVICE_CONTROL_STOP", "reason": "SERVICE_STOP"},
    {"event": "SERVICE_CONTROL_PRESHUTDOWN", "reason": "SERVICE_PRESHUTDOWN"},
    {"event": "SERVICE_CONTROL_SHUTDOWN", "reason": "SERVICE_SHUTDOWN"},
    {"event": "SERVICE_CONTROL_SESSIONCHANGE_LOGOFF", "reason": "SERVICE_LOGOFF"},
]


class EvidenceError(ValueError):
    """The artifact is malformed or does not prove the required contract."""


def _status(value: Any, path: str) -> str:
    if not isinstance(value, str) or value not in VALID_STATUSES:
        raise EvidenceError(
            f"{path} must be one of {sorted(VALID_STATUSES)!r}, got {value!r}"
        )
    return value


def _require_bool(item: dict[str, Any], key: str, path: str) -> bool:
    value = item.get(key)
    if not isinstance(value, bool):
        raise EvidenceError(f"{path}.{key} must be a boolean")
    return value


def _require_int(item: dict[str, Any], key: str, path: str) -> int:
    value = item.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise EvidenceError(f"{path}.{key} must be an integer")
    return value


def _require_sha(item: dict[str, Any], key: str, path: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        raise EvidenceError(f"{path}.{key} must be a 40-character git SHA")
    return value


def _validate_identity(
    item: dict[str, Any],
    path: str,
    expected_source_head_sha: str | None = None,
    expected_workflow_sha: str | None = None,
) -> tuple[str, str]:
    if item.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceError(f"{path}.schema_version must be {SCHEMA_VERSION}")
    if item.get("repository") != REPOSITORY:
        raise EvidenceError(
            f"{path}.repository must be {REPOSITORY!r}, got {item.get('repository')!r}"
        )
    if item.get("runner_os") != "windows-latest":
        raise EvidenceError(f"{path}.runner_os must be windows-latest")
    source_head_sha = _require_sha(item, "source_head_sha", path)
    workflow_sha = _require_sha(item, "workflow_sha", path)
    if (
        expected_source_head_sha is not None
        and source_head_sha != expected_source_head_sha
    ):
        raise EvidenceError(
            f"{path}.source_head_sha={source_head_sha} does not match "
            f"P2WLAN_EXACT_HEAD={expected_source_head_sha}"
        )
    if expected_workflow_sha is not None and workflow_sha != expected_workflow_sha:
        raise EvidenceError(
            f"{path}.workflow_sha={workflow_sha} does not match "
            f"P2WLAN_WORKFLOW_SHA={expected_workflow_sha}"
        )
    return source_head_sha, workflow_sha


def _capability_map(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = document.get("capabilities")
    if not isinstance(raw, list):
        raise EvidenceError("capabilities must be a list")
    result: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(raw):
        path = f"capabilities[{index}]"
        if not isinstance(value, dict):
            raise EvidenceError(f"{path} must be an object")
        name = value.get("name")
        if not isinstance(name, str) or not name:
            raise EvidenceError(f"{path}.name must be a non-empty string")
        if name in result:
            raise EvidenceError(f"duplicate capability {name!r}")
        _status(value.get("status"), f"{path}.status")
        result[name] = value
    return result


def _component_map(
    document: dict[str, Any],
    expected_source_head_sha: str | None,
    expected_workflow_sha: str | None,
    document_source_head_sha: str,
    document_workflow_sha: str,
) -> dict[str, dict[str, Any]]:
    raw = document.get("components")
    if not isinstance(raw, list):
        raise EvidenceError("components must be a list")
    result: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(raw):
        path = f"components[{index}]"
        if not isinstance(value, dict):
            raise EvidenceError(f"{path} must be an object")
        name = value.get("name")
        if not isinstance(name, str) or name not in EXPECTED_COMPONENTS:
            raise EvidenceError(f"{path}.name is not a required component")
        if name in result:
            raise EvidenceError(f"duplicate component {name!r}")
        component_source_head_sha, component_workflow_sha = _validate_identity(
            value,
            path,
            expected_source_head_sha=expected_source_head_sha,
            expected_workflow_sha=expected_workflow_sha,
        )
        if component_source_head_sha != document_source_head_sha:
            raise EvidenceError(
                f"{path}.source_head_sha must match evidence.source_head_sha"
            )
        if component_workflow_sha != document_workflow_sha:
            raise EvidenceError(
                f"{path}.workflow_sha must match evidence.workflow_sha"
            )
        _status(value.get("status"), f"{path}.status")
        result[name] = value
    missing = [name for name in EXPECTED_COMPONENTS if name not in result]
    if missing:
        raise EvidenceError(f"missing component(s): {missing!r}")
    return result


def _validate_cycles(document: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    raw = document.get("cycles")
    if not isinstance(raw, list):
        raise EvidenceError("cycles must be a list")

    errors: list[str] = []
    cycles: list[dict[str, Any]] = []
    for index, value in enumerate(raw):
        path = f"cycles[{index}]"
        if not isinstance(value, dict):
            raise EvidenceError(f"{path} must be an object")
        if not isinstance(value.get("cycle"), int) or isinstance(value.get("cycle"), bool):
            raise EvidenceError(f"{path}.cycle is required and must be an integer")
        for key in ("entrypoint", "mode"):
            if not isinstance(value.get(key), str) or not value.get(key):
                raise EvidenceError(f"{path}.{key} is required")
        for key in (
            "start_succeeded",
            "graceful_stop",
            "forced_termination",
            "process_exited",
            "children_gone",
            "diagnostics_port_released",
            "auth_token_removed",
            "wintun_stale",
            "wintun_observed",
            "real_wintun",
            "daemon_processes_clean",
        ):
            _require_bool(value, key, path)
        exit_code = value.get("process_exit_code")
        if exit_code is not None and (
            not isinstance(exit_code, int) or isinstance(exit_code, bool)
        ):
            raise EvidenceError(f"{path}.process_exit_code must be an integer or null")
        cycles.append(value)

        if not value["start_succeeded"]:
            errors.append(f"{path}: production start did not succeed")
        if not value["graceful_stop"]:
            errors.append(f"{path}: stop was not proven graceful")
        if value["forced_termination"]:
            errors.append(f"{path}: forceful termination was used")
        if not value["process_exited"]:
            errors.append(f"{path}: daemon process remained alive")
        if value.get("process_exit_code") not in (None, 0):
            errors.append(f"{path}: daemon exit code was {value['process_exit_code']}")
        if not value["children_gone"]:
            errors.append(f"{path}: child process cleanup failed")
        if not value["diagnostics_port_released"]:
            errors.append(f"{path}: diagnostics port was not released")
        if not value["auth_token_removed"]:
            errors.append(f"{path}: diagnostics auth file remained")
        if value["real_wintun"] and value["wintun_stale"]:
            errors.append(f"{path}: stale Wintun ownership remained")
        if value["real_wintun"] and not value["wintun_observed"]:
            errors.append(
                f"{path}: real Wintun adapter was not observed while daemon was running"
            )
    return cycles, errors


def _validate_wer(
    document: dict[str, Any], capabilities: dict[str, dict[str, Any]]
) -> list[str]:
    errors: list[str] = []
    wer = document.get("wer")
    if not isinstance(wer, dict):
        return ["wer must be an object"]
    events = wer.get("events")
    if not isinstance(events, list):
        errors.append("wer.events must be a list")
    elif events:
        errors.append(f"wer scan found {len(events)} crash/BEX event(s)")
    if wer.get("event_ids_checked") != [1000, 1001]:
        errors.append("wer.event_ids_checked must be exactly [1000, 1001]")
    capability = capabilities.get("wer_scan")
    if capability is None:
        errors.append("missing capability wer_scan")
    elif capability.get("status") != VERIFIED:
        errors.append(f"wer_scan is {capability.get('status')!r}, not verified")
    return errors


def _validate_service_controls(
    document: dict[str, Any], capabilities: dict[str, dict[str, Any]]
) -> list[str]:
    errors: list[str] = []
    raw = document.get("service_controls")
    if not isinstance(raw, list):
        return ["service_controls must be a list"]
    by_control: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(raw):
        path = f"service_controls[{index}]"
        if not isinstance(value, dict):
            errors.append(f"{path} must be an object")
            continue
        control = value.get("control")
        if not isinstance(control, str) or control not in {"stop", "preshutdown"}:
            errors.append(f"{path}.control must be stop or preshutdown")
            continue
        if control in by_control:
            errors.append(f"duplicate service control {control!r}")
            continue
        by_control[control] = value
        _status(value.get("status"), f"{path}.status")
        for key in ("process_gone", "wintun_observed", "wintun_stale"):
            _require_bool(value, key, path)

    for control, capability_name in (
        ("stop", "service_stop"),
        ("preshutdown", "service_preshutdown"),
    ):
        capability = capabilities.get(capability_name)
        record = by_control.get(control)
        if capability is not None and capability.get("status") == VERIFIED:
            if record is None:
                errors.append(f"missing service control record {control}")
                continue
            if record.get("status") != VERIFIED:
                errors.append(f"service control {control} is not verified")
            if not record["process_gone"]:
                errors.append(f"service control {control} left a process running")
            if not record["wintun_observed"]:
                errors.append(f"service control {control} did not observe a Wintun adapter")
            if record["wintun_stale"]:
                errors.append(f"service control {control} left stale Wintun ownership")
    return errors


def _validate_flutter_tray(
    document: dict[str, Any], capabilities: dict[str, dict[str, Any]]
) -> list[str]:
    capability = capabilities.get("flutter_release_tray_no_adapter_exit")
    raw = document.get("flutter_tray")
    if not isinstance(raw, dict):
        return (
            ["flutter_tray must be an object"]
            if capability is not None and capability.get("status") == VERIFIED
            else []
        )
    errors: list[str] = []
    for key in ("process_exited", "daemon_processes_clean", "forced_termination"):
        try:
            _require_bool(raw, key, "flutter_tray")
        except EvidenceError as error:
            errors.append(str(error))
    exit_code = raw.get("exit_code")
    if exit_code is not None and (
        not isinstance(exit_code, int) or isinstance(exit_code, bool)
    ):
        errors.append("flutter_tray.exit_code must be an integer or null")
    dump_paths = raw.get("dump_paths")
    if not isinstance(dump_paths, list) or any(
        not isinstance(path, str) for path in dump_paths
    ):
        errors.append("flutter_tray.dump_paths must be a list of strings")
    tray_cycles = raw.get("cycles")
    if not isinstance(tray_cycles, list):
        errors.append("flutter_tray.cycles must be a list")
        tray_cycles = []
    try:
        attempted_cycles = _require_int(raw, "attempted_cycles", "flutter_tray")
        successful_cycles = _require_int(raw, "successful_cycles", "flutter_tray")
    except EvidenceError as error:
        errors.append(str(error))
        attempted_cycles = -1
        successful_cycles = -1

    if capability is not None and capability.get("status") == VERIFIED:
        if attempted_cycles != 20:
            errors.append(f"flutter_tray.attempted_cycles must be 20, got {attempted_cycles}")
        if successful_cycles != 20:
            errors.append(f"flutter_tray.successful_cycles must be 20, got {successful_cycles}")
        if len(tray_cycles) != 20:
            errors.append(f"flutter_tray.cycles must contain 20 records, got {len(tray_cycles)}")
        if raw.get("first_failure_cycle") is not None:
            errors.append("verified flutter_tray must not contain first_failure_cycle")
        if raw.get("exit_code") != 0:
            errors.append(f"flutter_tray.exit_code must be 0, got {raw.get('exit_code')!r}")
        if raw.get("forced_termination"):
            errors.append("flutter release tray exit used forceful termination")
        if not raw.get("process_exited"):
            errors.append("flutter release tray process did not exit")
        if not raw.get("daemon_processes_clean"):
            errors.append("flutter release tray test left a daemon process running")

    for index, cycle in enumerate(tray_cycles):
        path = f"flutter_tray.cycles[{index}]"
        if not isinstance(cycle, dict):
            errors.append(f"{path} must be an object")
            continue
        if cycle.get("status") != VERIFIED:
            if capability is not None and capability.get("status") == VERIFIED:
                errors.append(f"{path}.status must be verified")
        for key in ("process_exited", "daemon_processes_clean", "forced_termination"):
            try:
                _require_bool(cycle, key, path)
            except EvidenceError as error:
                errors.append(str(error))
        if capability is not None and capability.get("status") == VERIFIED:
            if cycle.get("exit_code") != 0:
                errors.append(f"{path}.exit_code must be 0")
            if not cycle.get("process_exited"):
                errors.append(f"{path} did not exit")
            if not cycle.get("daemon_processes_clean"):
                errors.append(f"{path} left a daemon process running")
            if cycle.get("forced_termination"):
                errors.append(f"{path} used forceful termination")
    return errors


def _validate_handler_mapping(document: dict[str, Any]) -> list[str]:
    raw = document.get("handler_mapping")
    if not isinstance(raw, dict):
        return ["handler_mapping must be an object"]
    errors: list[str] = []
    if raw.get("status") != VERIFIED:
        errors.append(f"handler_mapping.status must be verified, got {raw.get('status')!r}")
    if raw.get("live_system_delivery") != DEFERRED:
        errors.append("handler_mapping.live_system_delivery must be deferred")
    detail = raw.get("live_system_delivery_detail")
    if not isinstance(detail, str) or not detail.strip():
        errors.append("handler_mapping.live_system_delivery_detail is required")
    for key, expected in (
        ("console", EXPECTED_CONSOLE_MAPPING),
        ("service", EXPECTED_SERVICE_MAPPING),
    ):
        value = raw.get(key)
        if value != expected:
            errors.append(
                f"handler_mapping.{key} does not match the production adapter mapping"
            )
    for key in (
        "idempotent_first_request_wins",
        "no_duplicate_frees",
        "coordinator_entered",
        "callback_non_blocking",
        "bounded_deadline",
        "force_kill",
    ):
        try:
            _require_bool(raw, key, "handler_mapping")
        except EvidenceError as error:
            errors.append(str(error))
    if raw.get("idempotent_first_request_wins") is not True:
        errors.append("handler mapping did not prove first-request idempotence")
    if raw.get("no_duplicate_frees") is not True:
        errors.append("handler mapping did not prove duplicate-free cleanup dispatch")
    if raw.get("coordinator_entered") is not True:
        errors.append("handler mapping did not enter the shared shutdown coordinator")
    if raw.get("callback_non_blocking") is not True:
        errors.append("handler mapping did not prove a non-blocking callback")
    if raw.get("bounded_deadline") is not True:
        errors.append("handler mapping did not prove a bounded shutdown deadline")
    deadline_ms = raw.get("shutdown_deadline_ms")
    if not isinstance(deadline_ms, int) or isinstance(deadline_ms, bool) or deadline_ms <= 0:
        errors.append("handler_mapping.shutdown_deadline_ms must be a positive integer")
    callback_elapsed_ms = raw.get("callback_elapsed_ms")
    if (
        not isinstance(callback_elapsed_ms, int)
        or isinstance(callback_elapsed_ms, bool)
        or callback_elapsed_ms < 0
        or callback_elapsed_ms > 1_000
    ):
        errors.append("handler_mapping.callback_elapsed_ms must be an integer in [0, 1000]")
    if raw.get("force_kill") is not False:
        errors.append("handler mapping reported forceful termination")
    coordinator = raw.get("coordinator")
    if not isinstance(coordinator, str) or not coordinator.strip():
        errors.append("handler_mapping.coordinator is required")
    return errors


def validate(
    document: dict[str, Any],
    expected_source_head_sha: str | None = None,
    expected_workflow_sha: str | None = None,
) -> dict[str, Any]:
    """Validate an evidence document and return a compact aggregate report."""

    if not isinstance(document, dict):
        raise EvidenceError("top-level evidence must be an object")
    source_head_sha, workflow_sha = _validate_identity(
        document,
        "evidence",
        expected_source_head_sha=expected_source_head_sha,
        expected_workflow_sha=expected_workflow_sha,
    )
    components = _component_map(
        document,
        expected_source_head_sha=expected_source_head_sha,
        expected_workflow_sha=expected_workflow_sha,
        document_source_head_sha=source_head_sha,
        document_workflow_sha=workflow_sha,
    )
    capabilities = _capability_map(document)
    cycles, cycle_errors = _validate_cycles(document)
    errors = list(cycle_errors)
    errors.extend(_validate_handler_mapping(document))

    missing = [name for name in REQUIRED_CAPABILITIES if name not in capabilities]
    errors.extend(f"missing capability {name}" for name in missing)
    deferred = [
        name
        for name in REQUIRED_CAPABILITIES
        if name in capabilities and capabilities[name]["status"] == DEFERRED
    ]
    if document["handler_mapping"].get("live_system_delivery") == DEFERRED:
        deferred.append("live_system_delivery")
    failed = [
        name
        for name in REQUIRED_CAPABILITIES
        if name in capabilities and capabilities[name]["status"] == FAILED
    ]
    errors.extend(f"capability {name} is failed" for name in failed)

    deferred_components = [
        name
        for name in EXPECTED_COMPONENTS
        if components[name]["status"] == DEFERRED
    ]
    failed_components = [
        name for name in EXPECTED_COMPONENTS if components[name]["status"] == FAILED
    ]
    errors.extend(f"component {name} is failed" for name in failed_components)

    production = [cycle for cycle in cycles if cycle.get("mode") == "production"]
    if len(production) != 50:
        errors.append(f"found {len(production)} production cycles; exactly 50 are required")

    entrypoints = {cycle.get("entrypoint") for cycle in production}
    for entrypoint in ("diagnostics", "cli", "ctrl_c"):
        if entrypoint not in entrypoints:
            errors.append(f"no production cycle exercised {entrypoint}")

    ui_capability = capabilities.get("ui_stop")
    ui_cycles = [cycle for cycle in cycles if cycle.get("entrypoint") == "ui"]
    if ui_capability is not None and ui_capability.get("status") == VERIFIED:
        if len(ui_cycles) < 8:
            errors.append(f"only {len(ui_cycles)} UI cycles; at least 8 are required")
        for index, cycle in enumerate(ui_cycles):
            if cycle.get("forced_termination"):
                errors.append(f"ui cycle {index} used forceful termination")
            if not cycle.get("graceful_stop"):
                errors.append(f"ui cycle {index} was not proven graceful")

    wintun_capability = capabilities.get("wintun_ownership")
    if wintun_capability is not None and wintun_capability.get("status") == VERIFIED:
        non_real = [
            cycle.get("cycle") for cycle in production if not cycle.get("real_wintun")
        ]
        if non_real:
            errors.append(f"production cycles without real Wintun evidence: {non_real!r}")

    errors.extend(_validate_wer(document, capabilities))
    errors.extend(_validate_service_controls(document, capabilities))
    errors.extend(_validate_flutter_tray(document, capabilities))

    # A deferred capability/component is explicit evidence that the runner
    # could not execute one required operation. It is never a verified pass.
    # Any schema, identity, cycle, mapping, or failed-capability error remains
    # a hard failure even when another operation is deferred.
    overall = (
        FAILED
        if errors
        else DEFERRED
        if deferred or deferred_components
        else VERIFIED
    )
    report = {
        "schema_version": SCHEMA_VERSION,
        "repository": REPOSITORY,
        "source_head_sha": source_head_sha,
        "workflow_sha": workflow_sha,
        "overall": overall,
        "production_cycles": len(production),
        "production_entrypoints": sorted(entrypoints),
        "deferred_capabilities": deferred,
        "failed_capabilities": failed,
        "deferred_components": deferred_components,
        "failed_components": failed_components,
        "error_count": len(errors),
        "errors": errors,
    }
    return report


def _required_environment_sha(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not SHA_RE.fullmatch(value):
        raise EvidenceError(f"{name} must be a 40-character git SHA")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.input.read_text(encoding="utf-8-sig"))
        report = validate(
            document,
            expected_source_head_sha=_required_environment_sha("P2WLAN_EXACT_HEAD"),
            expected_workflow_sha=_required_environment_sha("P2WLAN_WORKFLOW_SHA"),
        )
    except (OSError, json.JSONDecodeError, EvidenceError) as error:
        print(f"Windows lifecycle evidence rejected: {error}", file=sys.stderr)
        return 1

    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if report["overall"] == FAILED:
        return 2
    if report["overall"] == DEFERRED:
        print(
            "Windows lifecycle evidence accepted with explicit deferred operations; "
            "see the aggregate JSON for the non-verified scope.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
