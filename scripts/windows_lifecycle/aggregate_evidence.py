#!/usr/bin/env python3
"""Fail-closed aggregate for the Windows lifecycle acceptance artifact.

The Windows runner is the source of truth for every Windows-specific result.
This module only validates the artifact emitted by that runner; it never turns
an omitted or force-killed operation into a pass.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
VERIFIED = "verified"
DEFERRED = "deferred"
FAILED = "failed"
VALID_STATUSES = {VERIFIED, DEFERRED, FAILED}

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
        for key in ("cycle", "entrypoint", "mode"):
            if not isinstance(value.get(key), (int, str)) or value.get(key) == "":
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
            errors.append(f"{path}: real Wintun adapter was not observed while daemon was running")
    return cycles, errors


def _validate_wer(document: dict[str, Any], capabilities: dict[str, dict[str, Any]]) -> list[str]:
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
    if capability is None or capability.get("status") != VERIFIED:
        return []
    raw = document.get("flutter_tray")
    if not isinstance(raw, dict):
        return ["flutter_tray must be an object when release tray exit is verified"]
    errors: list[str] = []
    for key in ("process_exited", "daemon_processes_clean", "forced_termination"):
        try:
            _require_bool(raw, key, "flutter_tray")
        except EvidenceError as error:
            errors.append(str(error))
    if raw.get("exit_code") != 0:
        errors.append(f"flutter_tray.exit_code must be 0, got {raw.get('exit_code')!r}")
    if raw.get("forced_termination"):
        errors.append("flutter release tray exit used forceful termination")
    if not raw.get("process_exited"):
        errors.append("flutter release tray process did not exit")
    if not raw.get("daemon_processes_clean"):
        errors.append("flutter release tray test left a daemon process running")
    return errors


def validate(document: dict[str, Any]) -> dict[str, Any]:
    """Validate an evidence document and return a compact aggregate report."""

    if not isinstance(document, dict):
        raise EvidenceError("top-level evidence must be an object")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceError(f"schema_version must be {SCHEMA_VERSION}")
    head_sha = document.get("head_sha")
    if not isinstance(head_sha, str) or not head_sha:
        raise EvidenceError("head_sha is required")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", head_sha):
        raise EvidenceError("head_sha must be a 40-character git SHA")
    if document.get("runner_os") != "windows-latest":
        raise EvidenceError("runner_os must be windows-latest")
    capabilities = _capability_map(document)
    cycles, cycle_errors = _validate_cycles(document)
    errors = list(cycle_errors)

    missing = [name for name in REQUIRED_CAPABILITIES if name not in capabilities]
    errors.extend(f"missing capability {name}" for name in missing)
    deferred = [
        name
        for name in REQUIRED_CAPABILITIES
        if name in capabilities and capabilities[name]["status"] == DEFERRED
    ]
    failed = [
        name
        for name in REQUIRED_CAPABILITIES
        if name in capabilities and capabilities[name]["status"] == FAILED
    ]
    errors.extend(f"capability {name} is failed" for name in failed)

    production = [cycle for cycle in cycles if cycle.get("mode") == "production"]
    if len(production) < 50:
        errors.append(f"only {len(production)} production cycles; at least 50 are required")

    entrypoints = {cycle.get("entrypoint") for cycle in production}
    for entrypoint in ("diagnostics", "cli", "ctrl_c"):
        if entrypoint not in entrypoints:
            errors.append(f"no production cycle exercised {entrypoint}")

    ui_capability = capabilities.get("ui_stop")
    ui_cycles = [cycle for cycle in cycles if cycle.get("entrypoint") == "ui"]
    if ui_capability is not None and ui_capability.get("status") == VERIFIED and not ui_cycles:
        errors.append("ui_stop is verified but no UI lifecycle cycle was recorded")
    if ui_capability is not None and ui_capability.get("status") == VERIFIED:
        for index, cycle in enumerate(ui_cycles):
            if cycle.get("forced_termination"):
                errors.append(f"ui cycle {index} used forceful termination")
            if not cycle.get("graceful_stop"):
                errors.append(f"ui cycle {index} was not proven graceful")

    wintun_capability = capabilities.get("wintun_ownership")
    if wintun_capability is not None and wintun_capability.get("status") == VERIFIED:
        non_real = [cycle.get("cycle") for cycle in production if not cycle.get("real_wintun")]
        if non_real:
            errors.append(f"production cycles without real Wintun evidence: {non_real!r}")

    errors.extend(_validate_wer(document, capabilities))
    errors.extend(_validate_service_controls(document, capabilities))
    errors.extend(_validate_flutter_tray(document, capabilities))

    # A deferred capability is explicit evidence that the runner could not
    # execute one required operation. It is never a verified pass. Any schema,
    # cycle, or failed-capability error remains a hard failure even when some
    # other capability is deferred; otherwise an incomplete artifact could be
    # incorrectly downgraded to a harmless deferral.
    overall = FAILED if errors else DEFERRED if deferred else VERIFIED
    report = {
        "schema_version": SCHEMA_VERSION,
        "head_sha": head_sha,
        "overall": overall,
        "production_cycles": len(production),
        "production_entrypoints": sorted(entrypoints),
        "deferred_capabilities": deferred,
        "failed_capabilities": failed,
        "error_count": len(errors),
        "errors": errors,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.input.read_text(encoding="utf-8-sig"))
        report = validate(document)
    except (OSError, json.JSONDecodeError, EvidenceError) as error:
        print(f"Windows lifecycle evidence rejected: {error}", file=sys.stderr)
        return 1

    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if report["overall"] != VERIFIED:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
