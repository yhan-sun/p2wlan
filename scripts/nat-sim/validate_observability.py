#!/usr/bin/env python3
"""Strict schema validation for nat-sim status and relay metrics evidence."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        raise ValueError(f"{label}_empty_or_non_object")
    return value


def validate_status(value: Any) -> dict[str, Any]:
    value = _object(value, "status")
    stats = _object(value.get("stats"), "status_stats")
    timeline = _object(value.get("connection_timeline"), "status_timeline")
    drops = stats.get("outbound_drops")
    if not isinstance(drops, dict):
        raise ValueError("status_schema_missing_outbound_drops")
    for reason, counters in drops.items():
        if not isinstance(reason, str) or not isinstance(counters, dict):
            raise ValueError("status_schema_invalid_drop_counter")
        for field in ("packets", "bytes"):
            if not isinstance(counters.get(field), int) or counters[field] < 0:
                raise ValueError(f"status_schema_invalid_drop_{field}")
    if not isinstance(stats.get("outbound_loss_events"), list):
        raise ValueError("status_schema_missing_outbound_loss_events")
    if not isinstance(timeline.get("correlation_id"), str) or not timeline["correlation_id"]:
        raise ValueError("status_schema_missing_correlation_id")
    if not isinstance(timeline.get("events"), list):
        raise ValueError("status_schema_missing_timeline_events")
    if "first_usable_summaries" in timeline and not isinstance(
        timeline.get("first_usable_summaries"), list
    ):
        raise ValueError("status_schema_invalid_first_usable_summaries")
    return value


def validate_metrics(value: Any) -> dict[str, Any]:
    value = _object(value, "metrics")
    for field in (
        "active_connections",
        "registered_peers",
        "forwarded_frames_total",
        "forward_errors_total",
    ):
        if not isinstance(value.get(field), (int, float)) or isinstance(value.get(field), bool):
            raise ValueError(f"metrics_schema_missing_{field}")
    if "auth_failure_sources" in value or "source_key" in value:
        raise ValueError("metrics_schema_contains_source_identifiers")
    return value


def load_and_validate(path: Path, kind: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{kind}_invalid_json: {exc}") from exc
    return validate_status(value) if kind == "status" else validate_metrics(value)


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[2] not in {"status", "metrics"}:
        raise SystemExit("usage: validate_observability.py FILE status|metrics")
    try:
        load_and_validate(Path(sys.argv[1]), sys.argv[2])
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
