#!/usr/bin/env python3
"""Validate the bounded path-observability contract and emit CI evidence."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "client/daemon/src/peer/path_observability.rs"
DOC = ROOT / "docs/path-observability.md"
WORKFLOW = ROOT / ".github/workflows/path-observability-required.yml"
FIXTURE = ROOT / "contracts/fixtures/status.json"
EXPECTED_METRICS = [
    "accepted_transitions",
    "accepted_observations",
    "duplicate_events",
    "rejected_transitions",
    "path_changes",
    "direct_attempts",
    "direct_retries",
    "direct_validations",
    "direct_successes",
    "direct_failures",
    "validation_failures",
    "relay_confirmations",
    "relay_fallbacks",
    "relay_failures",
    "candidate_refreshes",
    "control_reconnects",
    "network_generation_changes",
    "lifecycle_resets",
    "dplpmtud_changes",
    "active_tasks",
    "active_sockets",
    "dropped_transition_events",
    "direct_time_to_connect_ms",
]
FORBIDDEN_LABELS = ["peer_id", "endpoint", "ip", "session_id", "error_text"]
EXPECTED_BOUNDS = [50, 100, 250, 500, 1000, 3000, 10000, 30000]


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8")
    documentation = DOC.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    metrics = fixture["stats"]["path_observability"]

    errors: list[str] = []
    if "PATH_TRANSITION_EVENT_LIMIT: usize = 32" not in source:
        errors.append("transition ring is not fixed at 32")
    if "Path Observability Required" not in workflow:
        errors.append("stable aggregate check name is missing")
    if "schema_version" not in source or "PATH_OBSERVABILITY_SCHEMA_VERSION" not in source:
        errors.append("versioned path observability schema is missing")
    if "commit_path_transition" not in documentation:
        errors.append("single transition owner is not documented")
    if "control_reconnect_counter_survives_timeline_eviction" not in documentation:
        errors.append("timeline-eviction reconnect regression is not documented")

    for metric in EXPECTED_METRICS:
        if metric not in source:
            errors.append(f"metric missing from source: {metric}")
        if metric not in documentation:
            errors.append(f"metric missing from documentation: {metric}")
        if metric not in metrics:
            errors.append(f"metric missing from status fixture: {metric}")

    histogram = metrics.get("direct_time_to_connect_ms", {})
    if histogram.get("bounds_ms") != EXPECTED_BOUNDS:
        errors.append("fixture histogram bounds changed")
    if len(histogram.get("buckets", [])) != len(EXPECTED_BOUNDS) + 1:
        errors.append("histogram bucket count is not bounds+1")

    # The metric struct must stay a fixed field set. Maps may exist elsewhere
    # in the module, but not inside PathObservabilityMetrics.
    match = re.search(
        r"pub struct PathObservabilityMetrics \{(?P<body>.*?)\n\}",
        source,
        re.DOTALL,
    )
    if match is None:
        errors.append("PathObservabilityMetrics struct not found")
    else:
        body = match.group("body")
        if "HashMap" in body or "BTreeMap" in body:
            errors.append("dynamic metric-label map found")
        for label in FORBIDDEN_LABELS:
            if re.search(rf"pub\s+{re.escape(label)}\s*:", body):
                errors.append(f"forbidden metric label field found: {label}")

    evidence = {
        "schema_version": 1,
        "result": "pass" if not errors else "fail",
        "transition_event_limit": 32,
        "histogram_bounds_ms": EXPECTED_BOUNDS,
        "metric_count": len(EXPECTED_METRICS),
        "forbidden_labels": FORBIDDEN_LABELS,
        "errors": errors,
    }
    destination = Path(
        os.environ.get(
            "P2WLAN_PATH_OBSERVABILITY_EVIDENCE",
            ROOT / "path-observability-evidence.json",
        )
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
