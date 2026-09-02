#!/usr/bin/env python3
"""Shared metadata contract for security-audit evidence reports."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from typing import Any, Iterable

SCHEMA_VERSION = 2
DEFAULT_REPOSITORY = "yhan-sun/p2wlan"


def repository_name(value: str | None = None) -> str:
    return value or os.environ.get("GITHUB_REPOSITORY") or DEFAULT_REPOSITORY


def failure_categories(findings: Iterable[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            str(item.get("code"))
            for item in findings
            if isinstance(item, dict) and item.get("code")
        }
    )


def make_report(
    *,
    component: str,
    head_sha: str | None,
    result: str,
    findings: list[dict[str, Any]],
    tool: str,
    tools: dict[str, str],
    command: str | list[str],
    evidence_summary: dict[str, Any],
    repository: str | None = None,
    workflow_sha: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Return a report with stable identity, provenance and failure fields.

    ``head_sha`` is retained as a compatibility alias for the audited source
    commit.  On pull requests ``workflow_sha`` may be the workflow event SHA,
    while ``source_commit`` remains the explicitly checked-out PR head.
    """

    source_commit = head_sha
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "repository": repository_name(repository),
        "component": component,
        "source_commit": source_commit,
        "head_sha": head_sha,
        "workflow_sha": workflow_sha if workflow_sha is not None else head_sha,
        "tool": tool,
        "tools": tools,
        "tool_versions": tools,
        "command": command,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "result": result,
        "failure_category": failure_categories(findings),
        "evidence_summary": evidence_summary,
    }
    report.update(extra)
    report["findings"] = findings
    return report
