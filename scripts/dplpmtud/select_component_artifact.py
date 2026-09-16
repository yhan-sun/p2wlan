#!/usr/bin/env python3
"""Select the component evidence that the DPLPMTUD aggregate may consume.

Artifacts are named ``dplpmtud-live-component-<run_id>-<run_attempt>``. A full
re-run uploads the component again under the new attempt, so the aggregate
finds it directly. A *partial* re-run (GitHub's "re-run failed jobs") leaves
the component artifact under the attempt that actually produced it, which is
why the previous implementation -- matching the current attempt exactly and
then picking an arbitrary file with ``find -quit`` -- failed with an opaque
"no files were found" and could silently pick the wrong evidence.

This selector accepts an artifact from a previous attempt only after checking
every identity that matters: the run identity encoded in the artifact name,
the source commit, the workflow blob, the contract digest, the self digest and
the success of the job that produced it. Anything it cannot verify fails closed
with a specific reason code instead of succeeding.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

ARTIFACT_PREFIX = "dplpmtud-live-component-"
COMPONENT_FILE = "dplpmtud-live-component.json"
COMPONENT_JOB_NAME = "DPLPMTUD live dataplane evidence"
ARTIFACT_NAME = re.compile(rf"^{re.escape(ARTIFACT_PREFIX)}(\d+)-(\d+)$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class SelectionError(RuntimeError):
    """The component evidence may not be used; the message is the reason code."""


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def parse_artifact_name(name: str) -> tuple[int, int]:
    match = ARTIFACT_NAME.fullmatch(name)
    if match is None:
        raise SelectionError(f"component_artifact_name_invalid:{name}")
    return int(match.group(1)), int(match.group(2))


def index_candidates(names: Iterable[str], root: Path) -> dict[tuple[int, int], Path]:
    """Map (run_id, attempt) -> directory, refusing ambiguous evidence."""
    candidates: dict[tuple[int, int], Path] = {}
    for name in names:
        if not name.startswith(ARTIFACT_PREFIX):
            continue
        parsed_run, parsed_attempt = parse_artifact_name(name)
        key = (parsed_run, parsed_attempt)
        if key in candidates:
            raise SelectionError(f"component_artifact_duplicate:{name}")
        candidates[key] = root / name
    return candidates


def find_component_file(artifact_dir: Path) -> Path:
    matches = sorted(path for path in artifact_dir.rglob(COMPONENT_FILE) if path.is_file())
    if not matches:
        raise SelectionError(f"component_evidence_file_missing:{artifact_dir.name}")
    if len(matches) > 1:
        raise SelectionError(
            f"component_evidence_file_duplicate:{artifact_dir.name}:{len(matches)}"
        )
    return matches[0]


def verify_component(
    component: dict[str, Any],
    *,
    contract: dict[str, Any],
    source_head_sha: str,
    workflow_sha: str,
    run_id: int,
    run_attempt: int,
) -> None:
    if component.get("schema_version") != 1:
        raise SelectionError("component_schema_unknown")
    if component.get("repository") != contract.get("repository"):
        raise SelectionError("component_repository_mismatch")
    if component.get("component") != contract.get("component"):
        raise SelectionError("component_name_mismatch")
    if component.get("source_head_sha") != source_head_sha:
        raise SelectionError(
            f"component_source_head_mismatch:{component.get('source_head_sha')}:{source_head_sha}"
        )
    if component.get("workflow_sha") != workflow_sha:
        raise SelectionError(
            f"component_workflow_sha_mismatch:{component.get('workflow_sha')}:{workflow_sha}"
        )
    if component.get("run_id") != run_id:
        raise SelectionError(f"component_run_id_mismatch:{component.get('run_id')}:{run_id}")
    if component.get("run_attempt") != run_attempt:
        raise SelectionError(
            f"component_run_attempt_mismatch:{component.get('run_attempt')}:{run_attempt}"
        )
    if component.get("result") != "pass":
        raise SelectionError("component_result_not_pass")
    if component.get("contract_sha256") != _canonical_sha256(contract):
        raise SelectionError("component_contract_digest_mismatch")
    claimed = component.get("report_digest")
    if not isinstance(claimed, str):
        raise SelectionError("component_report_digest_missing")
    without = dict(component)
    without.pop("report_digest", None)
    if _canonical_sha256(without) != claimed:
        raise SelectionError("component_report_digest_mismatch")


def component_job_succeeded(attempt_jobs: Iterable[dict[str, Any]]) -> bool:
    matches = [job for job in attempt_jobs if job.get("name") == COMPONENT_JOB_NAME]
    if len(matches) != 1:
        return False
    return matches[0].get("status") == "completed" and matches[0].get("conclusion") == "success"


def http_attempt_jobs(repo: str, token: str, run_id: int, attempt: int) -> list[dict[str, Any]]:
    url = (
        f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs"
        f"?{urllib.parse.urlencode({'per_page': '100'})}"
    )
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "p2wlan-dplpmtud-selector",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as error:
        raise SelectionError(f"component_attempt_query_failed:{attempt}:{error}") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("jobs"), list):
        raise SelectionError(f"component_attempt_query_invalid:{attempt}")
    return payload["jobs"]


def select(
    artifacts_root: Path,
    *,
    contract: dict[str, Any],
    source_head_sha: str,
    workflow_sha: str,
    run_id: int,
    current_attempt: int,
    component_result: str,
    attempt_jobs: Callable[[int], list[dict[str, Any]]],
    allow_earlier_attempts: bool = True,
) -> dict[str, Any]:
    _validate_sha(source_head_sha, "source_head_sha")
    _validate_sha(workflow_sha, "workflow_sha")

    entries = sorted(artifacts_root.iterdir()) if artifacts_root.is_dir() else []
    candidates = index_candidates([entry.name for entry in entries if entry.is_dir()], artifacts_root)

    relevant = {
        key: path for key, path in candidates.items() if key[0] == run_id and key[1] <= current_attempt
    }
    if not relevant:
        seen = ",".join(sorted({str(attempt) for _, attempt in candidates})) or "none"
        raise SelectionError(f"component_artifact_missing:run_id={run_id}:attempts_seen={seen}")

    reasons: list[str] = []
    for attempt in sorted({attempt for _, attempt in relevant}, reverse=True):
        path = relevant[(run_id, attempt)]
        reused = attempt != current_attempt
        if reused and not allow_earlier_attempts:
            reasons.append(f"attempt={attempt}:component_reuse_disabled")
            continue
        try:
            component_file = find_component_file(path)
            component = json.loads(component_file.read_text(encoding="utf-8"))
            if not isinstance(component, dict):
                raise SelectionError(f"component_not_object:{path.name}")
            verify_component(
                component,
                contract=contract,
                source_head_sha=source_head_sha,
                workflow_sha=workflow_sha,
                run_id=run_id,
                run_attempt=attempt,
            )
        except (SelectionError, OSError, json.JSONDecodeError) as error:
            reasons.append(f"attempt={attempt}:{error}")
            continue

        if reused:
            # Reusing another attempt is only sound if that attempt really ran
            # the component to success. The job result reported for the current
            # attempt says nothing about it.
            if not component_job_succeeded(attempt_jobs(attempt)):
                reasons.append(f"attempt={attempt}:component_job_not_success_in_that_attempt")
                continue
        elif component_result != "success":
            reasons.append(f"attempt={attempt}:component_job_not_success:{component_result}")
            continue

        return {
            "component": str(component_file),
            "run_id": run_id,
            "run_attempt": attempt,
            "reused": reused,
            "report_digest": component["report_digest"],
        }

    raise SelectionError("component_artifact_unverified:" + "|".join(reasons))


def _validate_sha(value: str, label: str) -> None:
    if SHA40.fullmatch(value) is None:
        raise SelectionError(f"{label}_invalid")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-root", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--source-head-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--current-attempt", required=True, type=int)
    parser.add_argument("--component-result", required=True)
    parser.add_argument("--allow-earlier-attempts", choices=["true", "false"], default="true")
    parser.add_argument("--output", default="")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        contract = json.loads(Path(args.contract).read_text(encoding="utf-8"))
        if not isinstance(contract, dict):
            raise SelectionError("contract_not_object")

        def attempt_jobs(attempt: int) -> list[dict[str, Any]]:
            token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
            repo = os.environ.get("GITHUB_REPOSITORY")
            if not token or not repo:
                raise SelectionError("component_attempt_query_unavailable")
            return http_attempt_jobs(repo, token, args.run_id, attempt)

        result = select(
            Path(args.artifacts_root),
            contract=contract,
            source_head_sha=args.source_head_sha,
            workflow_sha=args.workflow_sha,
            run_id=args.run_id,
            current_attempt=args.current_attempt,
            component_result=args.component_result,
            attempt_jobs=attempt_jobs,
            allow_earlier_attempts=args.allow_earlier_attempts == "true",
        )
    except (SelectionError, OSError, json.JSONDecodeError) as error:
        print(f"component selection failed: {error}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    if args.output:
        with open(args.output, "a", encoding="utf-8") as handle:
            handle.write(f"component={result['component']}\n")
            handle.write(f"component_run_id={result['run_id']}\n")
            handle.write(f"component_run_attempt={result['run_attempt']}\n")
            handle.write(f"component_reused={'true' if result['reused'] else 'false'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
