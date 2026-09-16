#!/usr/bin/env python3
"""Decide whether the required cross-workflow gates passed for one exact commit.

This is the merge-authorization gate. It exists because the previous inline
``github-script`` aggregators could not express the difference between "the
gate passed", "the gate never ran", "the query failed" and "a scheduled run
overwrote a cancelled commit validation", and treated all four as silence.

Rules this module enforces:

* A required gate is bound to the **workflow that owns it** as well as to the
  job name, so a same-named check from an unrelated workflow cannot satisfy it.
* ``push``/``pull_request`` runs are the authoritative evidence for a commit.
  ``schedule``/``workflow_dispatch`` runs of the same workflow may add evidence
  but must never mask an authoritative failure or cancellation.
* Every gate ends in exactly one of ``pass``, ``fail``, ``cancelled``,
  ``missing``, ``api_error`` or ``pending``. Only ``pass`` authorizes a merge.
* A failed request, an unreadable response, a response missing required fields
  or an unfinished pagination walk produces ``api_error`` -- never success.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping, Sequence


class GateState(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    CANCELLED = "cancelled"
    MISSING = "missing"
    API_ERROR = "api_error"
    PENDING = "pending"

    @property
    def terminal(self) -> bool:
        return self is not GateState.PENDING


TERMINAL_FAILURES = frozenset(
    {"failure", "timed_out", "startup_failure", "action_required", "stale"}
)
AUTHORITATIVE_EVENTS = frozenset({"pull_request", "push"})

# A required job name is only meaningful together with the workflow that
# publishes it. Keeping the pair here means a rename in either place fails
# loudly instead of silently matching an unrelated check.
GATE_WORKFLOWS: Mapping[str, str] = {
    "Business MTU Budget Required": "Business MTU Budget Required",
    "Path State Machine Required": "Path State Machine",
    "NAT Topology Required": "NAT Topology Gate",
    "Windows Lifecycle Required": "Windows Lifecycle",
    "Mobile Lifecycle Required": "Mobile Lifecycle",
    "Path Observability Required": "Path Observability",
    "Security Audit Required": "Security Audit",
    "CI Required": "CI",
    "DPLPMTUD Required": "DPLPMTUD Required",
    "Analyze and Test": "Flutter Client",
    "Android arm64 CI test APK": "Flutter Client",
    "iOS Compile": "Flutter Client",
    "Linux x64 Release Bundle": "Flutter Client",
    "macOS Release Apps": "Flutter Client",
    "Windows x64 Release Bundle": "Flutter Client",
    "macOS arm64 test DMG": "Package Test Builds",
    "Android arm64 test APK": "Package Test Builds",
}


class GateRequestError(RuntimeError):
    """The query could not be completed; the caller must not read this as success."""


@dataclass(frozen=True)
class JobResult:
    name: str
    status: str
    conclusion: str | None


@dataclass(frozen=True)
class WorkflowRun:
    run_id: int
    workflow_name: str
    event: str
    head_sha: str
    status: str
    conclusion: str | None
    run_attempt: int
    created_at: str
    jobs: tuple[JobResult, ...] = ()

    @property
    def authoritative(self) -> bool:
        return self.event in AUTHORITATIVE_EVENTS

    def sort_key(self) -> tuple[str, int]:
        return (self.created_at or "", self.run_id)


@dataclass
class GateFinding:
    job_name: str
    workflow_name: str
    state: GateState
    detail: str

    def render(self) -> str:
        return f"{self.job_name}: {self.state.value} ({self.detail})"


def _job_state(job: JobResult) -> GateState:
    if job.status != "completed":
        return GateState.PENDING
    if job.conclusion == "success":
        return GateState.PASS
    if job.conclusion == "cancelled":
        return GateState.CANCELLED
    if job.conclusion in TERMINAL_FAILURES:
        return GateState.FAIL
    if job.conclusion is None:
        return GateState.PENDING
    return GateState.FAIL


def _run_state(run: WorkflowRun, job_name: str) -> tuple[GateState, str]:
    jobs = [job for job in run.jobs if job.name == job_name]
    attempt = f"attempt={run.run_attempt}"
    if run.status == "completed" and run.conclusion == "cancelled":
        return GateState.CANCELLED, f"run {run.run_id} {run.event} {attempt} was cancelled"
    if not jobs:
        if run.status == "completed":
            return GateState.MISSING, f"run {run.run_id} {run.event} {attempt} has no job {job_name!r}"
        return GateState.PENDING, f"run {run.run_id} {run.event} {attempt} has not published the job yet"
    if len(jobs) > 1:
        # GitHub does not normally repeat a job name inside one run; if it does,
        # fail closed rather than choosing one of the duplicates.
        return GateState.API_ERROR, f"run {run.run_id} reports {len(jobs)} jobs named {job_name!r}"
    state = _job_state(jobs[0])
    return state, f"run {run.run_id} {run.event} {attempt} job {jobs[0].status}/{jobs[0].conclusion or 'pending'}"


def classify_gate(
    job_name: str, runs: Sequence[WorkflowRun], *, head_sha: str | None = None
) -> GateFinding:
    """Classify one required gate from the runs observed for the target commit."""
    workflow_name = GATE_WORKFLOWS.get(job_name)
    if workflow_name is None:
        return GateFinding(job_name, "<unknown>", GateState.API_ERROR, "no workflow is bound to this gate name")

    candidates = [
        run
        for run in runs
        if run.workflow_name == workflow_name and (head_sha is None or run.head_sha == head_sha)
    ]
    if not candidates:
        return GateFinding(
            job_name,
            workflow_name,
            GateState.MISSING,
            f"no {workflow_name!r} run observed for {head_sha}",
        )

    authoritative = [run for run in candidates if run.authoritative]
    # A scheduled or manually dispatched run may only be consulted when the
    # commit has no authoritative validation at all.
    source = authoritative if authoritative else candidates
    provenance = "authoritative" if authoritative else f"{source[0].event}-only"

    evaluated = sorted(
        ((_run_state(run, job_name), run) for run in source),
        key=lambda item: item[1].sort_key(),
        reverse=True,
    )

    # Fail closed: an authoritative failure or cancellation is reported even if
    # some other run of the same gate happened to finish green.
    for (state, _detail), run in evaluated:
        if state in (GateState.FAIL, GateState.CANCELLED, GateState.API_ERROR):
            run_state, run_detail = _run_state(run, job_name)
            return GateFinding(
                job_name,
                workflow_name,
                run_state,
                f"{provenance}; {run_detail}",
            )

    (state, detail), _run = evaluated[0]
    if state is GateState.PASS:
        return GateFinding(job_name, workflow_name, GateState.PASS, f"{provenance}; {detail}")
    return GateFinding(job_name, workflow_name, state, f"{provenance}; {detail}")


def evaluate(
    gates: Iterable[str], runs: Sequence[WorkflowRun], *, head_sha: str | None = None
) -> list[GateFinding]:
    return [classify_gate(name, runs, head_sha=head_sha) for name in gates]


def blocking_findings(findings: Sequence[GateFinding]) -> list[GateFinding]:
    """Gates that already failed; a pass and a pending gate are not blockers.

    Only a terminal non-pass state stops the wait. Treating a pass as a blocker
    would abort on the first gate that finishes instead of waiting for the rest.
    """
    return [
        finding
        for finding in findings
        if finding.state not in (GateState.PENDING, GateState.PASS)
    ]


def authorized(findings: Sequence[GateFinding]) -> bool:
    """Only a fully terminal, fully passing set of gates authorizes a merge."""
    return bool(findings) and all(finding.state is GateState.PASS for finding in findings)


# --------------------------------------------------------------------------
# GitHub API access
# --------------------------------------------------------------------------

MAX_PAGES = 20  # 20 * 100 = 2000 runs/jobs; more than any real commit produces.


class GitHubClient:
    def __init__(self, repo: str, token: str, *, api: str = "https://api.github.com", retries: int = 3):
        self.repo = repo
        self.token = token
        self.api = api.rstrip("/")
        self.retries = retries
        self._job_cache: dict[int, tuple[JobResult, ...]] = {}

    def _paginate(self, path: str, key: str, params: Mapping[str, str]) -> list[dict]:
        items: list[dict] = []
        page = 1
        while True:
            query = dict(params, per_page="100", page=str(page))
            url = f"{self.api}{path}?{urllib.parse.urlencode(query)}"
            request = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "p2wlan-required-gates",
                },
            )
            last_error: Exception | None = None
            for attempt in range(self.retries):
                try:
                    with urllib.request.urlopen(request, timeout=30) as response:
                        payload = json.loads(response.read().decode("utf-8"))
                    break
                except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as error:
                    last_error = error
                    if attempt + 1 < self.retries:
                        time.sleep(2 * (attempt + 1))
            else:
                raise GateRequestError(f"GET {path} page {page} failed after {self.retries} attempts: {last_error}")

            if not isinstance(payload, dict):
                raise GateRequestError(f"GET {path} page {page} returned a non-object body")
            if key not in payload:
                raise GateRequestError(f"GET {path} page {page} is missing the {key!r} field")
            chunk = payload[key]
            if not isinstance(chunk, list):
                raise GateRequestError(f"GET {path} page {page} returned {key!r} as {type(chunk).__name__}")
            items.extend(chunk)
            if len(chunk) < 100:
                return items
            page += 1
            if page > MAX_PAGES:
                raise GateRequestError(f"GET {path} did not finish paginating within {MAX_PAGES} pages")

    def jobs(self, run_id: int, *, final: bool) -> tuple[JobResult, ...]:
        # A job list is only stable once the run is completed: caching the jobs
        # of an in-flight run freezes the "job not published yet" state and
        # later reports a finished run as missing that gate.
        if final and run_id in self._job_cache:
            return self._job_cache[run_id]
        raw = self._paginate(f"/repos/{self.repo}/actions/runs/{run_id}/jobs", "jobs", {})
        parsed: list[JobResult] = []
        for job in raw:
            name = job.get("name")
            status = job.get("status")
            if not isinstance(name, str) or not isinstance(status, str):
                raise GateRequestError(f"run {run_id} returned a job without name/status")
            parsed.append(JobResult(name=name, status=status, conclusion=job.get("conclusion")))
        if final:
            self._job_cache[run_id] = tuple(parsed)
        return tuple(parsed)

    def runs_for(self, head_sha: str) -> list[WorkflowRun]:
        raw = self._paginate(
            f"/repos/{self.repo}/actions/runs", "workflow_runs", {"head_sha": head_sha}
        )
        runs: list[WorkflowRun] = []
        for run in raw:
            if run.get("head_sha") != head_sha:
                # The head_sha filter is authoritative; anything else means the
                # response cannot be trusted for this commit.
                raise GateRequestError(
                    f"runs query for {head_sha} returned head_sha={run.get('head_sha')!r}"
                )
            try:
                run_id = int(run["id"])
                workflow_name = run["name"]
                event = run["event"]
                status = run["status"]
                created_at = run["created_at"]
            except (KeyError, TypeError, ValueError) as error:
                raise GateRequestError(f"run entry is missing a required field: {error}") from error
            runs.append(
                WorkflowRun(
                    run_id=run_id,
                    workflow_name=workflow_name,
                    event=event,
                    head_sha=head_sha,
                    status=status,
                    conclusion=run.get("conclusion"),
                    run_attempt=int(run.get("run_attempt") or 1),
                    created_at=created_at,
                    jobs=self.jobs(run_id, final=status == "completed"),
                )
            )
        return runs


def _client() -> GitHubClient:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token:
        raise GateRequestError("GH_TOKEN/GITHUB_TOKEN is not set")
    if not repo or "/" not in repo:
        raise GateRequestError("GITHUB_REPOSITORY is not set to owner/repo")
    return GitHubClient(repo, token)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", default=os.environ.get("P2WLAN_EXACT_HEAD") or os.environ.get("GITHUB_SHA"))
    parser.add_argument("--require", action="append", default=[], metavar="JOB_NAME")
    parser.add_argument("--timeout-seconds", type=int, default=3900)
    parser.add_argument("--poll-seconds", type=int, default=20)
    args = parser.parse_args(argv)

    if not args.sha:
        print("FAIL required gates: no target SHA was provided", file=sys.stderr)
        return 2
    if not args.require:
        print("FAIL required gates: no --require gate was provided", file=sys.stderr)
        return 2
    unknown = [name for name in args.require if name not in GATE_WORKFLOWS]
    if unknown:
        print(
            "FAIL required gates: these gate names have no bound workflow: " + ", ".join(unknown),
            file=sys.stderr,
        )
        return 2

    try:
        client = _client()
    except GateRequestError as error:
        print(f"FAIL required gates: {error}", file=sys.stderr)
        return 1

    deadline = time.monotonic() + args.timeout_seconds
    last_line = ""
    while True:
        try:
            runs = client.runs_for(args.sha)
            findings = evaluate(args.require, runs, head_sha=args.sha)
        except GateRequestError as error:
            # A query that cannot be completed is an API error, not a pass.
            print(f"FAIL required gates for {args.sha}: api_error: {error}", file=sys.stderr)
            return 1

        line = " | ".join(finding.render() for finding in findings)
        if line != last_line:
            print(f"required gate status for {args.sha}: {line}")
            last_line = line

        if authorized(findings):
            print(f"PASS required gates for {args.sha}: {len(findings)} gates")
            return 0

        blocking = blocking_findings(findings)
        if blocking:
            print(f"FAIL required gates for {args.sha}", file=sys.stderr)
            for finding in blocking:
                print(f"- {finding.render()}", file=sys.stderr)
            return 1

        if time.monotonic() >= deadline:
            print(f"FAIL required gates for {args.sha}: timed out waiting", file=sys.stderr)
            for finding in findings:
                print(f"- {finding.render()}", file=sys.stderr)
            return 1
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
