import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_required_gates as gates

SHA = "a" * 40
OTHER_SHA = "b" * 40


def job(name, status="completed", conclusion="success"):
    return gates.JobResult(name=name, status=status, conclusion=conclusion)


def run(
    workflow,
    event,
    jobs,
    *,
    status="completed",
    conclusion="success",
    run_id=1,
    attempt=1,
    created="2026-01-01T00:00:00Z",
    head_sha=SHA,
):
    return gates.WorkflowRun(
        run_id=run_id,
        workflow_name=workflow,
        event=event,
        head_sha=head_sha,
        status=status,
        conclusion=conclusion,
        run_attempt=attempt,
        created_at=created,
        jobs=tuple(jobs),
    )


class ClassifyTests(unittest.TestCase):
    def test_passing_authoritative_run_authorizes(self):
        runs = [run("CI", "pull_request", [job("CI Required")])]
        finding = gates.classify_gate("CI Required", runs, head_sha=SHA)
        self.assertIs(finding.state, gates.GateState.PASS)
        self.assertTrue(gates.authorized([finding]))

    def test_schedule_success_does_not_mask_push_failure(self):
        runs = [
            run("NAT Topology Gate", "push", [job("NAT Topology Required", conclusion="failure")], run_id=1),
            run(
                "NAT Topology Gate",
                "schedule",
                [job("NAT Topology Required")],
                run_id=2,
                created="2026-01-02T00:00:00Z",
            ),
        ]
        finding = gates.classify_gate("NAT Topology Required", runs, head_sha=SHA)
        self.assertIs(finding.state, gates.GateState.FAIL)
        self.assertFalse(gates.authorized([finding]))
        self.assertIn("authoritative", finding.detail)

    def test_schedule_success_does_not_mask_push_cancellation(self):
        runs = [
            run(
                "NAT Topology Gate",
                "push",
                [job("NAT Topology Required", conclusion="cancelled")],
                status="completed",
                conclusion="cancelled",
                run_id=1,
            ),
            run("NAT Topology Gate", "schedule", [job("NAT Topology Required")], run_id=2, created="2026-01-02T00:00:00Z"),
        ]
        finding = gates.classify_gate("NAT Topology Required", runs, head_sha=SHA)
        self.assertIs(finding.state, gates.GateState.CANCELLED)
        self.assertFalse(gates.authorized([finding]))

    def test_scheduled_only_evidence_is_labelled(self):
        runs = [run("NAT Topology Gate", "schedule", [job("NAT Topology Required")])]
        finding = gates.classify_gate("NAT Topology Required", runs, head_sha=SHA)
        self.assertIs(finding.state, gates.GateState.PASS)
        self.assertIn("schedule-only", finding.detail)

    def test_cancelled_is_not_reported_as_failure(self):
        runs = [run("CI", "push", [job("CI Required", conclusion="cancelled")])]
        self.assertIs(gates.classify_gate("CI Required", runs, head_sha=SHA).state, gates.GateState.CANCELLED)

    def test_terminal_failures_are_failures(self):
        for conclusion in ["failure", "timed_out", "startup_failure", "action_required", "stale"]:
            with self.subTest(conclusion=conclusion):
                runs = [run("CI", "push", [job("CI Required", conclusion=conclusion)])]
                self.assertIs(gates.classify_gate("CI Required", runs, head_sha=SHA).state, gates.GateState.FAIL)

    def test_incomplete_job_is_pending(self):
        runs = [run("CI", "push", [job("CI Required", status="in_progress", conclusion=None)], status="in_progress", conclusion=None)]
        self.assertIs(gates.classify_gate("CI Required", runs, head_sha=SHA).state, gates.GateState.PENDING)

    def test_run_without_the_job_is_missing(self):
        runs = [run("CI", "push", [job("Some Other Job")])]
        self.assertIs(gates.classify_gate("CI Required", runs, head_sha=SHA).state, gates.GateState.MISSING)

    def test_no_run_at_all_is_missing_not_pass(self):
        finding = gates.classify_gate("CI Required", [], head_sha=SHA)
        self.assertIs(finding.state, gates.GateState.MISSING)
        self.assertFalse(gates.authorized([finding]))

    def test_unbound_gate_name_is_rejected(self):
        finding = gates.classify_gate("Not A Real Gate", [run("CI", "push", [job("Not A Real Gate")])], head_sha=SHA)
        self.assertIs(finding.state, gates.GateState.API_ERROR)
        self.assertFalse(gates.authorized([finding]))

    def test_same_named_check_from_another_workflow_cannot_satisfy(self):
        runs = [run("Path Observability", "push", [job("CI Required")])]
        self.assertIs(gates.classify_gate("CI Required", runs, head_sha=SHA).state, gates.GateState.MISSING)

    def test_duplicate_job_names_in_one_run_fail_closed(self):
        runs = [run("CI", "push", [job("CI Required"), job("CI Required", conclusion="failure")])]
        self.assertIs(gates.classify_gate("CI Required", runs, head_sha=SHA).state, gates.GateState.API_ERROR)

    def test_runs_for_other_commits_are_ignored(self):
        runs = [run("CI", "push", [job("CI Required")], head_sha=OTHER_SHA)]
        self.assertIs(gates.classify_gate("CI Required", runs, head_sha=SHA).state, gates.GateState.MISSING)

    def test_every_bound_gate_resolves_to_a_workflow(self):
        for name in gates.GATE_WORKFLOWS:
            self.assertIsNotNone(gates.GATE_WORKFLOWS[name])

    def test_authorization_requires_a_non_empty_all_pass_set(self):
        self.assertFalse(gates.authorized([]))
        pending = gates.classify_gate(
            "CI Required",
            [run("CI", "push", [job("CI Required", status="in_progress", conclusion=None)])],
            head_sha=SHA,
        )
        self.assertFalse(gates.authorized([pending]))


    def test_a_pass_does_not_block_waiting_for_the_rest(self):
        findings = [
            gates.classify_gate(
                "CI Required",
                [run("CI", "push", [job("CI Required")])],
                head_sha=SHA,
            ),
            gates.classify_gate(
                "NAT Topology Required",
                [run("NAT Topology Gate", "push", [job("NAT Topology Required", status="in_progress", conclusion=None)], status="in_progress")],
                head_sha=SHA,
            ),
        ]
        self.assertIs(findings[0].state, gates.GateState.PASS)
        self.assertIs(findings[1].state, gates.GateState.PENDING)
        self.assertEqual(gates.blocking_findings(findings), [])
        self.assertFalse(gates.authorized(findings))

    def test_terminal_failures_and_missing_do_block(self):
        findings = [
            gates.classify_gate("CI Required", [run("CI", "push", [job("CI Required", conclusion="failure")])], head_sha=SHA),
            gates.classify_gate("NAT Topology Required", [], head_sha=SHA),
        ]
        self.assertEqual(
            [f.job_name for f in gates.blocking_findings(findings)],
            ["CI Required", "NAT Topology Required"],
        )


class ResponseTests(unittest.TestCase):
    """The HTTP layer must never turn a broken response into success."""

    RUNS_URL = "/actions/runs"
    JOBS_URL = "/jobs"

    def _client(self, route):
        """route(url) -> (status, body_bytes); returns (client, patcher, requested_urls)."""
        requested = []

        class FakeResponse(io.BytesIO):
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_urlopen(request, timeout=30):
            requested.append(request.full_url)
            status, body = route(request.full_url)
            if status >= 400:
                raise urllib.error.HTTPError(request.full_url, status, "error", {}, io.BytesIO(body))
            return FakeResponse(body)

        return (
            gates.GitHubClient("owner/repo", "token", retries=1),
            patch("urllib.request.urlopen", fake_urlopen),
            requested,
        )

    def _runs_page(self, runs):
        return json.dumps({"total_count": len(runs), "workflow_runs": runs}).encode()

    def _jobs_page(self, jobs):
        return json.dumps({"total_count": len(jobs), "jobs": jobs}).encode()

    def _run_entry(self, run_id, head_sha=SHA):
        return {
            "id": run_id,
            "name": "CI",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "run_attempt": 2,
            "created_at": "2026-01-01T00:00:00Z",
            "head_sha": head_sha,
        }

    def _always_jobs(self, jobs):
        def route(url):
            if self.JOBS_URL in url:
                return 200, self._jobs_page(jobs)
            raise AssertionError(f"unexpected url {url}")

        return route

    def test_happy_path_reads_runs_and_jobs(self):
        def route(url):
            if self.JOBS_URL in url:
                return 200, self._jobs_page([{"name": "CI Required", "status": "completed", "conclusion": "success"}])
            return 200, self._runs_page([self._run_entry(7)])

        client, patcher, _ = self._client(route)
        with patcher:
            runs = client.runs_for(SHA)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].run_attempt, 2)
        self.assertIs(gates.classify_gate("CI Required", runs, head_sha=SHA).state, gates.GateState.PASS)

    def test_http_error_is_an_api_error(self):
        client, patcher, _ = self._client(lambda url: (500, b"{}"))
        with patcher, self.assertRaises(gates.GateRequestError):
            client.runs_for(SHA)

    def test_empty_body_is_an_api_error(self):
        client, patcher, _ = self._client(lambda url: (200, b""))
        with patcher, self.assertRaises(gates.GateRequestError):
            client.runs_for(SHA)

    def test_missing_required_field_is_an_api_error(self):
        partial = {"id": 7, "name": "CI", "event": "push"}
        client, patcher, _ = self._client(lambda url: (200, self._runs_page([partial])))
        with patcher, self.assertRaises(gates.GateRequestError):
            client.runs_for(SHA)

    def test_body_without_the_runs_field_is_an_api_error(self):
        client, patcher, _ = self._client(lambda url: (200, json.dumps({"total_count": 1}).encode()))
        with patcher, self.assertRaises(gates.GateRequestError):
            client.runs_for(SHA)

    def test_head_sha_mismatch_is_an_api_error(self):
        entry = self._run_entry(7, head_sha=OTHER_SHA)
        client, patcher, _ = self._client(lambda url: (200, self._runs_page([entry])))
        with patcher, self.assertRaises(gates.GateRequestError):
            client.runs_for(SHA)

    def test_full_page_followed_by_failure_is_an_api_error(self):
        full_page = [self._run_entry(i) for i in range(100)]

        def route(url):
            if "page=2" in url:
                return 500, b"{}"
            return 200, self._runs_page(full_page)

        client, patcher, _ = self._client(route)
        with patcher, self.assertRaises(gates.GateRequestError):
            client.runs_for(SHA)

    def test_pagination_walks_every_page(self):
        first = [self._run_entry(i) for i in range(100)]
        second = [self._run_entry(100)]
        jobs = [{"name": "CI Required", "status": "completed", "conclusion": "success"}]

        def route(url):
            if self.JOBS_URL in url:
                return 200, self._jobs_page(jobs)
            if "page=2" in url:
                return 200, self._runs_page(second)
            return 200, self._runs_page(first)

        client, patcher, requested = self._client(route)
        with patcher:
            runs = client.runs_for(SHA)
        self.assertEqual(len(runs), 101)
        runs_pages = [url for url in requested if self.JOBS_URL not in url]
        self.assertEqual(len(runs_pages), 2, runs_pages)
        self.assertIn("page=1", runs_pages[0])
        self.assertIn("page=2", runs_pages[1])

    def test_in_flight_runs_are_re_read_but_finished_runs_are_cached(self):
        jobs = [{"name": "CI Required", "status": "completed", "conclusion": "success"}]

        def route(url):
            if self.JOBS_URL in url:
                return 200, self._jobs_page(jobs)
            return 200, self._runs_page([self._run_entry(7)])

        client, patcher, requested = self._client(route)
        with patcher:
            client.jobs(7, final=False)
            client.jobs(7, final=False)
            client.jobs(7, final=True)
            client.jobs(7, final=True)
        job_urls = [url for url in requested if self.JOBS_URL in url]
        # An in-flight run is re-read every poll; a completed one is cached.
        self.assertEqual(len(job_urls), 3, job_urls)

    def test_jobs_are_fetched_once_per_run(self):
        jobs = [{"name": "CI Required", "status": "completed", "conclusion": "success"}]

        def route(url):
            if self.JOBS_URL in url:
                return 200, self._jobs_page(jobs)
            return 200, self._runs_page([self._run_entry(7)])

        client, patcher, requested = self._client(route)
        with patcher:
            client.runs_for(SHA)
            client.runs_for(SHA)
        job_urls = [url for url in requested if self.JOBS_URL in url]
        self.assertEqual(len(job_urls), 1, job_urls)

    def test_job_without_name_is_an_api_error(self):
        client, patcher, _ = self._client(
            lambda url: (200, self._jobs_page([{"status": "completed", "conclusion": "success"}]))
        )
        with patcher, self.assertRaises(gates.GateRequestError):
            client.jobs(7, final=True)


class CliTests(unittest.TestCase):
    def test_missing_sha_and_gate_are_rejected(self):
        self.assertEqual(gates.main(["--require", "CI Required", "--sha", ""]), 2)
        self.assertEqual(gates.main(["--sha", SHA]), 2)

    def test_unknown_gate_name_is_rejected_before_any_query(self):
        self.assertEqual(gates.main(["--sha", SHA, "--require", "Nope"]), 2)

    def test_api_failure_exits_non_zero(self):
        with patch.object(gates, "_client", side_effect=gates.GateRequestError("boom")):
            self.assertEqual(gates.main(["--sha", SHA, "--require", "CI Required"]), 1)

    def test_terminal_non_pass_exits_non_zero(self):
        failing = gates.WorkflowRun(
            run_id=1,
            workflow_name="CI",
            event="push",
            head_sha=SHA,
            status="completed",
            conclusion="failure",
            run_attempt=1,
            created_at="2026-01-01T00:00:00Z",
            jobs=(gates.JobResult("CI Required", "completed", "failure"),),
        )
        with patch.object(gates, "_client") as client:
            client.return_value.runs_for.return_value = [failing]
            self.assertEqual(gates.main(["--sha", SHA, "--require", "CI Required"]), 1)

    def test_all_pass_exits_zero(self):
        passing = gates.WorkflowRun(
            run_id=1,
            workflow_name="CI",
            event="push",
            head_sha=SHA,
            status="completed",
            conclusion="success",
            run_attempt=1,
            created_at="2026-01-01T00:00:00Z",
            jobs=(gates.JobResult("CI Required", "completed", "success"),),
        )
        with patch.object(gates, "_client") as client:
            client.return_value.runs_for.return_value = [passing]
            self.assertEqual(gates.main(["--sha", SHA, "--require", "CI Required"]), 0)


if __name__ == "__main__":
    unittest.main()
