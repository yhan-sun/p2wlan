import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import select_component_artifact as selector

SOURCE = "a" * 40
WORKFLOW = "b" * 40
RUN_ID = 424242
CURRENT_ATTEMPT = 2
CONTRACT = {
    "schema_version": 1,
    "repository": "yhan-sun/p2wlan",
    "component": "dplpmtud-live-dataplane",
}


def component(run_id=RUN_ID, run_attempt=1, **overrides):
    value = {
        "schema_version": 1,
        "repository": CONTRACT["repository"],
        "component": CONTRACT["component"],
        "source_head_sha": SOURCE,
        "workflow_sha": WORKFLOW,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "contract_sha256": selector._canonical_sha256(CONTRACT),
        "result": "pass",
        "scenario_count": 1,
    }
    value.update(overrides)
    value["report_digest"] = selector._canonical_sha256(
        {k: v for k, v in value.items() if k != "report_digest"}
    )
    return value


def jobs(name=selector.COMPONENT_JOB_NAME, status="completed", conclusion="success"):
    return [{"name": name, "status": status, "conclusion": conclusion}]


class SelectorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def artifact(self, attempt, payload=None, *, run_id=RUN_ID, files=1):
        directory = self.root / f"{selector.ARTIFACT_PREFIX}{run_id}-{attempt}"
        directory.mkdir(parents=True, exist_ok=True)
        for index in range(files):
            target = directory if index == 0 else directory / f"nested{index}"
            target.mkdir(parents=True, exist_ok=True)
            (target / selector.COMPONENT_FILE).write_text(
                json.dumps(payload if payload is not None else component(run_id=run_id, run_attempt=attempt)),
                encoding="utf-8",
            )
        return directory

    def select(self, *, component_result="success", job_lookup=None, allow_earlier=True):
        return selector.select(
            self.root,
            contract=CONTRACT,
            source_head_sha=SOURCE,
            workflow_sha=WORKFLOW,
            run_id=RUN_ID,
            current_attempt=CURRENT_ATTEMPT,
            component_result=component_result,
            attempt_jobs=job_lookup or (lambda attempt: jobs()),
            allow_earlier_attempts=allow_earlier,
        )

    # ---- the full re-run path must keep working -------------------------

    def test_current_attempt_artifact_is_selected(self):
        self.artifact(CURRENT_ATTEMPT)
        result = self.select()
        self.assertEqual(result["run_attempt"], CURRENT_ATTEMPT)
        self.assertFalse(result["reused"])

    def test_current_attempt_wins_over_an_earlier_one(self):
        self.artifact(1)
        self.artifact(CURRENT_ATTEMPT)
        result = self.select()
        self.assertEqual(result["run_attempt"], CURRENT_ATTEMPT)
        self.assertFalse(result["reused"])

    def test_failed_current_attempt_is_rejected(self):
        self.artifact(CURRENT_ATTEMPT)
        with self.assertRaisesRegex(selector.SelectionError, "component_job_not_success"):
            self.select(component_result="failure")

    # ---- partial re-run -------------------------------------------------

    def test_partial_rerun_reuses_the_attempt_that_produced_the_artifact(self):
        self.artifact(1)
        result = self.select(job_lookup=lambda attempt: jobs())
        self.assertEqual(result["run_attempt"], 1)
        self.assertTrue(result["reused"])

    def test_partial_rerun_reports_the_exact_attempt_it_verified(self):
        self.artifact(1)
        asked = []

        def lookup(attempt):
            asked.append(attempt)
            return jobs()

        self.select(job_lookup=lookup)
        self.assertEqual(asked, [1])

    def test_partial_rerun_refuses_an_attempt_that_did_not_succeed(self):
        self.artifact(1)
        with self.assertRaisesRegex(selector.SelectionError, "component_job_not_success_in_that_attempt"):
            self.select(job_lookup=lambda attempt: jobs(conclusion="failure"))

    def test_partial_rerun_refuses_when_the_attempt_cannot_be_queried(self):
        self.artifact(1)

        def failing(attempt):
            raise selector.SelectionError("component_attempt_query_unavailable")

        with self.assertRaisesRegex(selector.SelectionError, "component_attempt_query_unavailable"):
            self.select(job_lookup=failing)

    def test_reuse_can_be_disabled_with_an_explicit_reason(self):
        self.artifact(1)
        with self.assertRaisesRegex(selector.SelectionError, "component_reuse_disabled"):
            self.select(allow_earlier=False)

    # ---- identity verification -----------------------------------------

    def test_source_sha_mismatch_is_refused(self):
        self.artifact(1, component(run_attempt=1, source_head_sha="c" * 40))
        with self.assertRaisesRegex(selector.SelectionError, "component_source_head_mismatch"):
            self.select()

    def test_workflow_sha_mismatch_is_refused(self):
        self.artifact(1, component(run_attempt=1, workflow_sha="d" * 40))
        with self.assertRaisesRegex(selector.SelectionError, "component_workflow_sha_mismatch"):
            self.select()

    def test_run_id_mismatch_is_refused(self):
        self.artifact(1, component(run_id=RUN_ID + 1, run_attempt=1))
        with self.assertRaisesRegex(selector.SelectionError, "component_run_id_mismatch"):
            self.select()

    def test_artifact_claiming_an_attempt_its_content_denies_is_refused(self):
        # The directory says attempt 1, the evidence says attempt 2.
        self.artifact(1, component(run_attempt=2))
        with self.assertRaisesRegex(selector.SelectionError, "component_run_attempt_mismatch"):
            self.select()

    def test_tampered_report_digest_is_refused(self):
        payload = component(run_attempt=1)
        payload["scenario_count"] = 99
        self.artifact(1, payload)
        with self.assertRaisesRegex(selector.SelectionError, "component_report_digest_mismatch"):
            self.select()

    def test_non_pass_component_is_refused(self):
        self.artifact(1, component(run_attempt=1, result="fail"))
        with self.assertRaisesRegex(selector.SelectionError, "component_result_not_pass"):
            self.select()

    # ---- defects in the artifact layout ---------------------------------

    def test_duplicate_artifacts_for_one_attempt_are_refused(self):
        # Two extracted copies of the same artifact name can reach the selector
        # when a download merges several artifact stores into one root.
        names = [f"{selector.ARTIFACT_PREFIX}{RUN_ID}-1", f"{selector.ARTIFACT_PREFIX}{RUN_ID}-1"]
        with self.assertRaisesRegex(selector.SelectionError, "component_artifact_duplicate"):
            selector.index_candidates(names, self.root)

    def test_index_ignores_names_that_are_not_component_artifacts(self):
        names = [
            f"{selector.ARTIFACT_PREFIX}{RUN_ID}-1",
            "dplpmtud-aggregate-1-1",
            f"{selector.ARTIFACT_PREFIX}{RUN_ID}-2",
        ]
        indexed = selector.index_candidates(names, self.root)
        self.assertEqual(sorted(indexed), [(RUN_ID, 1), (RUN_ID, 2)])

    def test_duplicate_component_files_inside_one_artifact_are_refused(self):
        self.artifact(1, files=2)
        with self.assertRaisesRegex(selector.SelectionError, "component_evidence_file_duplicate"):
            self.select()

    def test_missing_component_file_is_refused(self):
        (self.root / f"{selector.ARTIFACT_PREFIX}{RUN_ID}-1").mkdir()
        with self.assertRaisesRegex(selector.SelectionError, "component_evidence_file_missing"):
            self.select()

    def test_malformed_artifact_name_is_refused(self):
        (self.root / f"{selector.ARTIFACT_PREFIX}{RUN_ID}-1-extra").mkdir()
        with self.assertRaisesRegex(selector.SelectionError, "component_artifact_name_invalid"):
            self.select()

    def test_missing_artifact_reports_the_attempts_that_were_seen(self):
        self.artifact(CURRENT_ATTEMPT + 1)
        with self.assertRaisesRegex(
            selector.SelectionError, f"component_artifact_missing.*attempts_seen={CURRENT_ATTEMPT + 1}"
        ):
            self.select()

    def test_no_artifact_at_all_reports_no_attempts(self):
        with self.assertRaisesRegex(selector.SelectionError, "component_artifact_missing.*attempts_seen=none"):
            self.select()

    def test_artifact_from_another_run_is_ignored(self):
        self.artifact(1, run_id=RUN_ID + 5)
        with self.assertRaisesRegex(selector.SelectionError, "component_artifact_missing"):
            self.select()

    def test_artifact_from_a_later_attempt_is_ignored(self):
        self.artifact(CURRENT_ATTEMPT + 1)
        with self.assertRaisesRegex(selector.SelectionError, "component_artifact_missing"):
            self.select()

    def test_unverified_candidates_are_listed_in_the_reason(self):
        self.artifact(1, component(run_attempt=1, workflow_sha="e" * 40))
        with self.assertRaisesRegex(selector.SelectionError, "component_artifact_unverified.*attempt=1"):
            self.select()

    def test_local_evidence_without_a_run_identity_can_never_be_consumed(self):
        # A local report carries no CI run identity; it must never be accepted
        # as the component of a CI attempt.
        self.artifact(1, component(run_id=None, run_attempt=None))
        with self.assertRaisesRegex(selector.SelectionError, "component_run_id_mismatch"):
            self.select()


class NamingTests(unittest.TestCase):
    def test_name_parsing(self):
        self.assertEqual(selector.parse_artifact_name(f"{selector.ARTIFACT_PREFIX}12-3"), (12, 3))

    def test_name_parsing_rejects_missing_attempt(self):
        with self.assertRaises(selector.SelectionError):
            selector.parse_artifact_name(f"{selector.ARTIFACT_PREFIX}12")

    def test_job_lookup_requires_exactly_one_matching_job(self):
        self.assertTrue(selector.component_job_succeeded(jobs()))
        self.assertFalse(selector.component_job_succeeded([]))
        self.assertFalse(selector.component_job_succeeded(jobs() + jobs()))
        self.assertFalse(selector.component_job_succeeded(jobs(conclusion="cancelled")))
        self.assertFalse(selector.component_job_succeeded(jobs(status="in_progress")))


if __name__ == "__main__":
    unittest.main()
