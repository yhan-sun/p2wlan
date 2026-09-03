#!/usr/bin/env python3
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("aggregate_evidence.py")
SPEC = importlib.util.spec_from_file_location("aggregate_evidence", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


SOURCE_SHA = "a" * 40
WORKFLOW_SHA = "b" * 40


def capability(name, status="verified", **extra):
    return {"name": name, "status": status, **extra}


def cycle(number, entrypoint="diagnostics", mode="production", **extra):
    value = {
        "cycle": number,
        "entrypoint": entrypoint,
        "mode": mode,
        "start_succeeded": True,
        "graceful_stop": True,
        "forced_termination": False,
        "process_exited": True,
        "process_exit_code": 0,
        "children_gone": True,
        "diagnostics_port_released": True,
        "auth_token_removed": True,
        "wintun_stale": False,
        "wintun_observed": True if mode == "production" else False,
        "real_wintun": True if mode == "production" else False,
        "daemon_processes_clean": True,
    }
    value.update(extra)
    return value


def component(name, status="verified", source=SOURCE_SHA, workflow=WORKFLOW_SHA):
    return {
        "name": name,
        "schema_version": 2,
        "repository": MODULE.REPOSITORY,
        "source_head_sha": source,
        "workflow_sha": workflow,
        "runner_os": "windows-latest",
        "status": status,
        "detail": "component evidence",
    }


def handler_mapping():
    return {
        "status": "verified",
        "live_system_delivery": "deferred",
        "live_system_delivery_detail": "host logoff/shutdown is deferred on GitHub-hosted runners",
        "console": MODULE.EXPECTED_CONSOLE_MAPPING,
        "service": MODULE.EXPECTED_SERVICE_MAPPING,
        "idempotent_first_request_wins": True,
        "no_duplicate_frees": True,
        "coordinator_entered": True,
        "callback_non_blocking": True,
        "callback_elapsed_ms": 1,
        "bounded_deadline": True,
        "shutdown_deadline_ms": 10000,
        "force_kill": False,
        "coordinator": "wait_for_windows_lifecycle_signal -> run_daemon_inner",
    }


def valid_document():
    production_cycles = [
        cycle(
            i,
            entrypoint=(
                "cli"
                if i % 3 == 1
                else "ctrl_c"
                if i % 3 == 2
                else "diagnostics"
            ),
        )
        for i in range(1, 51)
    ]
    ui_cycles = [cycle(i, entrypoint="ui", mode="ui") for i in range(101, 109)]
    tray_cycles = [
        {
            "cycle": i,
            "status": "verified",
            "process_exited": True,
            "exit_code": 0,
            "daemon_processes_clean": True,
            "forced_termination": False,
        }
        for i in range(1, 21)
    ]
    return {
        "schema_version": 2,
        "repository": MODULE.REPOSITORY,
        "source_head_sha": SOURCE_SHA,
        "workflow_sha": WORKFLOW_SHA,
        "runner_os": "windows-latest",
        "components": [
            component("production_harness"),
            component("flutter_ui"),
            component("handler_mapping"),
        ],
        "handler_mapping": handler_mapping(),
        "capabilities": [
            capability(name) for name in MODULE.REQUIRED_CAPABILITIES
        ],
        "cycles": production_cycles + ui_cycles,
        "service_controls": [
            {
                "control": "stop",
                "status": "verified",
                "process_gone": True,
                "wintun_observed": True,
                "wintun_stale": False,
            },
            {
                "control": "preshutdown",
                "status": "verified",
                "process_gone": True,
                "wintun_observed": True,
                "wintun_stale": False,
            },
        ],
        "flutter_tray": {
            "attempted_cycles": 20,
            "successful_cycles": 20,
            "first_failure_cycle": None,
            "process_exited": True,
            "exit_code": 0,
            "daemon_processes_clean": True,
            "forced_termination": False,
            "dump_paths": [],
            "cycles": tray_cycles,
        },
        "wer": {"event_ids_checked": [1000, 1001], "events": []},
    }


class AggregateEvidenceTests(unittest.TestCase):
    def test_accepts_fifty_graceful_production_cycles_but_preserves_deferred_delivery(self):
        report = MODULE.validate(valid_document())
        self.assertEqual(report["overall"], "deferred")
        self.assertEqual(report["production_cycles"], 50)
        self.assertEqual(report["error_count"], 0)
        self.assertIn("live_system_delivery", report["deferred_capabilities"])

    def test_rejects_forceful_termination(self):
        document = valid_document()
        document["cycles"][7]["forced_termination"] = True
        report = MODULE.validate(document)
        self.assertEqual(report["overall"], "failed")
        self.assertTrue(any("forceful termination" in error for error in report["errors"]))

    def test_rejects_real_cycle_without_observed_wintun(self):
        document = valid_document()
        document["cycles"][0]["wintun_observed"] = False
        report = MODULE.validate(document)
        self.assertEqual(report["overall"], "failed")
        self.assertTrue(
            any("Wintun adapter was not observed" in error for error in report["errors"])
        )

    def test_deferred_capability_is_not_verified(self):
        document = valid_document()
        document["capabilities"] = [
            capability(
                name,
                status="deferred" if name == "wintun_ownership" else "verified",
            )
            for name in MODULE.REQUIRED_CAPABILITIES
        ]
        report = MODULE.validate(document)
        self.assertEqual(report["overall"], "deferred")
        self.assertIn("wintun_ownership", report["deferred_capabilities"])

    def test_missing_capability_fails_closed(self):
        document = valid_document()
        document["capabilities"] = document["capabilities"][1:]
        report = MODULE.validate(document)
        self.assertEqual(report["overall"], "failed")
        self.assertTrue(
            any(
                "missing capability production_start_stop" in error
                for error in report["errors"]
            )
        )

    def test_rejects_crash_events_even_when_cycles_are_clean(self):
        document = valid_document()
        document["wer"]["events"] = [{"id": 1000, "message": "BEX64"}]
        report = MODULE.validate(document)
        self.assertEqual(report["overall"], "failed")
        self.assertTrue(any("crash/BEX" in error for error in report["errors"]))

    def test_deferred_does_not_hide_a_hard_cycle_error(self):
        document = valid_document()
        document["capabilities"] = [
            capability(
                name,
                status="deferred" if name == "wintun_ownership" else "verified",
            )
            for name in MODULE.REQUIRED_CAPABILITIES
        ]
        document["cycles"][0]["process_exited"] = False
        report = MODULE.validate(document)
        self.assertEqual(report["overall"], "failed")

    def test_source_head_mismatch_is_rejected(self):
        document = valid_document()
        document["source_head_sha"] = "c" * 40
        with self.assertRaises(MODULE.EvidenceError):
            MODULE.validate(
                document,
                expected_source_head_sha=SOURCE_SHA,
                expected_workflow_sha=WORKFLOW_SHA,
            )

    def test_workflow_sha_mismatch_is_rejected(self):
        document = valid_document()
        document["workflow_sha"] = "d" * 40
        with self.assertRaises(MODULE.EvidenceError):
            MODULE.validate(
                document,
                expected_source_head_sha=SOURCE_SHA,
                expected_workflow_sha=WORKFLOW_SHA,
            )

    def test_merge_sha_cannot_pretend_to_be_source_head(self):
        document = valid_document()
        document["source_head_sha"] = WORKFLOW_SHA
        with self.assertRaises(MODULE.EvidenceError):
            MODULE.validate(
                document,
                expected_source_head_sha=SOURCE_SHA,
                expected_workflow_sha=WORKFLOW_SHA,
            )

    def test_missing_sha_is_rejected(self):
        document = valid_document()
        document.pop("source_head_sha")
        with self.assertRaises(MODULE.EvidenceError):
            MODULE.validate(document)

    def test_valid_dual_sha_identity_is_preserved(self):
        report = MODULE.validate(
            valid_document(),
            expected_source_head_sha=SOURCE_SHA,
            expected_workflow_sha=WORKFLOW_SHA,
        )
        self.assertEqual(report["source_head_sha"], SOURCE_SHA)
        self.assertEqual(report["workflow_sha"], WORKFLOW_SHA)
        self.assertEqual(report["overall"], "deferred")

    def test_clean_deferred_document_is_a_successful_cli_result(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "evidence.json"
            output_path = Path(directory) / "aggregate.json"
            input_path.write_text(
                json.dumps(valid_document()), encoding="utf-8"
            )
            with mock.patch.dict(
                os.environ,
                {
                    "P2WLAN_EXACT_HEAD": SOURCE_SHA,
                    "P2WLAN_WORKFLOW_SHA": WORKFLOW_SHA,
                },
            ):
                self.assertEqual(
                    MODULE.main(
                        [
                            "--input",
                            str(input_path),
                            "--output",
                            str(output_path),
                        ]
                    ),
                    0,
                )
            self.assertEqual(
                json.loads(output_path.read_text(encoding="utf-8"))["overall"],
                "deferred",
            )

    def test_component_identity_must_match_top_level_identity(self):
        document = valid_document()
        document["components"][0]["workflow_sha"] = "e" * 40
        with self.assertRaises(MODULE.EvidenceError):
            MODULE.validate(document)


if __name__ == "__main__":
    unittest.main()
