#!/usr/bin/env python3
import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("aggregate_evidence.py")
SPEC = importlib.util.spec_from_file_location("aggregate_evidence", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


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


def valid_document():
    names = MODULE.REQUIRED_CAPABILITIES
    cycles = [cycle(i, entrypoint=("cli" if i % 4 == 1 else "ui" if i % 4 == 2 else "ctrl_c" if i % 4 == 3 else "diagnostics")) for i in range(50)]
    return {
        "schema_version": 1,
        "head_sha": "a" * 40,
        "runner_os": "windows-latest",
        "capabilities": [capability(name) for name in names],
        "cycles": cycles,
        "service_controls": [
            {"control": "stop", "status": "verified", "process_gone": True, "wintun_observed": True, "wintun_stale": False},
            {"control": "preshutdown", "status": "verified", "process_gone": True, "wintun_observed": True, "wintun_stale": False},
        ],
        "flutter_tray": {
            "process_exited": True,
            "exit_code": 0,
            "daemon_processes_clean": True,
            "forced_termination": False,
        },
        "wer": {"event_ids_checked": [1000, 1001], "events": []},
    }


class AggregateEvidenceTests(unittest.TestCase):
    def test_accepts_fifty_graceful_production_cycles(self):
        report = MODULE.validate(valid_document())
        self.assertEqual(report["overall"], "verified")
        self.assertEqual(report["production_cycles"], 50)
        self.assertEqual(report["error_count"], 0)

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
        self.assertTrue(any("Wintun adapter was not observed" in error for error in report["errors"]))

    def test_deferred_capability_is_not_verified(self):
        document = valid_document()
        document["capabilities"] = [
            capability(name, status="deferred" if name == "wintun_ownership" else "verified")
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
        self.assertTrue(any("missing capability production_start_stop" in error for error in report["errors"]))

    def test_rejects_crash_events_even_when_cycles_are_clean(self):
        document = valid_document()
        document["wer"]["events"] = [{"id": 1000, "message": "BEX64"}]
        report = MODULE.validate(document)
        self.assertEqual(report["overall"], "failed")
        self.assertTrue(any("crash/BEX" in error for error in report["errors"]))

    def test_deferred_does_not_hide_a_hard_cycle_error(self):
        document = valid_document()
        document["capabilities"] = [
            capability(name, status="deferred" if name == "wintun_ownership" else "verified")
            for name in MODULE.REQUIRED_CAPABILITIES
        ]
        document["cycles"][0]["process_exited"] = False
        report = MODULE.validate(document)
        self.assertEqual(report["overall"], "failed")


if __name__ == "__main__":
    unittest.main()
