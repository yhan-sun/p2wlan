#!/usr/bin/env python3
"""Fixture coverage for the network-isolation proof helper.

Each known failure sample (third-party active node, registration not yet
converged, control-plane HTTP error, delete failure, cleanup leak) must be
distinguished by a distinct reason so the harness never collapses an
infrastructure problem into a product verdict.
"""

from __future__ import print_function

import importlib.util
import json
import pathlib
import threading
import subprocess
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SPEC = importlib.util.spec_from_file_location(
    "network_isolation", str(pathlib.Path(__file__).with_name("network-isolation.py"))
)
ISO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ISO)


def node(device_id, online=False, last_seen=0):
    return {"id": device_id, "device_name": "test", "online": online, "last_seen": last_seen}


class FakeControl(BaseHTTPRequestHandler):
    """Scriptable fake for the subset of the control API the helper uses."""

    nodes = []
    delete_results = []
    fail_nodes_until = 0

    def log_message(self, *args):
        pass

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def do_GET(self):
        if self.path.startswith("/api/v1/nodes"):
            self._nodes_response()
            return
        self.send_response(404)
        self.end_headers()

    def do_DELETE(self):
        if not self.path.startswith("/api/v1/devices/"):
            self.send_response(404)
            self.end_headers()
            return
        if not self.delete_results:
            self.send_response(500)
            self.end_headers()
            return
        status, body = self.delete_results.pop(0)
        self.send_response(status)
        self.end_headers()
        if body:
            self.wfile.write(body.encode())

    def _nodes_response(self):
        if FakeControl.fail_nodes_until > 0:
            FakeControl.fail_nodes_until -= 1
            self.send_response(503)
            self.end_headers()
            return
        payload = json.dumps({"nodes": FakeControl.nodes}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class NetworkIsolationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeControl)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = "http://127.0.0.1:%d" % cls.port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        FakeControl.nodes = []
        FakeControl.delete_results = []
        FakeControl.fail_nodes_until = 0

    def test_exactly_two_active_nodes_passes(self):
        FakeControl.nodes = [
            node("mini", True, 100),
            node("air", True, 100),
            node("historical", False, 0),
        ]
        report = ISO.prove_isolation(self.url, "tok", "default", ["mini", "air"], deadline_s=5)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["reason"], "isolated_exactly_two_active_nodes")
        self.assertEqual(report["inert_historical_rows"], 1)

    def test_third_party_active_node_fails_fast(self):
        FakeControl.nodes = [
            node("mini", True, 100),
            node("air", True, 100),
            node("intruder", True, 100),
        ]
        report = ISO.prove_isolation(self.url, "tok", "default", ["mini", "air"], deadline_s=8)
        self.assertFalse(report["ok"])
        self.assertEqual(report["reason"], "third_party_active_node")

    def test_registration_transient_then_converged_passes(self):
        def gradually_activate():
            FakeControl.nodes = [node("mini", True, 100)]
            import time as _time
            _time.sleep(0.4)
            FakeControl.nodes = [node("mini", True, 100), node("air", True, 100)]

        thread = threading.Thread(target=gradually_activate, daemon=True)
        thread.start()
        report = ISO.prove_isolation(self.url, "tok", "default", ["mini", "air"], deadline_s=8)
        thread.join()
        self.assertTrue(report["ok"], report)

    def test_expected_exactly_two_enforced(self):
        report = ISO.prove_isolation(self.url, "tok", "default", ["mini"], deadline_s=3)
        self.assertFalse(report["ok"])
        self.assertEqual(report["reason"], "expected_exactly_two_nodes")

    def test_nodes_list_http_error_fails_with_distinct_reason(self):
        FakeControl.fail_nodes_until = 100
        report = ISO.prove_isolation(self.url, "tok", "default", ["mini", "air"], deadline_s=3)
        self.assertFalse(report["ok"])
        self.assertEqual(report["reason"], "nodes_list_failed")

    def test_wrong_node_never_registers_fails_deadline(self):
        FakeControl.nodes = [node("mini", True, 100)]
        report = ISO.prove_isolation(self.url, "tok", "default", ["mini", "air"], deadline_s=3)
        self.assertFalse(report["ok"])
        self.assertEqual(report["reason"], "active_roster_not_converged")

    def test_delete_success(self):
        FakeControl.delete_results = [(200, '{"success":true}')]
        ok, status, _ = ISO.delete_device(self.url, "tok", "mini")
        self.assertTrue(ok)
        self.assertEqual(status, 200)

    def test_delete_404_is_successful_idempotent_cleanup(self):
        FakeControl.delete_results = [(404, '{"error":"not found"}')]
        ok, status, _ = ISO.delete_device(self.url, "tok", "mini")
        self.assertTrue(ok)
        self.assertEqual(status, 404)

    def test_delete_http_error_fails(self):
        FakeControl.delete_results = [(500, '{"error":"boom"}')]
        ok, status, _ = ISO.delete_device(self.url, "tok", "mini")
        self.assertFalse(ok)
        self.assertEqual(status, 500)

    def test_delete_connection_error_fails(self):
        ok, status, _ = ISO.delete_device("http://127.0.0.1:1", "tok", "mini")
        self.assertFalse(ok)
        self.assertEqual(status, 0)

    def test_prove_cleaned_passes_when_active_roster_empty(self):
        FakeControl.nodes = [node("historical", False, 0)]
        report = ISO.prove_cleaned(self.url, "tok", "default", ["mini", "air"], deadline_s=5)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["reason"], "network_clean_no_active_nodes")

    def test_prove_cleaned_fails_on_leftover_own_device(self):
        FakeControl.nodes = [node("mini", True, 100)]
        report = ISO.prove_cleaned(self.url, "tok", "default", ["mini", "air"], deadline_s=3)
        self.assertFalse(report["ok"])
        self.assertNotEqual(report["reason"], "third_party_active_during_cleanup")

    def test_prove_cleaned_fails_on_third_party_activity(self):
        FakeControl.nodes = [node("intruder", True, 100)]
        report = ISO.prove_cleaned(self.url, "tok", "default", ["mini", "air"], deadline_s=3)
        self.assertFalse(report["ok"])
        self.assertEqual(report["reason"], "third_party_active_during_cleanup")

    def test_scoped_cleanup_allows_unrelated_active_devices(self):
        FakeControl.nodes = [node("intruder", True, 100), node("historical", False, 0)]
        report = ISO.prove_cleaned(
            self.url,
            "tok",
            "default",
            ["mini", "air"],
            deadline_s=5,
            reject_third_party=False,
        )
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["reason"], "deleted_nodes_inactive_third_party_recorded")
        self.assertEqual(report["third_party_active"], ["intruder"])

    def test_cli_prove_exit_code_distinguishes_failure(self):
        FakeControl.nodes = [node("mini", True, 100), node("air", True, 100)]
        good = subprocess.run(
            ["python3", str(pathlib.Path(__file__).with_name("network-isolation.py")),
             "--prove", self.url, "tok", "default", "mini", "air", "--deadline", "5"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(good.returncode, 0, good.stderr)
        FakeControl.nodes = [node("mini", True, 100), node("air", True, 100), node("x", True, 1)]
        bad = subprocess.run(
            ["python3", str(pathlib.Path(__file__).with_name("network-isolation.py")),
             "--prove", self.url, "tok", "default", "mini", "air", "--deadline", "5"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertNotEqual(bad.returncode, 0)
        report = json.loads(bad.stdout)
        self.assertEqual(report["reason"], "third_party_active_node")

    def test_cli_delete_exit_code_distinguishes_failure(self):
        FakeControl.delete_results = [(200, "{}")]
        good = subprocess.run(
            ["python3", str(pathlib.Path(__file__).with_name("network-isolation.py")),
             "--delete", self.url, "tok", "mini"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(good.returncode, 0, good.stderr)
        FakeControl.delete_results = [(500, "{}")]
        bad = subprocess.run(
            ["python3", str(pathlib.Path(__file__).with_name("network-isolation.py")),
             "--delete", self.url, "tok", "mini"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
