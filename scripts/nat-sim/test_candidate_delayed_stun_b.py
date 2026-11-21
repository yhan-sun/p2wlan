#!/usr/bin/env python3
"""Actual CLI delayed STUN-B input contract under the original fixed budgets."""
import hashlib, json, os, re, shlex, stat, sys, tempfile, time, unittest
from pathlib import Path

import test_actual_barrier_outer_callers as base

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def new_file(path, data):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())

def run(source, root):
    source = source.resolve()
    legacy = source / "scripts/nat-sim/test_actual_barrier_outer_callers.py"
    if Path(base.__file__).resolve() != legacy:
        raise AssertionError("delayed_B_wrong_original_fixture_module")
    class DelayedBFixture(base.BarrierOuterCliFixture):
        def prepare(self):
            preparation_end = time.monotonic() + 4
            source_paths = (legacy, base.EXTERNAL_TOOLS.resolve(),
                            Path(__file__).resolve(),
                            Path(__file__).with_name("fixture_candidate_delayed_stun_b_tools.py").resolve())
            if any(not path.is_relative_to(self.source) for path in source_paths):
                raise AssertionError("delayed_B_source_outside_declared_repository")
            self.delayed_source_capture = {
                str(path.relative_to(self.source)): digest(path) for path in source_paths}
            self.delayed_assertions_relative = str(legacy.relative_to(self.source))
            self.delayed_tools_relative = str(base.EXTERNAL_TOOLS.resolve().relative_to(self.source))
            self.delayed_test_relative = str(Path(__file__).resolve().relative_to(self.source))
            self.delayed_adapter_relative = str(source_paths[-1].relative_to(self.source))
            super().prepare()
            self.verify_delayed_source_capture()
            commands = self.root / "fake-path"
            unchanged = {name: digest(commands / name) for name in ("cargo", "go", "curl")}
            adapter = self.root / "fixture-delayed-stun-b-tools.py"
            new_file(adapter, Path(__file__).with_name("fixture_candidate_delayed_stun_b_tools.py").read_bytes())
            launcher = "#!/bin/sh\nexec " + shlex.join([sys.executable, "-S", str(adapter), str(self.root), "python3"]) + ' "$@"\n'
            descriptor = os.open(commands / "python3", os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
                    raise AssertionError("delayed_B_launcher_not_owned_regular_0700")
                if os.write(descriptor, launcher.encode()) != len(launcher.encode()):
                    raise AssertionError("delayed_B_short_launcher_write")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            declared = {"fixture_only": True, "delay_seconds": 0.15,
                        "adapter_sha256": digest(adapter), "python_launcher_sha256": digest(commands / "python3"),
                        "unchanged_tool_sha256": unchanged,
                        "original_assertions_relative_path": self.delayed_assertions_relative,
                        "original_assertions_sha256": self.delayed_source_capture[self.delayed_assertions_relative],
                        "original_tools_relative_path": self.delayed_tools_relative,
                        "original_tools_sha256": self.delayed_source_capture[self.delayed_tools_relative],
                        "test_source_relative_path": self.delayed_test_relative,
                        "test_source_sha256": self.delayed_source_capture[self.delayed_test_relative],
                        "adapter_source_relative_path": self.delayed_adapter_relative,
                        "adapter_source_sha256": self.delayed_source_capture[self.delayed_adapter_relative]}
            new_file(self.root / "delayed-b-input.json", (json.dumps(declared, sort_keys=True) + "\n").encode())
            if any(digest(commands / name) != value for name, value in unchanged.items()):
                raise AssertionError("delayed_B_other_tool_changed")
            if time.monotonic() >= preparation_end:
                raise AssertionError("delayed_B_original_fixed_preparation_window_exhausted")

        def verify_delayed_source_capture(self):
            settings = self.bounded_json(self.root / "fixture-config.json")
            if settings["original_sources"] != self.original_sources:
                raise AssertionError("delayed_B_original_source_map_mismatch")
            for relative, expected in self.delayed_source_capture.items():
                if (self.original_sources.get(relative) != expected
                        or digest(self.source / relative) != expected
                        or digest(self.repository / relative) != expected):
                    raise AssertionError("delayed_B_captured_source_changed")
            original_tools_sha = self.delayed_source_capture[self.delayed_tools_relative]
            if (settings["external_tools_sha256"] != original_tools_sha
                    or digest(self.root / "fixture-external-tools.py") != original_tools_sha):
                raise AssertionError("delayed_B_original_tool_transport_changed")

        def execute(self):
            result = super().execute()
            self.verify_delayed_source_capture()
            return result
    fixture = DelayedBFixture(root, source, "direct-barrier-unhealthy", 1)
    checks = base.ActualBarrierOuterCallerTests()  # Reuse original methods; never call its fixture/test methods.
    try:
        fixture.execute()
        checks.prerequisites(fixture)
        checks.assert_finalization(fixture, "B01_DELAYED_B_ORIGINAL_FIVE_OWNER_FINALIZATION")
        events = [row for row in fixture.events if row["tool"] == "delayed_stun_flush"]
        checks.assertEqual([row["side"] for row in events], ["a", "b"])
        checks.assertTrue(all(row["pid"] == fixture.child_records["nat"]["pid"] for row in events))
        gap = events[1]["monotonic_ns"] - events[0]["monotonic_ns"]
        checks.assertGreaterEqual(gap, 100_000_000)
        nat_ready = next(row for row in fixture.events if row["tool"] == "child_ready" and row["role"] == "nat")
        health = [row for row in fixture.events if row["tool"] == "curl" and row["endpoint"] == "/health" and row.get("exit_code") != 7]
        checks.assertLess(events[1]["monotonic_ns"], nat_ready["monotonic_ns"])
        checks.assertTrue(health and all(row["monotonic_ns"] > nat_ready["monotonic_ns"] for row in health))
        nodes = [row for row in fixture.events if row["tool"] == "child_ready" and row["role"] in {"node-a", "node-b"}]
        checks.assertTrue(len(nodes) == 2 and all(row["monotonic_ns"] > health[-1]["monotonic_ns"] for row in nodes))
        commands = re.findall(r"^\++ B01_CLI pid=" + str(fixture.process.pid) + r" sub=0 line=[0-9]+: (.*)$", fixture.stderr, re.MULTILINE)
        consumed = commands.index("STUN_B=127.0.0.1:31002")
        loop = [value for value in commands[:consumed] if value.startswith(("grep -q STUN_A= ", "grep -q STUN_B= ")) or value in {"deadline_pause 0.05", "break"}]
        polls = [i for i, value in enumerate(loop) if value.startswith("grep -q STUN_B= ")]
        missed = [i for i in polls if loop[i + 1] == "deadline_pause 0.05"]
        checks.assertTrue(missed, "B01 fixture coverage failure: fixed delayed input did not overlap actual B poll")
        accepted = next(i for i in polls if loop[i + 1] == "break")
        first_health = next(i for i, value in enumerate(commands) if value.startswith("curl ") and "/health" in value)
        checks.assertTrue(min(missed) < accepted and consumed < first_health)
        checks.assertTrue(all(loop[i - 1].startswith("grep -q STUN_A= ") for i in polls))
        for role, variable in (("node-a", "NODE_A_PID"), ("node-b", "NODE_B_PID")):
            checks.assertGreater(commands.index(variable + "=" + str(fixture.child_records[role]["pid"])), first_health)
        checks.assertNotIn("reason_code=test_harness_startup_failure", fixture.stderr)
    finally:
        fixture.close()
    sentinel = fixture.bounded_json(fixture.root / "sentinel-cleanup.json")
    checks.assertTrue(sentinel["wait_completed"])
    checks.assertEqual(sentinel["wait_status"], 0)
    checks.assertFalse(fixture.rescued)
    new_file(fixture.root / "delayed-b-positive-result.json", (json.dumps({
        "fixture_only": True, "gap_ns": gap, "missed_b_polls": len(missed),
        "canonical_reason": "critical_tasks_unhealthy", "nat_acceptance": False,
        "delayed_input_sha256": digest(fixture.root / "delayed-b-input.json"),
        "adapter_sha256": digest(fixture.root / "fixture-delayed-stun-b-tools.py"),
        "python_launcher_sha256": digest(fixture.root / "fake-path/python3"),
        "captured_source_sha256": fixture.delayed_source_capture,
        "original_sources": fixture.original_sources}, sort_keys=True) + "\n").encode())

class CandidateDelayedStunBTests(unittest.TestCase):
    def test_actual_delayed_stun_b_waits_for_original_pair_before_nodes(self):
        source = base.source_repository()
        evidence = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if evidence:
            directory = Path(evidence).resolve() / self._testMethodName
        else:
            temporary = tempfile.TemporaryDirectory(prefix="p2wlan-delayed-stun-b-cli-")
            self.addCleanup(temporary.cleanup)
            directory = Path(temporary.name) / "exclusive-case"
        run(source, directory)


if __name__ == "__main__":
    unittest.main()
