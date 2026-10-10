#!/usr/bin/env python3
"""Unexecuted fixture API observers around the real completed collector.

Production main/run_bounded/supervise/read/prepare/replace are called as-is.
Two fixed-fence controls use native FIFO handshakes, real command/leader waits
and unchanged three-second protocol/two-second teardown. No NAT/TUN claim.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import select
import time
import unittest
from unittest.mock import patch

import test_round_cleanup as legacy
import test_round_finalization as common
import test_round_finalization_regressions as semantic


COMMANDS = r"""
    PROMOTION_READ|PROMOTION_PREPARED)
      _round_context
      _round_fixed_windows
      candidate=$(($(_round_now) + 600))
      if (( candidate < _ROUND_CAPTURE_END_MS )); then _ROUND_CAPTURE_END_MS=$candidate; fi
      if [[ "$command" == PROMOTION_READ ]]; then _FIXTURE_PROMOTION_MODE=read-return; else _FIXTURE_PROMOTION_MODE=prepared-mapping; fi
      if round_run_collector collector "$fixture_python" "$BASE_DIR/fixture-completed-collector.py" "$ROUND_DIR"; then rc=0; else rc=$?; fi
      _FIXTURE_PROMOTION_MODE=idle
      printf 'BOUNDARY_COLLECTOR:%s:%s:%s\n' "$rc" "$_ROUND_CAPTURE_END_MS" "$_ROUND_RESOURCE_END_MS" ;;
"""

# Fixture dispatcher only. The real shell round_run_collector still chooses
# its existing arguments and absolute fences; the wrapper calls the real main.
DISPATCH = r"""
_FIXTURE_PROMOTION_MODE=idle
_round_tool() {
  if [[ "${1:-}" == run && "${_FIXTURE_PROMOTION_MODE:-idle}" != idle ]]; then
    "$fixture_python" "$BASE_DIR/fixture-promotion-observer.py" \
      "$ROOT_DIR/scripts/nat-sim/round_finalization.py" "$_FIXTURE_PROMOTION_MODE" "$ROUND_DIR" "$@"
  else
    "$fixture_python" "$ROOT_DIR/scripts/nat-sim/round_finalization.py" "$@"
  fi
}
"""

COLLECTOR = r"""
import json
import os
from pathlib import Path
import sys
root = Path(sys.argv[1])
def write(name, value):
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
write("nat-evidence.json", {
    "schema_version": 1, "executed": True, "result": "pass",
    "decision": {"result": "pass", "reason_code": "fixture_early_collector"},
    "nat_terminal": None,
})
write("mapping-evidence.json", {"schema_version": 1, "executed": True, "fixture_mapping_value": 41})
write("fixture-native-collector.json", {"pid": os.getpid(), "exit_intent": 0})
raise SystemExit(0)
"""

# Only observation/gating adapters are defined here. No production algorithm,
# receipt construction or deadline decision is reimplemented in this wrapper.
WRAPPER = r"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

module_path, mode, round_dir = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
production_argv = sys.argv[4:]
if production_argv[:1] != ["run"] or mode not in {"read-return", "prepared-mapping"}:
    raise AssertionError("fixture observer entrance mismatch")
def argument(name):
    if production_argv.count(name) != 1:
        raise AssertionError("fixture requires one original declared argument")
    return production_argv[production_argv.index(name) + 1]
capture_end = int(argument("--deadline-ms"))
grace_end = int(argument("--grace-end-ms"))
if Path(argument("--round-dir")) != round_dir or argument("--label") != "collector":
    raise AssertionError("fixture observer directory or label mismatch")
spec = importlib.util.spec_from_file_location("fixture_promotion_original_module", module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
real_supervise = module.supervise
real_read = module.bounded_bytes
real_fsync = module.os.fsync
real_replace = module.os.replace
snapshot = round_dir / ".bounded-collector"
release_fifo = round_dir / "fixture-promotion-release.fifo"
observed_worker = None
parked = False
native_commit_count = 0

def write(name, value):
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(data) > 8192:
        raise AssertionError("fixture observation exceeds fixed cap")
    fd = os.open(round_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)

def observed_supervise(*args, **kwargs):
    global observed_worker
    result = real_supervise(*args, **kwargs)
    observed_worker = dict(result)
    write("fixture-observed-supervise.json", observed_worker)
    return result

def park(position, extra):
    global parked
    if parked or observed_worker is None:
        raise AssertionError("fixture park must follow one actual supervision")
    if (observed_worker.get("result") != "completed" or observed_worker.get("wait_completed") is not True
            or observed_worker.get("command_wait_completed") is not True or observed_worker.get("command_wait_status") != 0
            or observed_worker.get("owned_group_shutdown_requested_before_wait") is not True):
        raise AssertionError("fixture requires real completed leader/command waits before parking")
    parked = True
    fd = os.open(release_fifo, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        write("fixture-promotion-boundary.json", {
            "position": position, "mode": mode, "wrapper_pid": os.getpid(),
            "capture_end_ms": capture_end, "resource_end_ms": grace_end,
            "parked_at_ms": module.now_ms(), "extra": extra,
        })
        print("PROMOTION_PARKED:" + mode + ":" + str(capture_end) + ":" + str(grace_end), flush=True)
        if os.read(fd, 1) != b"R":
            raise AssertionError("fixture promotion release token mismatch")
    finally:
        os.close(fd)

def observed_read(path, cap):
    data = real_read(path, cap)
    if mode == "read-return" and Path(path) == snapshot / "nat-evidence.json":
        park("bounded_read_return", {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return data

def observed_fsync(fd):
    result = real_fsync(fd)
    prepared = round_dir / "mapping-evidence.json.writing"
    if mode == "prepared-mapping" and prepared.is_file():
        actual, expected = os.fstat(fd), prepared.stat()
        if (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino):
            data = real_read(prepared, module.MAX_RECEIPT_BYTES)
            park("prepared_mapping_after_native_fsync", {
                "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                "dev": actual.st_dev, "ino": actual.st_ino,
            })
    return result

def observed_replace(source, destination):
    global native_commit_count
    result = real_replace(source, destination)
    destination = Path(destination)
    if destination.parent == round_dir and destination.name in {"nat-evidence.json", "mapping-evidence.json", "continuity-evidence.json"}:
        if native_commit_count >= 3:
            raise AssertionError("fixture canonical commit observation cap exceeded")
        data = real_read(destination, module.MAX_RECEIPT_BYTES)
        stat = destination.stat()
        write("fixture-native-commit-" + str(native_commit_count) + ".json", {
            "name": destination.name, "sha256": hashlib.sha256(data).hexdigest(),
            "committed_at_ms": module.now_ms(), "dev": stat.st_dev, "ino": stat.st_ino,
        })
        native_commit_count += 1
    return result

sys.argv = [str(module_path), *production_argv]
with patch.object(module, "supervise", observed_supervise), patch.object(module, "bounded_bytes", observed_read), \
     patch.object(module.os, "fsync", observed_fsync), patch.object(module.os, "replace", observed_replace):
    result = module.main()
raise SystemExit(result)
"""


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise AssertionError("promotion fixture extension anchor changed")
    return text.replace(before, after, 1)


def controller():
    text = common.controller()
    text = replace_once(text, "    CAPTURE)\n", COMMANDS + "    CAPTURE)\n")
    anchor = 'source "$ROOT_DIR/scripts/nat-sim/round_cleanup.sh"\n'
    return replace_once(text, anchor, anchor + DISPATCH)


class RoundPromotionBoundaryControls(unittest.TestCase):
    def fixture(self):
        temporary = legacy.tempfile.TemporaryDirectory(prefix="p2wlan-promotion-boundary-")
        self.addCleanup(temporary.cleanup)
        with patch.object(legacy, "CONTROLLER", controller()):
            fixture = legacy.OwnedCleanupProcesses(Path(temporary.name))
        self.addCleanup(fixture.close)
        for name, source in (("fixture-completed-collector.py", COLLECTOR), ("fixture-promotion-observer.py", WRAPPER)):
            fd = os.open(fixture.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as output:
                output.write(source)
        os.mkfifo(fixture.round_dir / "fixture-promotion-release.fifo", 0o600)
        return fixture

    @staticmethod
    def read(fixture, name):
        return common.RoundFinalizationControls.read(fixture, name)

    def gone(self, pid):
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def bytes_if_present(self, path):
        if not path.exists():
            return None
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        return path.read_bytes()

    def run_boundary(self, mode):
        fixture = self.fixture()
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        fixture.send("PROMOTION_READ" if mode == "read-return" else "PROMOTION_PREPARED")
        response = fixture.receive().split(":")
        self.assertEqual(response[:2], ["PROMOTION_PARKED", mode])
        self.assertEqual(len(response), 4)
        capture_end, resource_end = map(int, response[2:])
        marker = self.read(fixture, "fixture-promotion-boundary.json")
        worker = self.read(fixture, "fixture-observed-supervise.json")
        self.assertEqual((marker["mode"], marker["capture_end_ms"], marker["resource_end_ms"]), (mode, capture_end, resource_end))
        self.assertLess(marker["parked_at_ms"], capture_end)
        self.assertLess(capture_end, resource_end)
        self.assertEqual(worker["result"], "completed")
        self.assertTrue(worker["started"])
        self.assertTrue(worker["wait_completed"])
        self.assertTrue(worker["command_wait_completed"])
        self.assertEqual(worker["command_wait_status"], 0)
        self.assertTrue(worker["owned_group_shutdown_requested_before_wait"])
        self.assertFalse(worker["forced_termination"])
        self.gone(worker["pid"])
        native = json.loads((fixture.round_dir / ".bounded-collector/fixture-native-collector.json").read_bytes())
        self.assertEqual(native["exit_intent"], 0)
        self.gone(native["pid"])
        staged_nat = (fixture.round_dir / ".bounded-collector/nat-evidence.json").read_bytes()
        staged_mapping = (fixture.round_dir / ".bounded-collector/mapping-evidence.json").read_bytes()
        self.assertIs(json.loads(staged_nat)["executed"], True)
        self.assertEqual(json.loads(staged_mapping)["fixture_mapping_value"], 41)
        prepared_path = fixture.round_dir / "mapping-evidence.json.writing"
        prepared_at_park = self.bytes_if_present(prepared_path)
        canonical_at_park = self.bytes_if_present(fixture.round_dir / "nat-evidence.json")
        self.assertFalse((fixture.round_dir / "mapping-evidence.json").exists())
        # Wait only to the already-declared absolute fence. No fresh window,
        # probability sleep, fake clock or increase to capture/resource is used.
        self.assertLess(capture_end / 1000, fixture.protocol_end)
        remaining = (capture_end * 1_000_000 - time.monotonic_ns()) / 1_000_000_000
        self.assertGreater(remaining, 0, "fixture must reach its controlled park before the original fence")
        select.select([], [], [], remaining)
        self.assertGreaterEqual(time.monotonic_ns() // 1_000_000, capture_end)
        fd = os.open(fixture.round_dir / "fixture-promotion-release.fifo", os.O_WRONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        try:
            self.assertEqual(os.write(fd, b"R"), 1)
        finally:
            os.close(fd)
        response = fixture.receive().split(":")
        self.assertEqual(response, ["BOUNDARY_COLLECTOR", "1", str(capture_end), str(resource_end)])
        self.gone(marker["wrapper_pid"])
        receipt = self.read(fixture, ".collector-result.json")
        self.assertEqual((receipt["result"], receipt["reason_code"]), ("unknown", "deadline_exhausted"))
        for name in ("pid", "wait_completed", "wait_status", "command_wait_completed", "command_wait_status", "owned_group_shutdown_requested_before_wait", "forced_termination", "resource_grace_deadline_monotonic_ms"):
            self.assertEqual(receipt[name], worker[name])
        canonical_after_run = self.bytes_if_present(fixture.round_dir / "nat-evidence.json")
        mapping_after_run = self.bytes_if_present(fixture.round_dir / "mapping-evidence.json")
        temporaries_after_run = {name: (fixture.round_dir / name).exists() for name in ("nat-evidence.json.writing", "mapping-evidence.json.writing", "continuity-evidence.json.writing")}
        commits = [self.read(fixture, "fixture-native-commit-" + str(index) + ".json")
                   for index in range(3) if (fixture.round_dir / ("fixture-native-commit-" + str(index) + ".json")).exists()]
        self.assertEqual(fixture.finish()[-1], 0)
        value, _ = semantic.RoundFinalizationRegressions().failed_and_reaped(
            fixture, rejection="raw_evidence_missing:node-a.status.json,node-b.status.json")
        self.assertLessEqual(value["capture_deadline_monotonic_ms"], capture_end)
        self.assertFalse((fixture.round_dir / "fixture-final-fetch.calls").exists())
        self.assertFalse(value["statuses"]["a"]["worker"]["started"])
        self.assertFalse(value["statuses"]["b"]["worker"]["started"])
        self.assertEqual(value["collector"], receipt)
        final_nat = self.read(fixture, "nat-evidence.json")
        self.assertEqual(final_nat["result"], "fail")
        self.assertIs(final_nat["executed"], False)
        self.assertEqual(final_nat["decision"]["reason_code"], "harness:baseline_status_not_available")
        return {
            "marker": marker, "receipt": receipt, "commits": commits,
            "staged_nat": staged_nat, "staged_mapping": staged_mapping,
            "prepared_at_park": prepared_at_park, "canonical_at_park": canonical_at_park,
            "canonical_after_run": canonical_after_run, "mapping_after_run": mapping_after_run,
            "temporaries_after_run": temporaries_after_run,
        }

    def test_completed_collector_read_crossing_cutoff_stays_unknown_without_promotion(self):
        state = self.run_boundary("read-return")
        self.assertEqual(state["marker"]["position"], "bounded_read_return")
        self.assertEqual(state["marker"]["extra"], {
            "bytes": len(state["staged_nat"]), "sha256": hashlib.sha256(state["staged_nat"]).hexdigest()})
        self.assertIsNone(state["canonical_at_park"])
        self.assertIsNone(state["prepared_at_park"])
        self.assertIsNone(state["canonical_after_run"])
        self.assertIsNone(state["mapping_after_run"])
        self.assertEqual(state["commits"], [])
        self.assertEqual(state["receipt"]["outputs"], [])
        self.assertFalse(any(state["temporaries_after_run"].values()))

    def test_prepared_second_output_cutoff_retains_only_actual_first_commit(self):
        state = self.run_boundary("prepared-mapping")
        self.assertEqual(state["marker"]["position"], "prepared_mapping_after_native_fsync")
        self.assertIsNotNone(state["prepared_at_park"])
        self.assertEqual(json.loads(state["prepared_at_park"]), json.loads(state["staged_mapping"]))
        self.assertEqual(state["marker"]["extra"]["bytes"], len(state["prepared_at_park"]))
        self.assertEqual(state["marker"]["extra"]["sha256"], hashlib.sha256(state["prepared_at_park"]).hexdigest())
        self.assertEqual(json.loads(state["canonical_at_park"]), json.loads(state["staged_nat"]))
        self.assertEqual(state["canonical_after_run"], state["canonical_at_park"])
        self.assertIsNone(state["mapping_after_run"])
        self.assertFalse(any(state["temporaries_after_run"].values()))
        self.assertEqual(len(state["commits"]), 1)
        commit = state["commits"][0]
        expected_digest = hashlib.sha256(state["canonical_at_park"]).hexdigest()
        self.assertEqual((commit["name"], commit["sha256"]), ("nat-evidence.json", expected_digest))
        self.assertLess(commit["committed_at_ms"], state["marker"]["capture_end_ms"])
        self.assertEqual(state["receipt"]["outputs"], [{"name": "nat-evidence.json", "captured_sha256": expected_digest}])


if __name__ == "__main__":
    unittest.main()
