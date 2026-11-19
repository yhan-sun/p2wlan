"""Keep the real libc capture contract across the final native exec boundary."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest import mock

import launch_identity
import test_udp_egress as native


ROOT = Path(__file__).resolve().parent


@unittest.skipUnless(sys.platform in ("darwin", "linux") and Path("/usr/bin/python3").is_file(),
                     "requires the Unix system interpreter and native test fixture")
class FinalExecNativeUdpTests(unittest.IsolatedAsyncioTestCase):
    async def test_original_native_capture_through_system_python_final_exec(self):
        # Reuse the original real sendto/sendmsg, mapping, exact counters and
        # oversized-datagram assertions. Only its process launch crosses the
        # same recorder/interpreter boundary as the daemon harness.
        class Fixture(native.UdpEgressTests):
            pass

        Fixture.setUpClass()
        case = Fixture("test_native_sendto_sendmsg_capture_unbound_destinations_and_source_socket")
        prepared = Fixture.root / "native-fixture"
        prepared.mkdir()
        source = launch_identity.source_identity(ROOT.parents[1])
        launch_identity.prepare_artifacts(prepared,
            {"daemon": Fixture.sender, "udp-shim": Fixture.library}, source)
        record = Fixture.root / "native-final-exec.json"
        original_spawn = asyncio.create_subprocess_exec
        children = []

        async def through_recorder(*arguments, **kwargs):
            self.assertEqual(Path(arguments[0]), Fixture.sender)
            requested = kwargs["env"]
            command = [sys.executable, str(ROOT / "udp_egress.py"), "--recorder",
                       "--library", str(Fixture.library),
                       "--port", requested["P2WLAN_NAT_SIM_GATEWAY_PORT"],
                       "--stats", requested["P2WLAN_NAT_SIM_EGRESS_STATS"], "--",
                       "/usr/bin/python3", str(ROOT / "launch_identity.py"), "exec",
                       "--artifact-set", str(prepared / "artifact-set.json"),
                       "--component", "daemon", "--role", "node-a", "--record", str(record)]
            for key in ("DYLD_INSERT_LIBRARIES", "P2WLAN_NAT_SIM_GATEWAY_PORT",
                        "P2WLAN_NAT_SIM_EGRESS_STATS"):
                command.extend(["--env-key", key])
            kwargs["env"] = native.udp_egress.recorder_environment(requested)
            kwargs["env"]["P2WLAN_TEST_CAPTURE_CHILD_FIRST"] = "1"
            child = await original_spawn(*command, "--", *arguments[1:], **kwargs)
            children.append(child)
            return child

        try:
            await case.asyncSetUp()
            try:
                with mock.patch.object(asyncio, "create_subprocess_exec", side_effect=through_recorder):
                    await case.test_native_sendto_sendmsg_capture_unbound_destinations_and_source_socket()
            finally:
                await case.asyncTearDown()
            observed = json.loads(record.read_text())
            launch_identity.validate_record(observed, source)
            self.assertEqual(len(children), 1)
            self.assertEqual(observed["pid"], children[0].pid)
            self.assertEqual(children[0].returncode, 0)
        finally:
            try:
                evidence = os.environ.get("P2WLAN_NAT_SIM_NATIVE_EVIDENCE_DIR")
                if evidence:
                    output = Path(evidence)
                    output.mkdir(parents=True, exist_ok=False)
                    artifacts = {}
                    for name, path in {
                        "actual-native-sender": Fixture.sender,
                        "actual-udp-shim": Fixture.library,
                        "native-sender.c": Fixture.root / "sender.c",
                        "native-final-exec.json": record,
                        "artifact-set.json": prepared / "artifact-set.json",
                        "nat-trace.jsonl": case.trace_path,
                    }.items():
                        if path.is_file():
                            self.assertLessEqual(path.stat().st_size, 16 * 1024 * 1024)
                            shutil.copyfile(path, output / name)
                            artifacts[name] = hashlib.sha256(path.read_bytes()).hexdigest()
                    (output / "native-artifacts.json").write_text(json.dumps({
                        "source": source, "artifacts_sha256": artifacts,
                        "scope": "original C fixture and shim; not a Rust daemon binary",
                    }, indent=2))
            finally:
                Fixture.tearDownClass()


if __name__ == "__main__":
    unittest.main()
