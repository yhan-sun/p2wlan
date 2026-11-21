#!/usr/bin/env python3
"""Endpoint attribution candidate: actual CLI endpoint attribution only, not recovery ACK proof.

Three independent controls retain the existing prepare4/CLI24/teardown2,
ROUND30/WORK15/Overlay12/resource1000. The controlled input join consumes
those fixed endpoints; it is not a transparent observer or a renewed window.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import tempfile
import time
import unittest
import test_actual_restart_failover_controls as original
from fixture_http_owner_assertions import assert_http_owner_union

HERE = Path(__file__).resolve().parent
TOOL = HERE / "fixture_candidate_failover_endpoint_tools.py"
PREFIX = "B01_PARTIAL_ENDPOINT_PREREQUISITE"
TARGET = "B01_FAILOVER_BUSINESS_ENDPOINT_MUST_MATCH_REPLACEMENT"
OBSERVER = r'''
_b01_endpoint_input_join() {
  set +x
  local incoming="$1" command="$2" original_trace="$3"
  if [[ "$0" == __CLI__ && "$command" == 're_confirmed=0' && "$BASH_SUBSHELL" == 0 ]]; then
    local root=__ROOT__ gate_end=$((SECONDS + 1))
    printf '%s\n' "$$" > "$root/endpoint-fault-joined.ready.tmp"
    /bin/mv "$root/endpoint-fault-joined.ready.tmp" "$root/endpoint-fault-joined.ready"
    while [[ ! -f "$root/artifacts/round-1/node-a.fixture-failover-flushed.json" || ! -f "$root/artifacts/round-1/node-b.fixture-failover-flushed.json" ]]; do
      if (( SECONDS >= gate_end || SECONDS >= WORK_DEADLINE || SECONDS >= OVERLAY_DEADLINE )); then
        printf '%s\n' 'input join exhausted' > "$root/endpoint-observer-prerequisite-failed"
        break
      fi
      /bin/sleep 0.005
    done
    if [[ ! -f "$root/endpoint-observer-prerequisite-failed" ]]; then
      printf '%s\n' "$$" > "$root/endpoint-inputs-flushed.ready"
    fi
  fi
  if [[ "$original_trace" == *x* ]]; then set -x; fi
  return 0
}
trap '_b01_endpoint_input_join "$?" "${BASH_COMMAND:-}" "$-"' DEBUG
'''

def require(condition, description):
    if not condition:
        raise RuntimeError(PREFIX + ": " + description)

class EndpointFixture(original.RestartFailoverFixture):
    def __init__(self, root, source, case):
        require(case in {"mismatch", "matching", "mixed"}, "declared endpoint case")
        super().__init__(root, source, "failover-no-replacement")
        self.endpoint_case = case
        try:
            relative = "scripts/nat-sim/fixture_candidate_failover_endpoint_tools.py"
            test_relative = "scripts/nat-sim/test_candidate_failover_endpoint_controls.py"
            payload = TOOL.read_bytes()
            require(hashlib.sha256(payload).hexdigest() == self.original_sources.get(relative), "captured NEW adapter")
            require(original.digest(Path(__file__).resolve()) == self.original_sources.get(test_relative), "captured NEW test")
            driver = self.root / "fixture-external-tools.py"
            driver.write_bytes(payload)
            driver.chmod(0o600)
            settings = original.read_json(self.root / "fixture-config.json")
            settings.update(endpoint_case=case, external_tools_sha256=original.digest(driver),
                            endpoint_test_sha256=self.original_sources[test_relative])
            config = self.root / "fixture-config.json"
            config.write_text(json.dumps(settings, sort_keys=True) + "\n")
            config.chmod(0o600)
            self.roles = self.roles | {"relay-3"}
            self.environment["RELAY_COUNT"] = "3"
            for name in ("python3", "cargo", "go", "curl"):
                expected = "#!/bin/sh\nexec " + shlex.join([settings["real_python"], "-S", str(driver), str(self.root), name]) + ' "$@"\n'
                require((self.root / "fake-path" / name).read_text() == expected, "unchanged original native launcher")
            observer = self.root / "endpoint-input-observer.sh"
            text = OBSERVER.replace("__CLI__", shlex.quote(str(self.repository / "scripts/nat-sim/nat-sim-smoke.sh")))
            text = text.replace("__ROOT__", shlex.quote(str(self.root)))
            with observer.open("x") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(text)
            self.environment["BASH_ENV"] = str(observer)
            self.transport_binding = {"fixture_only": True, "original_sources": self.original_sources,
                "adapter_relative_path": relative, "adapter_sha256": original.digest(driver),
                "original_tools_relative_path": "scripts/nat-sim/fixture_restart_failover_control_tools.py",
                "original_tools_sha256": self.original_sources["scripts/nat-sim/fixture_restart_failover_control_tools.py"],
                "test_sha256": self.original_sources[test_relative], "observer_sha256": original.digest(observer),
                "launchers": {name: original.digest(self.root / "fake-path" / name) for name in ("python3", "cargo", "go", "curl")},
                "input_join_scope": "controlled input scheduling inside unchanged fixed Overlay/WORK/capture endpoints; SECONDS+1 is not a strict monotonic 1s guarantee"}
            path = self.root / "endpoint-transport-binding.json"
            with path.open("x") as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump(self.transport_binding, stream, sort_keys=True)
                stream.write("\n")
            require(not os.path.lexists(self.artifacts), "ART still belongs to original main")
        except BaseException:
            self.close()
            raise

class ActualFailoverEndpointPartialTests(unittest.TestCase):
    def _case(self, case):
        started = time.monotonic()
        location = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if location:
            root = Path(location).resolve() / self._testMethodName
        else:
            temporary = tempfile.TemporaryDirectory(prefix="p2wlan-partial-endpoint-")
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name).resolve() / "exclusive-case"
        fixture = None
        try:
            fixture = EndpointFixture(root, original.source_repository(), case)
            self.addCleanup(fixture.close)
            require(time.monotonic() < started + original.PREPARATION_SECONDS, "same combined prep4")
            require((original.CLI_SECONDS, original.TEARDOWN_SECONDS, original.ROUND_SECONDS,
                     original.OVERLAY_SECONDS, original.WORK_SECONDS, original.RESOURCE_GRACE_MS)
                    == (24, 2, 30, 12, 15, 1000), "unchanged original budgets")
            fixture.execute()
            proof = self._preconditions(fixture)
            fixture.close()
            sentinel = original.read_json(fixture.root / "sentinel-cleanup.json")
            require(sentinel["wait_completed"] is True and sentinel["wait_status"] == 0 and not fixture.rescued,
                    "actual unrelated sentinel0 without rescue")
        except AssertionError as error:
            raise RuntimeError(PREFIX + ": input/native prerequisite: " + str(error)) from error
        final, canonical, selected, relays = proof
        if case == "mismatch":
            self.assertEqual(fixture.cli_status, 1, TARGET)
            self.assertEqual(final["terminal_reason_code"], "relay_failover_no_replacement_business", TARGET)
            self.assertEqual(final["original_exit_code"], 1, TARGET)
            self.assertEqual(final["round_result"], "invalid", TARGET)
            self.assertEqual(canonical["result"], "fail", TARGET)
            self.assertEqual(canonical["decision"]["reason_code"], "harness:relay_failover_no_replacement_business", TARGET)
            self.assertNotIn("PASS relay_failover_reconfirmed", fixture.stdout, TARGET)
        else:
            self.assertEqual(fixture.cli_status, 0, TARGET)
            self.assertEqual(final["original_exit_code"], 0, TARGET)
            self.assertEqual(final["terminal_reason_code"], "completed", TARGET)
            self.assertEqual(final["round_result"], "completed", TARGET)
            self.assertEqual(canonical["result"], "pass", TARGET)
            self.assertEqual(len(selected), 1, TARGET)
            self.assertEqual(selected[0]["active"], relays[1]["endpoint"], TARGET)
            self.assertEqual(selected[0]["replacement"], relays[2]["endpoint"], TARGET)
            expected = "relay:" + relays[2]["endpoint"]
            self.assertEqual((selected[0]["post_ingress_a"], selected[0]["post_ingress_b"]), (expected, expected), TARGET)

    def _preconditions(self, fixture):
        directory = fixture.artifacts / "round-1"
        rows = original.parent_trace(fixture)
        require(fixture.cli_status in (0, 1) and not fixture.rescued, "natural CLI0/1, never timeout")
        require(not (fixture.root / "endpoint-observer-prerequisite-failed").exists(), "bounded fixed input join")
        for name in ("endpoint-inputs-flushed.ready", "endpoint-fault-joined.ready"):
            require(original.bytes_regular(fixture.root / name, 32).strip() == str(fixture.process.pid).encode(), "same real caller input handshake")
        require(original.read_json(fixture.root / "endpoint-transport-binding.json") == fixture.transport_binding,
                "adapter/launcher observer binding unchanged")
        final = original.read_json(directory / "round-finalization.json")
        canonical = original.read_json(directory / "nat-evidence.json")
        collector = original.read_json(directory / ".collector-result.json")
        require(collector["result"] == "completed" and collector["command_wait_completed"] is True
                and collector["command_wait_status"] == 0 and collector["wait_completed"] is True
                and collector["wait_status"] == -9 and collector["owned_group_shutdown_requested_before_wait"] is True
                and collector["forced_termination"] is False and final["collector"] == collector,
                "original collector command0/held-driver-9")
        backup = directory / ".collector-nat-evidence.json"
        captured = original.read_json(backup) if backup.exists() else canonical
        require(captured["schema_version"] == 2 and captured["result"] == "pass" and captured["executed"] is True
                and captured["skipped"] is False and captured["source_head_sha"] == original.SOURCE_HEAD
                and captured["workflow_sha"] == original.WORKFLOW_HEAD and captured["topology"] == "relay-blackhole"
                and captured["decision"] == {"result": "pass", "reason_code": None, "observed_decision": "first_usable_committed"},
                "initial collector PASS remains initial evidence, both later outcomes allowed")
        encoded = (json.dumps(captured, indent=2, sort_keys=True) + "\n").encode()
        require(len(collector["outputs"]) == 1 and collector["outputs"][0]["name"] == "nat-evidence.json"
                and collector["outputs"][0]["scope"] == "bytes_at_capture"
                and collector["outputs"][0]["captured_sha256"] == hashlib.sha256(encoded).hexdigest(), "original pretty collector SHA")
        if backup.exists():
            require(original.bytes_regular(backup) == (json.dumps(captured, sort_keys=True, separators=(",", ":")) + "\n").encode(),
                    "failed publisher exact compact preservation")
        else:
            require(original.bytes_regular(directory / "nat-evidence.json") == encoded, "success keeps original pretty evidence")
        run = original.unique(rows, lambda row: row["sub"] == 1 and "/round_finalization.py run " in row["command"]
                              and "--label collector " in row["command"], "one original collector action")
        argv = shlex.split(run["command"]); command = argv[argv.index("--") + 1:]
        require(command[:2] == ["python3", str(fixture.repository / "scripts/nat-sim/collect_evidence.py")]
                and command[command.index("--topology") + 1] == "relay-blackhole"
                and command[command.index("--expected-path") + 1] == "relay"
                and command[command.index("--overlay-burst") + 1] == "256"
                and hashlib.sha256(json.dumps(command, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
                == collector["command_argv_sha256"], "complete original collector argv")
        event = original.unique(fixture.events, lambda row: row["tool"] == "original_collector_enter", "real collector native entry")
        require(event["original_script_sha256"] == collector["entry_source"]["sha256"]
                == fixture.original_sources["scripts/nat-sim/collect_evidence.py"]
                and event["command_argv_sha256"] == collector["command_argv_sha256"], "captured original collector source")
        initial = original.unique(rows, lambda row: row["sub"] == 0 and row["command"].startswith("echo ")
                                  and "PASS relay_first_evidence overlay_ok=1" in row["command"], "original Relay strict PASS")
        require("STUN_A=" in (directory / "nat-sim.out").read_text()
                and "STUN_B=" in (directory / "nat-sim.out").read_text()
                and "BLOCK_DIRECT=1" in (directory / "nat-sim.out").read_text().splitlines(), "original blackhole/STUN input")
        relays = {i: original.read_json(directory / ("relay-" + str(i) + ".fixture-ready.json")) for i in (1, 2, 3)}
        require(len({r["pid"] for r in relays.values()}) == len({r["endpoint"] for r in relays.values()}) == 3
                and relays[1]["endpoint"] < relays[2]["endpoint"] < relays[3]["endpoint"], "real distinct catalog preserves primary sort")
        primary = relays[1]
        kill = original.exact_parent(rows, "kill " + str(primary["pid"]))
        wait = original.exact_parent(rows, "wait " + str(primary["pid"]))
        ledger = original.exact_parent(rows, "round_record_wait " + str(primary["pid"]) + " 0")
        joined = original.exact_parent(rows, "killed=1")
        require(run["index"] < initial["index"] < kill["index"] < wait["index"] < ledger["index"] < joined["index"],
                "initial PASS then original native fault/wait/ledger")
        publish = [row for row in rows if row["sub"] == 1 and "/round_finalization.py publish " in row["command"]]
        require(len(publish) == 1, "one real publisher body")
        cleanup = original.read_json(directory / "cleanup.json")
        assert_http_owner_union(self, fixture, directory, cleanup, fixture.roles, (1,), PREFIX)
        require(len(cleanup["owned_processes"]) == 9 and cleanup["started_process_count"] == 9
                and cleanup["wait_completed_count"] == 9 and cleanup["all_reaped"] is True
                and cleanup["pending_process_count"] == cleanup["worker_unknown_count"] == cleanup["unrecorded_process_count"] == 0
                and cleanup["forced_termination"] is False and cleanup["duration_ms"] <= original.RESOURCE_GRACE_MS,
                "exact7producer+2HTTP native owners and original resource cap")
        for owner in cleanup["owned_processes"]:
            require(owner["wait_completed"] is True and owner["wait_status"] == 0, "native owner wait0, never127")
            waited = original.exact_parent(rows, "wait " + str(owner["pid"]))
            recorded = original.exact_parent(rows, "round_record_wait " + str(owner["pid"]) + " 0")
            require(waited["index"] < recorded["index"] < publish[0]["index"], "native owner wait/ledger before publish")
        workers = cleanup["owned_workers"]
        require(len(workers) == 5 and {w["stage"] for w in workers} == {"status-a", "status-b", "collector", "http-barrier-1-a", "http-barrier-1-b"},
                "original five worker union, sampling not reclassified")
        for worker in workers:
            require(worker["command_wait_completed"] is True and worker["command_wait_status"] == 0
                    and worker["wait_completed"] is True and worker["wait_status"] == -9
                    and worker["forced_termination"] is False and original.gone(worker["pid"]), "real worker command0 and held-driver-9")
        # Reuse only the original non-verdict protocol helper. It checks the
        # unchanged fixed projection/action2s margin and original unregistered
        # sample $! -> native wait -> no-op ledger/HTTP header/auth/rm scope.
        action = original.ActualRestartFailoverControlTests._action_and_samples(self, fixture, rows, run, initial, cleanup, publish[0])
        stage, work_end, round_end = (action["original_overlay_stage_end_ms"], action["original_work_end_ms"], action["original_round_end_ms"])
        old_stop = original.read_json(directory / "relay-1.fixture-stopped.json")
        endpoints = ([relays[3]["endpoint"]] if fixture.endpoint_case == "mismatch"
                     else [relays[3]["endpoint"], relays[2]["endpoint"]] if fixture.endpoint_case == "mixed"
                     else [relays[2]["endpoint"]])
        for side in ("a", "b"):
            role = "node-" + side
            ready = original.read_json(directory / (role + ".fixture-ready.json"))
            baseline = original.read_json(directory / (role + ".baseline.readiness.json"))
            barrier = original.read_json(directory / "relay-barrier.readiness.json")
            require(baseline["result"] == "ready" and baseline["http_status"] == 200 and baseline["pid"] == ready["pid"]
                    and baseline["token_present"] is True and baseline["process_alive"] is True
                    and barrier["result"] == "ready" and barrier["reason_code"] is None
                    and barrier["pid_" + side] == ready["pid"] and barrier["http_status_" + side] == 200
                    and barrier["task_health_" + side] is True and barrier["relay_peer_confirmed_" + side] is True,
                    "both real original baselines and task/confirmation gate200")
            status = original.read_json(directory / (role + ".status.json"))
            require(status["process_id"] == ready["pid"] and status["network_generation"] == 1
                    and status["connection_timeline"]["first_usable_summaries"][0]["network_generation"] == 1,
                    "initial status stays same generation, no fabricated recovery status")
            historical = original.read_json(directory / (role + ".fixture-backup-confirmed.json"))
            receipt = original.read_json(directory / (role + ".fixture-failover-flushed.json"))
            require(historical["pid"] == receipt["pid"] == ready["pid"] and historical["backup_endpoint"] == relays[2]["endpoint"]
                    and historical["backup_pid"] == relays[2]["pid"]
                    and historical["monotonic_ns"] < old_stop["monotonic_ns"] < receipt["monotonic_ns"]
                    and receipt["controller_pid"] == fixture.process.pid and receipt["old_pid"] == primary["pid"]
                    and receipt["old_stopped_monotonic_ns"] == old_stop["monotonic_ns"]
                    and receipt["replacement_endpoint"] == relays[2]["endpoint"] and receipt["business_endpoints"] == endpoints,
                    "historical P2 confirmation then actual postfault same-node controlled input")
            require(receipt["monotonic_ns"] // 1_000_000 < min(stage, work_end, round_end), "input fits unchanged fixed endpoints")
            offset = original.unique(rows, lambda row: row["sub"] == 0 and re.fullmatch(side.upper() + r"_FAILOVER_START_LINE=[0-9]+", row["command"]) is not None,
                                     "original offset " + side)
            require(offset["index"] < kill["index"], "original offset before fault")
            log = (directory / (role + ".log")).read_text().splitlines()
            boundary = int(offset["command"].split("=")[1]); pre, post = log[:boundary - 1], log[boundary - 1:]
            require(sum('event="relay_peer_confirmed"' in l and 'relay_endpoint=' + relays[2]["endpoint"] + ' ' in l for l in pre) == 1
                    and not any('event="relay_peer_confirmed"' in l for l in post), "P2 confirmation is only historical, not recreated")
            expected_lines = ["overlay_payload_verified ingress=relay:" + endpoint
                              + " endpoint_control_sequence=" + str(index) + " fixture_only=true"
                              for index, endpoint in enumerate(endpoints)]
            require(sum('overlay_payload_verified' in l for l in pre) == 356
                    and [l for l in post if 'overlay_payload_verified' in l] == expected_lines,
                    "exact declared postfault endpoints, original100+256 preserved")
            require(not any('direct_promoted' in l or 'ingress=direct' in l for l in log), "Relay-only input stays Relay-only")
            wire = "\n".join(expected_lines) + "\n"
            require(receipt["stdout_batch_sha256"] == hashlib.sha256(wire.encode()).hexdigest(), "exact controlled stdout input SHA")
        identity = final["source_identity"]
        require(identity["result"] == "captured" and identity["artifact_validation_scope"] == "declaration_only"
                and len(identity["launch_records"]) == 6 and {r["role"] for r in identity["launch_records"]} == fixture.roles - {"nat"},
                "original six launch declarations are complete, not real artifact behavior")
        owners = {r["role"]:r["pid"] for r in cleanup["owned_processes"]}
        for row in identity["launch_records"]:
            require(row["pid"] == owners[row["role"]] and row["sha256"] == original.digest(directory / "launches" / (row["role"] + ".json")),
                    "actual role/PID/source launch binding")
        selected = []
        for row in rows:
            if row["sub"] == 0 and row["command"].startswith("echo ") and "PASS relay_failover_reconfirmed " in row["command"]:
                payload = shlex.split(row["command"])[1]
                selected.append(dict(re.findall(r"(active|replacement|post_ingress_a|post_ingress_b)=([^ ]+)", payload)))
        return final, canonical, selected, relays

    def test_actual_failover_wrong_endpoint_cannot_satisfy_shared_replacement(self):
        self._case("mismatch")

    def test_actual_failover_live_preconfirmed_backup_same_generation_endpoint_matches(self):
        self._case("matching")

    def test_actual_failover_ignores_other_ingress_before_matching_backup(self):
        self._case("mixed")

if __name__ == "__main__":
    unittest.main()
