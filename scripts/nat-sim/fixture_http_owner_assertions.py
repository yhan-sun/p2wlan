#!/usr/bin/env python3
"""DRAFT ONLY: assertion support for existing complete-CLI HTTP owners.

No TestCase, fixture import, process launch or product repair occurs here.
Group shutdown request plus driver wait is distinct from descendant closure.
"""

import json
import os
import re
import shlex


def bounded_http_contract_json(path):
    with path.open("rb") as stream:
        data = stream.read(128 * 1024 + 1)
    if len(data) > 128 * 1024:
        raise AssertionError("B01 HTTP owner receipt exceeds existing JSON cap")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise AssertionError("B01 HTTP owner receipt is not an object")
    return value


def assert_http_owner_union(test, fixture, directory, cleanup, base_roles, pair_sequences, marker):
    """Return the original business/watcher subset after exact union proof.

    Existing callers pass fixed () or (1,). These controls contain at most
    one fetched pair across their complete CLI, including the two-round case
    whose first round fails before any pair. Broader sampling is not covered.
    """
    test.assertIn(tuple(pair_sequences), ((), (1,)), marker)
    expected_http = {f"http-barrier-{sequence}-{side}"
                     for sequence in pair_sequences for side in ("a", "b")}
    base_roles = set(base_roles)
    test.assertFalse(base_roles & expected_http, marker)
    rows = cleanup["owned_processes"]
    test.assertIs(type(rows), list, marker)
    test.assertEqual(len(rows), len(base_roles | expected_http), marker)
    by_role = {row["role"]: row for row in rows}
    test.assertEqual(len(by_role), len(rows), marker)
    test.assertEqual(set(by_role), base_roles | expected_http, marker)
    pids = [row["pid"] for row in rows]
    test.assertTrue(all(type(pid) is int and pid > 0 for pid in pids), marker)
    test.assertEqual(len(set(pids)), len(pids), marker)
    for field in ("started_process_count", "wait_completed_count"):
        test.assertIs(type(cleanup[field]), int, marker)
        test.assertEqual(cleanup[field], len(rows), marker)
    for field in ("pending_process_count", "worker_unknown_count", "unrecorded_process_count"):
        test.assertEqual(cleanup[field], 0, marker)
    test.assertEqual(cleanup["metadata_coverage"], "complete", marker)
    test.assertIs(cleanup["all_reaped"], True, marker)
    test.assertIs(cleanup["forced_termination"], False, marker)
    workers = cleanup["owned_workers"]
    test.assertIs(type(workers), list, marker)
    http_workers = [row for row in workers if row["stage"].startswith("http-")]
    test.assertEqual(len(http_workers), len(expected_http), marker)
    by_stage = {row["stage"]: row for row in http_workers}
    test.assertEqual(set(by_stage), expected_http, marker)
    test.assertEqual(len(by_stage), len(http_workers), marker)
    parent_prefix = rf"^\++ B01_CLI pid={fixture.process.pid} sub=0 line=[0-9]+: (.*)$"
    commands = re.findall(parent_prefix, fixture.stderr, re.MULTILINE)
    registrations = [command for command in commands
                     if command.startswith("round_register_process http-")]
    expected_registers = {f"round_register_process {role} {by_role[role]['pid']}"
                         for role in expected_http}
    test.assertEqual(set(registrations), expected_registers, marker)
    test.assertEqual(len(registrations), len(expected_registers), marker)
    driver_pids = set()
    for role in sorted(expected_http):
        match = re.fullmatch(r"http-barrier-([1-9][0-9]*)-([ab])", role)
        test.assertIsNotNone(match, marker)
        sequence, side = int(match[1]), match[2]
        row = by_role[role]
        pid = row["pid"]
        test.assertIs(row["wait_completed"], True, marker)
        test.assertIs(type(row["wait_status"]), int, marker)
        test.assertEqual(row["wait_status"], 0, marker)
        test.assertIs(row["forced_termination"], False, marker)
        register = f"round_register_process {role} {pid}"
        assignment, native_wait, ledger = f"{side}_pid={pid}", f"wait {pid}", f"round_record_wait {pid} 0"
        for command in (assignment, native_wait, ledger):
            test.assertEqual(commands.count(command), 1, marker)
        test.assertLess(commands.index(assignment), commands.index(register), marker)
        test.assertLess(commands.index(register), commands.index(native_wait), marker)
        test.assertLess(commands.index(native_wait), commands.index(ledger), marker)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError(marker + ": HTTP owner remains live/unreaped")
        path = directory / ("." + role + "-result.json")
        test.assertEqual(path.stat().st_mode & 0o777, 0o600, marker)
        receipt = bounded_http_contract_json(path)
        test.assertIs(type(receipt["schema_version"]), int, marker)
        test.assertEqual(receipt["schema_version"], 1, marker)
        test.assertEqual(receipt["owner_role"], role, marker)
        test.assertEqual(receipt["owner_pid"], pid, marker)
        test.assertIs(type(receipt["pair_sequence"]), int, marker)
        test.assertEqual(receipt["pair_sequence"], sequence, marker)
        test.assertEqual(receipt["side"], side, marker)
        test.assertEqual(receipt["context_pid"], fixture.process.pid, marker)
        test.assertEqual(receipt["round_dir"], str(directory), marker)
        number = int(directory.name.removeprefix("round-"))
        test.assertEqual(receipt["round_run_id"],
                         fixture.environment["NAT_SIM_RUN_ID"] + f"-round-{number}", marker)
        calls = [event for event in fixture.events if event["tool"] == "curl"
                 and event.get("output") == str(directory / ("node-" + side + ".barrier.status.json"))]
        test.assertEqual(len(calls), 1, marker)
        test.assertEqual(calls[0]["side"], side, marker)
        test.assertEqual(calls[0]["round"], number, marker)
        test.assertEqual(by_stage[role], {"stage": role, **receipt}, marker)
        for field in ("started", "wait_completed", "command_wait_completed",
                      "owned_group_shutdown_requested_before_wait"):
            test.assertIs(receipt[field], True, marker)
        test.assertIs(receipt["forced_termination"], False, marker)
        test.assertEqual(receipt["result"], "completed", marker)
        test.assertIsNone(receipt["reason_code"], marker)
        test.assertIs(type(receipt["command_wait_status"]), int, marker)
        test.assertEqual(receipt["command_wait_status"], 0, marker)
        # The original metadata body prints its result and returns zero even
        # after a failed fetch. This is not an assertion that curl succeeded.
        test.assertIs(type(receipt["wait_status"]), int, marker)
        test.assertNotEqual(receipt["wait_status"], 127, marker)
        driver = receipt["pid"]
        test.assertIs(type(driver), int, marker)
        test.assertGreater(driver, 0, marker)
        test.assertNotIn(driver, pids, marker)
        test.assertNotIn(driver, driver_pids, marker)
        driver_pids.add(driver)
        # Native owner wait zero and held-driver group wait (usually -9)
        # are independent fields. A request and driver wait do not establish
        # that every descendant disappeared; the dedicated signal case does.
        test.assertIs(receipt["cancel_fence_matched"], False, marker)
        test.assertIsNone(receipt["cancellation_resource_end_ms"], marker)
        endpoints = [receipt[field] for field in ("input_deadline_monotonic_ms",
                    "round_deadline_monotonic_ms", "work_deadline_monotonic_ms")]
        test.assertTrue(all(type(value) is int and value > 0 for value in endpoints), marker)
        test.assertLessEqual(endpoints[0], endpoints[1], marker)
        test.assertLessEqual(endpoints[0], endpoints[2], marker)
        times = [receipt[field] for field in ("command_wait_observed_monotonic_ms",
                 "group_shutdown_requested_monotonic_ms", "driver_wait_returned_monotonic_ms",
                 "receipt_prepublication_monotonic_ms")]
        test.assertTrue(all(type(value) is int and value > 0 for value in times), marker)
        test.assertEqual(times, sorted(times), marker)
        test.assertLessEqual(times[-1], endpoints[0], marker)
    if expected_http:
        # The original parent reads all six metadata fields after its two
        # successful native joins, then removes only the two scratch files.
        metadata_reads = [f"read -r {side}_{field}" for side in ("a", "b")
                          for field in ("ok", "http", "reason")]
        last_join = max(commands.index(f"round_record_wait {by_role[role]['pid']} 0")
                        for role in expected_http)
        for command in metadata_reads:
            test.assertEqual(commands.count(command), 1, marker)
            test.assertGreater(commands.index(command), last_join, marker)
        scratch = [str(directory / (".barrier-" + side + "-fetch")) for side in ("a", "b")]
        removals = []
        for index, command in enumerate(commands):
            if not command.startswith("rm -f "):
                continue
            try:
                arguments = shlex.split(command)
            except ValueError:
                raise AssertionError(marker + ": malformed metadata cleanup trace") from None
            if arguments == ["rm", "-f", *scratch]:
                removals.append(index)
        test.assertEqual(len(removals), 1, marker)
        test.assertGreater(removals[0], max(commands.index(command) for command in metadata_reads), marker)
        test.assertTrue(all(not (directory / (".barrier-" + side + "-fetch")).exists()
                            for side in ("a", "b")), marker)
    # The final timestamp is prepublication only. Atomic write completion is
    # proved by the production post-write guard and native owner closing wait,
    # not inferred from a self-contained receipt timestamp.
    return [row for row in rows if row["role"] in base_roles]
