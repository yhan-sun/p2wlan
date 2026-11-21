#!/usr/bin/env python3
"""Fixture-only contract controls; these never execute or authenticate Minecraft."""

import copy
import hashlib
import unittest

import minecraft_interaction as interaction


MANIFEST_SHA = "a" * 64


def nonce(value: int) -> str:
    return f"{value:032x}"


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def manifest(count=2, rounds=1, edition="java", execution_kind="adapter_fixture"):
    identity = {name: sha("fixture-" + name) for name in interaction.IDENTITY_HASHES}
    identity.update(p2wlan_client_commit="1" * 40, p2wlan_server_commit="2" * 40,
                    game_client_version="fixture-client-1", game_server_version="fixture-server-1",
                    protocol_version="fixture-protocol-1", server_implementation="fixture",
                    runtime_version="fixture-1", platform="fixture", scenario_version="block-place-v1")
    return {
        "schema_version": 1, "scope": interaction.CONTRACT["scope"],
        "contract_sha256": interaction.CONTRACT_SHA256, "run_nonce": nonce(1),
        "execution_kind": execution_kind, "edition": edition,
        "transport": "tcp" if edition == "java" else "raknet_udp", "variant": "baseline",
        "identity": identity, "rounds": [{
            "round_nonce": nonce(10 + r), "adapter_nonce": nonce(100 + r),
            "session_nonce": nonce(200 + r), "clock_nonce": nonce(300 + r),
            "world_reset_sha256": sha(f"fixture-reset-{r}"), "duration_ns": count * 30 + 40,
            "requests": [{"ordinal": i, "request_nonce": nonce(1000 + r * 1000 + i),
                          "planned_offset_ns": i * 30, "timeout_ns": 20, "action": "block_place",
                          "target_sha256": sha(f"fixture-target-{r}-{i}"),
                          "before_state_sha256": sha("fixture-air"),
                          "after_state_sha256": sha("fixture-block")}
                         for i in range(count)]} for r in range(rounds)],
    }


def telemetry():
    return {name: {"value": None, "unit": unit, "reason": "not_collected", "source_sha256": None,
                   "clock_nonce": None, "start_offset_ns": None, "end_offset_ns": None}
            for name, unit in interaction.CONTRACT["telemetry_units"].items()}


def event(plan, kind, offset, request=0, round_index=0, **changes):
    round_ = plan["rounds"][round_index]
    result = {name: plan[name] if name == "run_nonce" else round_[name]
              for name in interaction.SOURCE_FIELDS}
    result.update(kind=kind, event_seq=0, offset_ns=offset)
    if kind.startswith("action_"):
        result["request_nonce"] = round_["requests"][request]["request_nonce"]
    if kind == "action_confirmed":
        result.update(confirmation="server_block_update", correlation="isolated_unique_target_transition",
                      wire_request_id=None, observation_sha256=sha(f"fixture-observation-{request}"))
        for name in ("target_sha256", "before_state_sha256", "after_state_sha256"):
            result[name] = round_["requests"][request][name]
    if kind == "action_failed":
        result["reason"] = "action_rejected"
    result.update(changes)
    return result


def report(plan, events=None, elapsed=60, termination="completed", round_index=0):
    if events is None:
        events = [event(plan, "session_ready", 0, round_index=round_index)]
        for i in range(len(plan["rounds"][round_index]["requests"])):
            events.extend([event(plan, "action_started", 10 + i * 30, i, round_index),
                           event(plan, "action_confirmed", 15 + i * 30, i, round_index)])
    events = copy.deepcopy(events)
    for i, item in enumerate(events):
        item["event_seq"] = i
    return {"schema_version": 1, "manifest_sha256": MANIFEST_SHA,
            "round_nonce": plan["rounds"][round_index]["round_nonce"], "elapsed_ns": elapsed,
            "termination": termination, "events": events, "telemetry": telemetry()}


def reduce(plan, value):
    interaction.validate_manifest(plan)
    return interaction.reduce_round(plan, plan["rounds"][0], value, MANIFEST_SHA)


class ManifestTests(unittest.TestCase):
    def test_both_editions_have_distinct_explicit_transports(self):
        for edition in ("java", "bedrock"):
            interaction.validate_manifest(manifest(edition=edition))

    def test_new_round_cannot_reuse_original_game_session(self):
        plan = manifest(rounds=2)
        for name in ("adapter_nonce", "session_nonce"):
            plan["rounds"][1][name] = plan["rounds"][0][name]
        with self.assertRaisesRegex(ValueError, "fresh game session"):
            interaction.validate_manifest(plan)

    def test_manifest_rejects_drift_bounds_duplicate_identity_and_fake_actions(self):
        mutations = [
            lambda p: p.update(schema_version=True),
            lambda p: p.update(transport="udp"),
            lambda p: p.update(transport="nethernet"),
            lambda p: p.update(contract_sha256="0" * 64),
            lambda p: p.update(execution_kind="verified_game"),
            lambda p: p.update(real_tun_verified=True),
            lambda p: p["identity"].pop("world_snapshot_sha256"),
            lambda p: p["identity"].update(game_client_version="latest version"),
            lambda p: p["identity"].update(game_client_version="latest"),
            lambda p: p["rounds"].append(copy.deepcopy(p["rounds"][0])),
            lambda p: p["rounds"][0].update(duration_ns=interaction.CONTRACT["max_duration_ns"] + 1),
            lambda p: p["rounds"][0]["requests"].clear(),
            lambda p: p["rounds"][0]["requests"][1].update(request_nonce=nonce(1000)),
            lambda p: p["rounds"][0]["requests"][1].update(ordinal=0),
            lambda p: p["rounds"][0]["requests"][1].update(planned_offset_ns=0),
            lambda p: p["rounds"][0]["requests"][1].update(timeout_ns=True),
            lambda p: p["rounds"][0]["requests"][1].update(timeout_ns=10**12),
            lambda p: p["rounds"][0]["requests"][1].update(target_sha256=p["rounds"][0]["requests"][0]["target_sha256"]),
            lambda p: p["rounds"][0]["requests"][0].update(after_state_sha256=sha("fixture-air")),
            lambda p: p["rounds"][0]["requests"][0].update(action="status_ping"),
        ]
        for mutate in mutations:
            plan = manifest()
            mutate(plan)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                interaction.validate_manifest(plan)


class ReducerTests(unittest.TestCase):
    def test_success_has_exact_same_clock_delta_and_immutable_schedule(self):
        plan = manifest()
        value = report(plan)
        original = copy.deepcopy((plan, value))
        result = reduce(plan, value)
        self.assertEqual([r["status"] for r in result["requests"]], ["success", "success"])
        self.assertEqual([r["rtt_ns"] for r in result["requests"]], [5, 5])
        self.assertEqual((plan, value), original)

    def test_wrong_source_request_transition_and_duplicate_do_not_poison_valid_confirmation(self):
        plan = manifest(count=1)
        events = [event(plan, "session_ready", 0), event(plan, "action_started", 10)]
        for name in interaction.SOURCE_FIELDS:
            events.append(event(plan, "action_confirmed", 12, **{name: nonce(999)}))
        events.extend([event(plan, "action_confirmed", 12, request_nonce=nonce(998)),
                       event(plan, "action_confirmed", 12, target_sha256=sha("other")),
                       event(plan, "action_confirmed", 15), event(plan, "action_confirmed", 16)])
        result = reduce(plan, report(plan, events, elapsed=16))
        self.assertEqual(result["requests"][0]["rtt_ns"], 5)
        self.assertEqual(result["rejected_events"], {"source_mismatch": 5, "unknown_request": 1,
                                                  "transition_mismatch": 1, "not_pending": 1})

    def test_confirmation_before_start_is_rejected_then_real_start_can_succeed(self):
        plan = manifest(count=1)
        events = [event(plan, "session_ready", 0), event(plan, "action_confirmed", 5),
                  event(plan, "action_started", 10), event(plan, "action_confirmed", 15)]
        result = reduce(plan, report(plan, events, elapsed=16))
        self.assertEqual(result["requests"][0]["status"], "success")
        self.assertEqual(result["rejected_events"], {"not_pending": 1})

    def test_foreign_source_time_cannot_poison_current_confirmation(self):
        plan = manifest(count=1)
        for name in interaction.SOURCE_FIELDS:
            with self.subTest(source_field=name):
                events = [event(plan, "session_ready", 0), event(plan, "action_started", 10),
                          event(plan, "action_confirmed", 100, **{name: nonce(999)}),
                          event(plan, "action_confirmed", 15)]
                result = reduce(plan, report(plan, events, elapsed=16))
                self.assertEqual(result["requests"][0]["status"], "success")
                self.assertEqual(result["requests"][0]["rtt_ns"], 5)
                self.assertEqual(result["rejected_events"], {"source_mismatch": 1})

    def test_source_fencing_preserves_offset_shape_and_current_time_bounds(self):
        plan = manifest(count=1)
        for offset in (True, -1, interaction.CONTRACT["max_duration_ns"] + 1):
            with self.subTest(foreign_offset=offset), self.assertRaises(ValueError):
                reduce(plan, report(plan, [event(plan, "action_confirmed", offset,
                                                clock_nonce=nonce(999))], elapsed=16,
                                    termination="interrupted"))
        with self.assertRaises(ValueError):
            reduce(plan, report(plan, [event(plan, "session_ready", 0),
                                      event(plan, "action_started", 10),
                                      event(plan, "action_confirmed", 100)], elapsed=16))

    def test_exact_deadline_and_late_confirmations_never_resurrect_timeout(self):
        plan = manifest()
        events = [event(plan, "session_ready", 0), event(plan, "action_started", 10),
                  event(plan, "action_confirmed", 30), event(plan, "action_confirmed", 35),
                  event(plan, "action_started", 40, 1), event(plan, "action_confirmed", 45, 1)]
        result = reduce(plan, report(plan, events))
        self.assertEqual([r["status"] for r in result["requests"]], ["timeout", "success"])
        self.assertEqual(result["requests"][0]["completed_offset_ns"], 30)
        self.assertIsNone(result["requests"][0]["rtt_ns"])

    def test_failure_and_explicit_cancel_remain_terminal_after_late_reply(self):
        for kind, expected in (("action_failed", "action_error"), ("action_cancelled", "cancelled")):
            plan = manifest()
            events = [event(plan, "session_ready", 0), event(plan, "action_started", 10),
                      event(plan, kind, 12), event(plan, "action_confirmed", 15),
                      event(plan, "action_started", 40, 1), event(plan, "action_confirmed", 45, 1)]
            result = reduce(plan, report(plan, events))
            self.assertEqual([r["status"] for r in result["requests"]], [expected, "success"])
            self.assertIsNone(result["requests"][0]["rtt_ns"])

    def test_session_close_rejects_old_replies_and_does_not_start_a_new_owner(self):
        plan = manifest()
        events = [event(plan, "session_ready", 0), event(plan, "action_started", 10),
                  event(plan, "session_closed", 12), event(plan, "action_confirmed", 15),
                  event(plan, "session_ready", 20), event(plan, "action_started", 40, 1)]
        result = reduce(plan, report(plan, events, termination="adapter_error"))
        self.assertEqual([r["status"] for r in result["requests"]], ["disconnected", "not_started"])
        self.assertEqual(result["rejected_events"], {"session_closed": 3})

    def test_report_interruption_unavailable_and_deadline_preserve_every_action(self):
        plan = manifest()
        partial = [event(plan, "session_ready", 0), event(plan, "action_started", 10)]
        cases = [([], 0, "adapter_unavailable", ["not_started", "not_started"]),
                 (partial, 12, "interrupted", ["cancelled", "not_started"]),
                 (partial, 100, "duration_deadline", ["timeout", "not_started"])]
        for events, elapsed, termination, expected in cases:
            result = reduce(plan, report(plan, events, elapsed, termination))
            self.assertEqual([r["status"] for r in result["requests"]], expected)

    def test_rejects_transport_ping_fake_wire_nonce_and_unbounded_or_inconsistent_streams(self):
        plan = manifest()
        mutations = [
            lambda r: r.update(schema_version=True),
            lambda r: r.update(manifest_sha256="b" * 64),
            lambda r: r.update(round_nonce=nonce(999)),
            lambda r: r.update(elapsed_ns=101),
            lambda r: r.update(termination="unknown"),
            lambda r: r.update(termination="duration_deadline"),
            lambda r: r.update(termination="adapter_unavailable"),
            lambda r: r.update(events=[r["events"][0]] * (interaction.CONTRACT["max_events_per_round"] + 1)),
            lambda r: r["events"][2].update(event_seq=1),
            lambda r: r["events"][2].update(offset_ns=9),
            lambda r: r["events"][2].update(offset_ns=True),
            lambda r: r["events"][2].update(wire_request_id=nonce(1000)),
            lambda r: r["events"][2].update(wire_nonce=nonce(1000)),
            lambda r: r["events"][2].update(confirmation="status_ping"),
            lambda r: r["events"][2].update(confirmation="tcp_write"),
            lambda r: r["events"][2].update(confirmation="raknet_ack"),
            lambda r: r["events"][2].update(correlation="request_nonce_echo"),
            lambda r: r["events"].__delitem__(slice(-2, None)),
        ]
        for mutate in mutations:
            value = report(plan)
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                reduce(plan, value)

    def test_start_is_single_attempt_in_order_and_within_original_budget(self):
        plan = manifest()
        cases = [
            [event(plan, "action_started", 10)],
            [event(plan, "session_ready", 0), event(plan, "action_started", 10),
             event(plan, "action_started", 12)],
            [event(plan, "session_ready", 0), event(plan, "action_started", 30, 1)],
            [event(plan, "session_ready", 0), event(plan, "action_started", 10),
             event(plan, "action_started", 30)],
            [event(plan, "session_ready", 0), event(plan, "action_started", 90)],
            [event(plan, "session_ready", 0), event(plan, "action_started", 10),
             event(plan, "action_confirmed", 15), event(plan, "action_started", 20, 1)],
        ]
        for events in cases:
            with self.subTest(events=events), self.assertRaises(ValueError):
                reduce(plan, report(plan, events, elapsed=100, termination="duration_deadline"))

    def test_unknown_telemetry_cannot_be_zero_or_inferred_and_observed_windows_stay_separate(self):
        plan = manifest()
        value = report(plan)
        metric = value["telemetry"]["server_tps"]
        metric.update(value=20, reason=None, source_sha256=sha("fixture-server-ticks"),
                      clock_nonce=nonce(888), start_offset_ns=3, end_offset_ns=50)
        result = reduce(plan, value)
        self.assertEqual(result["reported_telemetry"], value["telemetry"])
        self.assertEqual(result["requests"][0]["rtt_ns"], 5)
        for field, replacement in (("value", True), ("value", float("nan")),
                                   ("value", 10**1000), ("reason", "inferred_from_ping"),
                                   ("end_offset_ns", 3), ("source_sha256", None)):
            bad = copy.deepcopy(value)
            bad["telemetry"]["server_tps"][field] = replacement
            with self.subTest(field=field, replacement=replacement), self.assertRaises(ValueError):
                reduce(plan, bad)
        unknown = report(plan)
        unknown["telemetry"]["server_mspt"]["value"] = 0
        with self.assertRaises(ValueError):
            reduce(plan, unknown)
        unknown = report(plan)
        unknown["telemetry"]["server_tps"]["reason"] = "not_applicable"
        with self.assertRaises(ValueError):
            reduce(plan, unknown)


if __name__ == "__main__":
    unittest.main()
