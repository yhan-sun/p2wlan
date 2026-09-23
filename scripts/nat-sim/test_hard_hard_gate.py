#!/usr/bin/env python3
"""Tests for the fail-closed Hard<->Hard simulator gate release."""

from __future__ import annotations

import json
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hard_hard_gate import (
    GateError,
    RendezvousMarker,
    extract_rendezvous_markers,
    plan_gate,
    release_gate,
    select_common_rendezvous,
)


def marker(
    tag: str,
    role: str,
    *,
    punch: int = 10_000,
    server_punch: int = 20_000,
    network: int = 7,
    remote_network: int | None = 9,
    local_profile: int = 3,
    remote_profile: int = 5,
    remote_candidate: int = 11,
) -> RendezvousMarker:
    return RendezvousMarker(
        session_tag=hashlib.sha256(("session:" + tag).encode()).hexdigest()[:16],
        plan_tag=hashlib.sha256(("plan:" + tag).encode()).hexdigest()[:16],
        role=role,
        punch_at_ms=punch,
        punch_at_server_ms=server_punch,
        clock_domain="host_unix_ms",
        network_generation=network,
        remote_candidate_epoch=remote_candidate,
        local_profile_generation=local_profile,
        remote_profile_generation=remote_profile,
        remote_network_generation=remote_network,
    )


def complementary(tag: str, *, punch_a: int = 10_000, punch_b: int = 10_002):
    return (
        marker(
            tag,
            "initiator",
            punch=punch_a,
            network=7,
            remote_network=None,
            local_profile=3,
            remote_profile=5,
            remote_candidate=11,
        ),
        marker(
            tag,
            "responder",
            punch=punch_b,
            network=9,
            remote_network=7,
            local_profile=5,
            remote_profile=3,
            remote_candidate=13,
        ),
    )


def log_line(value: RendezvousMarker) -> str:
    remote_network = (
        "unknown"
        if value.remote_network_generation is None
        else str(value.remote_network_generation)
    )
    return (
        'event="hard_hard_rendezvous_scheduled" '
        f'session_tag="{value.session_tag}" plan_tag="{value.plan_tag}" '
        f'role="{value.role}" punch_at_ms={value.punch_at_ms} '
        f'punch_at_server_ms={value.punch_at_server_ms} '
        f'clock_domain="{value.clock_domain}" '
        f'network_generation={value.network_generation} '
        f'remote_network_generation={remote_network} '
        f'remote_candidate_epoch={value.remote_candidate_epoch} '
        f'local_profile_generation={value.local_profile_generation} '
        f'remote_profile_generation={value.remote_profile_generation}'
    )


class HardHardGateTests(unittest.TestCase):
    def test_extracts_typed_plan_identity_and_epochs(self):
        a, _ = complementary("session-one")
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "node.log"
            log.write_text(log_line(a) + "\n", encoding="utf-8")
            extracted = extract_rendezvous_markers(log)
        self.assertEqual(extracted, [a])

    def test_interleaved_sessions_select_latest_common_plan(self):
        a1, b1 = complementary("session-one", punch_a=9_000, punch_b=9_002)
        a2, b2 = complementary("session-two", punch_a=10_000, punch_b=10_004)
        pair = select_common_rendezvous([a1, a2], [b1, b2])
        self.assertEqual(pair.node_a.plan_tag, a2.plan_tag)
        plan = plan_gate(
            pair,
            9_000,
            max_skew_ms=250,
            lead_ms=10,
            max_future_ms=5000,
            max_late_ms=25,
        )
        self.assertEqual(plan.rendezvous_skew_ms, 4)

    def test_same_timestamp_different_sessions_are_not_paired(self):
        a, _ = complementary("session-one")
        _, b = complementary("session-two")
        with self.assertRaisesRegex(GateError, "latest_plan_unpaired"):
            select_common_rendezvous([a], [b])

    def test_new_one_sided_plan_never_falls_back_to_old_common_plan(self):
        a1, b1 = complementary("session-one")
        a2, _ = complementary("session-two", punch_a=10_100, punch_b=10_102)
        with self.assertRaisesRegex(GateError, "latest_plan_unpaired"):
            select_common_rendezvous([a1, a2], [b1])

    def test_duplicate_markers_are_idempotent(self):
        a, b = complementary("session-one")
        pair = select_common_rendezvous([a, a], [b, b])
        self.assertEqual(pair, type(pair)(a, b))

    def test_conflicting_duplicate_and_stale_epochs_fail_closed(self):
        a, b = complementary("session-one")
        changed = marker(
            "session-one",
            "initiator",
            punch=10_001,
            network=7,
            remote_network=None,
            local_profile=3,
            remote_profile=5,
        )
        with self.assertRaisesRegex(GateError, "duplicate_conflict"):
            select_common_rendezvous([a, changed], [b])
        stale_b = marker(
            "session-one",
            "responder",
            network=9,
            remote_network=7,
            local_profile=6,
            remote_profile=3,
        )
        with self.assertRaisesRegex(GateError, "epoch_mismatch"):
            select_common_rendezvous([a], [stale_b])

    def test_candidate_epochs_remain_endpoint_scoped(self):
        a, b = complementary("session-one", punch_a=10_000, punch_b=10_001)
        pair = select_common_rendezvous([a], [b])
        plan = plan_gate(
            pair,
            9_000,
            max_skew_ms=250,
            lead_ms=10,
            max_future_ms=5000,
            max_late_ms=25,
        )
        self.assertNotEqual(plan.node_a_remote_candidate_epoch, plan.node_b_remote_candidate_epoch)

    def test_missing_pair_and_bad_clock_domain_fail_closed(self):
        a, b = complementary("session-one")
        with self.assertRaisesRegex(GateError, "latest_plan_unpaired"):
            select_common_rendezvous([a], [marker("old-session", "responder")])
        wrong_clock = marker("session-one", "responder", network=9, remote_network=7,
                             local_profile=5, remote_profile=3)
        wrong_clock = RendezvousMarker(**{**wrong_clock.__dict__, "clock_domain": "process_monotonic_ms"})
        with self.assertRaisesRegex(GateError, "clock_domain"):
            select_common_rendezvous([a], [wrong_clock])

    def test_real_same_session_skew_is_still_checked_at_configured_limit(self):
        a, b = complementary("session-one", punch_a=10_000, punch_b=10_251)
        pair = select_common_rendezvous([a], [b])
        with self.assertRaisesRegex(GateError, "rendezvous_skew_exceeded:251"):
            plan_gate(
                pair,
                9_000,
                max_skew_ms=250,
                lead_ms=10,
                max_future_ms=5000,
                max_late_ms=25,
            )

    def test_plan_rejects_future_and_elapsed_deadline(self):
        a, b = complementary("session-one", punch_a=20_000, punch_b=20_001)
        pair = select_common_rendezvous([a], [b])
        common = dict(max_skew_ms=250, lead_ms=10, max_future_ms=5000, max_late_ms=25)
        with self.assertRaisesRegex(GateError, "rendezvous_deadline_too_far"):
            plan_gate(pair, 10_000, **common)
        a, b = complementary("session-two", punch_a=10_000, punch_b=10_001)
        pair = select_common_rendezvous([a], [b])
        with self.assertRaisesRegex(GateError, "rendezvous_deadline_elapsed"):
            plan_gate(pair, 10_026, **common)

    def test_release_writes_private_gate_and_evidence_at_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            a, b = complementary("session-one", punch_a=10_000, punch_b=10_002)
            plan = plan_gate(
                select_common_rendezvous([a], [b]),
                9_000,
                max_skew_ms=250,
                lead_ms=10,
                max_future_ms=5000,
                max_late_ms=25,
            )
            clock = iter((9_000, 9_991))
            sleeps: list[float] = []
            evidence = release_gate(
                plan,
                root / "direct.open",
                root / "gate.json",
                max_late_ms=25,
                now_ms=lambda: next(clock),
                sleep=sleeps.append,
            )
            self.assertEqual(sleeps, [0.99])
            self.assertEqual(evidence["release_offset_from_earliest_punch_ms"], -9)
            self.assertEqual((root / "direct.open").stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / "gate.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((root / "gate.json").read_text())["schema_version"], 2)
            self.assertEqual(json.loads((root / "gate.json").read_text())["result"], "released")

    def test_release_fails_closed_after_scheduler_delay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            a, b = complementary("session-one", punch_a=10_000, punch_b=10_001)
            plan = plan_gate(
                select_common_rendezvous([a], [b]),
                9_000,
                max_skew_ms=250,
                lead_ms=10,
                max_future_ms=5000,
                max_late_ms=25,
            )
            clock = iter((9_000, 10_026))
            with self.assertRaisesRegex(GateError, "rendezvous_release_late"):
                release_gate(
                    plan,
                    root / "direct.open",
                    root / "gate.json",
                    max_late_ms=25,
                    now_ms=lambda: next(clock),
                    sleep=lambda _seconds: None,
                )
            self.assertFalse((root / "direct.open").exists())


if __name__ == "__main__":
    unittest.main()
