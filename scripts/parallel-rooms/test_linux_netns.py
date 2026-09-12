#!/usr/bin/env python3
"""Deterministic checks for the Linux real-TUN harness evidence gates."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import threading
import unittest


SCRIPT = Path(__file__).with_name('linux-netns.py')
SPEC = importlib.util.spec_from_file_location('parallel_rooms_linux_netns', SCRIPT)
assert SPEC is not None and SPEC.loader is not None
linux_netns = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(linux_netns)


class SameProfileRestartEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.previous = {
            'process_id': 101,
            'node_id': 'node-reused-after-restart',
            'network_id': 'room-a',
            'connection_timeline': {'correlation_id': 'node-old-incarnation'},
        }

    def test_accepts_reused_node_identity_only_for_new_instance(self) -> None:
        current = {
            'process_id': 202,
            'node_id': self.previous['node_id'],
            'network_id': self.previous['network_id'],
            'connection_timeline': {'correlation_id': 'node-new-incarnation'},
        }

        linux_netns.verify_same_profile_restart(self.previous, current, 202)

    def test_rejects_status_from_a_different_or_stale_listener(self) -> None:
        current = {
            'process_id': 101,
            'node_id': self.previous['node_id'],
            'network_id': self.previous['network_id'],
            'connection_timeline': {'correlation_id': 'node-new-incarnation'},
        }

        with self.assertRaisesRegex(RuntimeError, 'does not match the new process'):
            linux_netns.verify_same_profile_restart(self.previous, current, 202)

    def test_rejects_old_runtime_incarnation_even_if_the_pid_is_reused(self) -> None:
        current = {
            'process_id': 202,
            'node_id': self.previous['node_id'],
            'network_id': self.previous['network_id'],
            'connection_timeline': self.previous['connection_timeline'],
        }

        with self.assertRaisesRegex(RuntimeError, 'old instance correlation_id'):
            linux_netns.verify_same_profile_restart(self.previous, current, 202)

    def test_rejects_changed_node_or_room_identity(self) -> None:
        current = {
            'process_id': 202,
            'node_id': 'different-node',
            'network_id': self.previous['network_id'],
            'connection_timeline': {'correlation_id': 'node-new-incarnation'},
        }

        with self.assertRaisesRegex(RuntimeError, 'changed node identity'):
            linux_netns.verify_same_profile_restart(self.previous, current, 202)

    def test_log_evidence_redacts_credentials_and_key_material(self) -> None:
        raw = (
            'Authorization: Bearer bearer-secret token="diag-secret" '
            'private_key=private-secret handshake_response=handshake-secret'
        )

        safe = linux_netns.redact_text(raw)
        self.assertNotIn('bearer-secret', safe)
        self.assertNotIn('diag-secret', safe)
        self.assertNotIn('private-secret', safe)
        self.assertNotIn('handshake-secret', safe)


class StopTrafficCoverageTests(unittest.TestCase):
    shutdown_started_ns = 100
    process_exited_ns = 200

    @staticmethod
    def sample(sequence: int, result: str, started_ns: int, finished_ns: int) -> dict[str, object]:
        return {
            'sequence': sequence,
            'result': result,
            'returncode': 0 if result == 'reply' else 1,
            'started_monotonic_ns': started_ns,
            'finished_monotonic_ns': finished_ns,
        }

    def probe_evidence(self, *, drop_during_stop: bool = False) -> dict[str, object]:
        samples = [self.sample(1, 'reply', 10, 20)]
        samples.append(
            self.sample(2, 'no_reply' if drop_during_stop else 'reply', 110, 120)
        )
        samples.extend(
            self.sample(sequence, 'reply', 200 + sequence * 10, 205 + sequence * 10)
            for sequence in range(3, 41)
        )
        return {
            'started_monotonic_ns': 1,
            'finished_monotonic_ns': 700,
            'expected_count': 40,
            'completed_count': len(samples),
            'samples': samples,
        }

    def validate(self, evidence: dict[str, object]) -> None:
        linux_netns.validate_stop_traffic_coverage(
            evidence,
            shutdown_started_ns=self.shutdown_started_ns,
            process_exited_ns=self.process_exited_ns,
        )

    def test_slow_pre_stop_diagnostic_probe_that_ended_before_shutdown_fails(self) -> None:
        evidence = self.probe_evidence()
        evidence['finished_monotonic_ns'] = 90
        evidence['samples'] = [
            self.sample(sequence, 'reply', sequence, sequence + 1)
            for sequence in range(1, 41)
        ]

        with self.assertRaisesRegex(RuntimeError, 'ended before room process exit'):
            self.validate(evidence)

    def test_success_before_and_after_cannot_mask_drop_during_shutdown(self) -> None:
        with self.assertRaisesRegex(RuntimeError, 'failed during shutdown'):
            self.validate(self.probe_evidence(drop_during_stop=True))

    def test_successful_probe_samples_cover_shutdown_and_continue_after_exit(self) -> None:
        evidence = self.probe_evidence()
        self.validate(evidence)

    def test_probe_ending_before_daemon_exit_fails_even_with_prior_replies(self) -> None:
        evidence = self.probe_evidence()
        evidence['finished_monotonic_ns'] = 190

        with self.assertRaisesRegex(RuntimeError, 'ended before room process exit'):
            self.validate(evidence)

    def test_missing_shutdown_window_sample_fails_closed(self) -> None:
        evidence = self.probe_evidence()
        evidence['samples'] = [
            self.sample(sequence, 'reply', sequence * 2, sequence * 2 + 1)
            for sequence in range(1, 41)
        ]

        with self.assertRaisesRegex(RuntimeError, 'no sample covering shutdown'):
            self.validate(evidence)

    def test_thread_submission_is_not_an_echo_reply_confirmation(self) -> None:
        started = threading.Event()
        release_probe = threading.Event()

        def controlled_probe() -> int:
            started.set()
            if not release_probe.wait(timeout=2):
                return 1
            return 0

        probe = linux_netns.ContinuousTrafficProbe(
            controlled_probe, count=1, interval_s=0, max_workers=1,
        )
        probe.start()
        self.assertTrue(started.wait(timeout=1))
        with self.assertRaisesRegex(TimeoutError, 'no confirmed echo reply'):
            probe.wait_for_reply(timeout_s=0)
        release_probe.set()
        self.assertEqual(probe.wait_for_reply(timeout_s=1)['result'], 'reply')
        probe.wait(timeout_s=1)


if __name__ == '__main__':
    unittest.main()
