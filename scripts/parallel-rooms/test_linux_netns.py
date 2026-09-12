#!/usr/bin/env python3
"""Deterministic checks for the Linux real-TUN harness evidence gates."""

from __future__ import annotations

import importlib.util
from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()
