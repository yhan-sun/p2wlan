import copy
import json
from pathlib import Path
import socket
import stat
import tempfile
import threading
from types import SimpleNamespace
import unittest

import application_layer_export as exporter
import application_layer_report as layers
import tcp_business_probe as tcp
from udp_business_probe import Config, UNVERIFIED


class OriginalLayerExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        client, listener = socket.socket(), socket.socket()
        client.bind(('127.0.0.1', 0)); listener.bind(('127.0.0.1', 0))
        a, b = client.getsockname(), listener.getsockname()
        config = Config(a, b, '11' * 16, '22' * 16, 2, 20, 200, 1000, 16)
        echo = Config(b, a, config.run_nonce, config.round_nonce, 2, 20, 200, 1000, 16)
        ready, result = threading.Event(), {}
        worker = threading.Thread(target=lambda: result.update(echo=tcp.run_echo(echo, listener, ready.set, observe_tcp=True)))
        worker.start()
        try:
            if not ready.wait(1):raise AssertionError('original listener readiness failed')
            result['probe'] = tcp.run_probe(config, client, observe_tcp=True)
        finally:
            client.close(); worker.join(2); listener.close()
        if worker.is_alive() or [r['status'] for r in tcp.validate_probe(result['probe'])] != ['success', 'success']:
            raise AssertionError('original pair failed; no retry')
        cls.original = result

    def inputs(self, root):
        probe, echo = copy.deepcopy(self.original['probe']), copy.deepcopy(self.original['echo'])
        probe['request_plan'] = {'producer_scope': '55' * 16}
        for role, report in [('probe', probe), ('echo', echo)]:
            (root / ('tcp-a-to-b-' + role + '.json')).write_text(json.dumps(report))
        return probe, echo

    def capture(self, probe):
        # Data fixtures exercise joins only; no KernelRead or native credit.
        rows = [dict(flow=2, sequence=r['sequence'], request_nonce=r['request_nonce'],
                     run_nonce=probe['run_nonce'], round_nonce=probe['round_nonce'],
                     kind='request', protocol='tcp', producer_scope='55' * 16)
                for r in probe['requests']]
        rows += [dict(rows[0], flow=0, producer_scope='66' * 16, protocol='udp', request_nonce='77' * 16)]
        timing = dict(schema_version=1, scope=layers.QUEUE_SCOPE, clock=layers.QUEUE_CLOCK,
                      dataplane_queue=dict(availability='available', nanoseconds=7),
                      network_outbound_queue=dict(availability='available', nanoseconds=13),
                      pending_queue=layers.unavailable('not_observed_by_this_scope'))
        return dict(schema_version=2, scope='registered_native_frame_capture', producer_scope='33' * 16,
                    capture_id='44' * 16, owner=1, requests=rows, historical_full_packets=[
                        dict(flow=2, read_ordinal=1, packet_sha256='ab' * 32,
                             spans=[dict(slot=0, start=0, end=10), dict(slot=1, start=0, end=10)],
                             initial_queue_intervals=timing)])

    def test_actual_loopback_reports_export_without_extra_network_or_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); probe, echo = self.inputs(root)
            summary = exporter.export(root, [dict(protocol='tcp', direction='a-to-b')])
            self.assertEqual(summary['extra_daemon_snapshot_requests'], 0)
            report = json.loads((root / summary['reports'][0]['file']).read_text())
            self.assertEqual(report['fixed_denominator'], 2)
            self.assertEqual(report['outcomes']['success'], 2)
            self.assertEqual([r['rtt_ns'] for r in report['requests']], [r['rtt_ns'] for r in probe['requests']])
            self.assertTrue(all(r['service_observation']['availability'] == 'available' for r in report['requests']))
            self.assertEqual(report['evidence'], UNVERIFIED)
            if stat.S_IMODE((root / summary['reports'][0]['file']).stat().st_mode) != 0o600 and hasattr(socket, 'AF_UNIX'):
                # Windows permissions do not implement POSIX mode semantics.
                import os
                self.assertEqual(os.name, 'nt')

    def test_actual_original_entries_attribute_and_producer_filter_join_only_retained_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); probe, _ = self.inputs(root); capture = self.capture(probe)
            entry = dict(protocol='tcp', direction='a-to-b')
            endpoint = SimpleNamespace(raw_snapshots=[json.dumps(capture).encode()])
            owner = SimpleNamespace(entries=[dict(entry=entry, endpoints=[endpoint, SimpleNamespace(raw_snapshots=[])])])
            summary = exporter.export(root, [entry], owner)
            self.assertEqual(summary['reports'][0]['same_request_both_channel_intervals_available'], 2)
            self.assertEqual(summary['extra_daemon_snapshot_requests'], 0)
            self.assertFalse(summary['packet_intervals_summed'])

    def test_selected_producer_cannot_change_nonce_or_protocol(self):
        with tempfile.TemporaryDirectory() as folder:
            probe, echo = self.inputs(Path(folder)); capture = self.capture(probe)
            for key, value in [('request_nonce', 'ff' * 16), ('protocol', 'udp')]:
                changed = copy.deepcopy(capture); changed['requests'][0][key] = value
                with self.assertRaises(ValueError):layers.combine(probe, echo, [changed])

    def test_duplicate_original_capture_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self.inputs(root); entry = dict(protocol='tcp', direction='a-to-b')
            row = dict(entry=entry, endpoints=[])
            with self.assertRaises(ValueError):exporter.export(root, [entry], SimpleNamespace(entries=[row, row]))

    def test_bounded_manifest_and_original_phase_are_enforced(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaises(ValueError):exporter.export(root, [{}] * 33)
            with self.assertRaises(ValueError):exporter.export(root, [dict(protocol='tcp', direction='a-to-b', phase='../foreign')])

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self.inputs(root); original = root / 'tcp-a-to-b-layers.json';original.write_bytes(b'original')
            with self.assertRaises((ValueError, OSError)):exporter.export(root, [dict(protocol='tcp', direction='a-to-b')])
            self.assertEqual(original.read_bytes(), b'original')


if __name__ == '__main__':
    unittest.main(verbosity=2)
