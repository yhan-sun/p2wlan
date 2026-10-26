import copy
import importlib.util
import socket
import threading
import unittest
from pathlib import Path

import application_layer_report as layers
import tcp_business_probe as tcp
from udp_business_probe import Config, UNVERIFIED


class LayeredObservations(unittest.TestCase):
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
            if not ready.wait(1):
                raise AssertionError('original listener failed readiness')
            result['probe'] = tcp.run_probe(config, client, observe_tcp=True)
        finally:
            client.close(); worker.join(2); listener.close()
        if worker.is_alive():
            raise AssertionError('owned echo did not end')
        if [r['status'] for r in tcp.validate_probe(result['probe'])] != ['success', 'success']:
            raise AssertionError('original loopback outcome failed;do not retry')
        cls.original = result

    def pair(self):
        return copy.deepcopy(self.original['probe']), copy.deepcopy(self.original['echo'])

    def capture(self, probe):
        requests = [dict(flow=0, sequence=r['sequence'], request_nonce=r['request_nonce'],
                         run_nonce=probe['run_nonce'], round_nonce=probe['round_nonce'], kind='request', protocol='tcp', producer_scope='55' * 16)
                    for r in probe['requests']]
        timing = dict(schema_version=1, scope=layers.QUEUE_SCOPE, clock=layers.QUEUE_CLOCK,
                      dataplane_queue=dict(availability='available', nanoseconds=7),
                      network_outbound_queue=dict(availability='available', nanoseconds=13),
                      pending_queue=layers.unavailable('not_observed_by_this_scope'))
        packet = dict(flow=0, read_ordinal=1, packet_sha256='ab' * 32,
                      spans=[dict(slot=0, start=0, end=10), dict(slot=1, start=0, end=10)],
                      initial_queue_intervals=timing)
        return dict(schema_version=2, scope='registered_native_frame_capture', owner=1,
                    producer_scope='33' * 16, capture_id='44' * 16, requests=requests,
                    historical_full_packets=[packet])

    def test_real_pair_preserves_fixed_outcomes_and_local_service_without_cross_clock_math(self):
        probe, echo = self.pair(); report = layers.combine(probe, echo)
        self.assertEqual(report['fixed_denominator'], 2)
        self.assertEqual(report['outcomes']['success'], 2)
        self.assertEqual([r['rtt_ns'] for r in report['requests']], [r['rtt_ns'] for r in probe['requests']])
        self.assertTrue(all(r['service_observation']['availability'] == 'available' for r in report['requests']))
        self.assertEqual(report['evidence'], UNVERIFIED)
        self.assertFalse(report['cross_host_clocks_subtracted'])
        self.assertFalse(report['RTT_minus_service_used_as_network_RTT'])
        self.assertFalse(report['connection_retransmissions']['probe']['request_attribution_verified'])

    def test_no_observation_is_unavailable_not_zero(self):
        probe, echo = self.pair(); probe.pop('tcp_observation'); echo.pop('tcp_observation'); echo.pop('application_service_intervals')
        report = layers.combine(probe, echo)
        self.assertEqual(report['connection_retransmissions']['probe']['availability'], 'unavailable')
        self.assertTrue(all(r['daemon_queue_availability'] == 'unavailable' for r in report['requests']))
        self.assertTrue(all(r['service_observation']['availability'] == 'unavailable' for r in report['requests']))

    def test_foreign_round_and_fixed_workload_change_are_rejected(self):
        for key in ('round_nonce', 'configuration'):
            probe, echo = self.pair()
            if key == 'round_nonce':echo[key] = 'ff' * 16
            else:echo[key]['count'] += 1
            with self.assertRaises(ValueError):layers.combine(probe, echo)

    def test_service_nonce_duplicate_reversed_clock_and_fake_cpu_scope_are_rejected(self):
        for mode in ('nonce', 'duplicate', 'clock', 'scope'):
            probe, echo = self.pair(); row = echo['application_service_intervals'][0]
            if mode == 'nonce':row['request_nonce'] = 'ff' * 16
            elif mode == 'duplicate':echo['application_service_intervals'].append(copy.deepcopy(row))
            elif mode == 'clock':row['response_write_returned_ns'] = 0
            else:row['scope'] = 'CPU_time'
            with self.assertRaises(ValueError):layers.combine(probe, echo)

    def test_same_packet_shared_by_two_frames_is_listed_without_summing(self):
        probe, echo = self.pair(); capture = self.capture(probe); report = layers.combine(probe, echo, [capture])
        for row in report['requests']:
            self.assertEqual(len(row['daemon_queue_observations']), 1)
            packet = row['daemon_queue_observations'][0]
            self.assertTrue(packet['shared_packet_across_request_frames'])
            self.assertEqual(packet['intervals']['dataplane_queue']['nanoseconds'], 7)
            self.assertEqual(packet['intervals']['pending_queue'], layers.unavailable('not_observed_by_this_scope'))
        self.assertFalse(report['packet_intervals_summed_into_request_latency'])
        self.assertEqual(report['requests'][0]['rtt_ns'], probe['requests'][0]['rtt_ns'])

    def test_duplicate_capture_and_packet_are_rejected(self):
        probe, echo = self.pair(); capture = self.capture(probe)
        with self.assertRaises(ValueError):layers.combine(probe, echo, [capture, capture])
        capture['historical_full_packets'].append(copy.deepcopy(capture['historical_full_packets'][0]))
        with self.assertRaises(ValueError):layers.combine(probe, echo, [capture])

    def test_wrong_nonce_or_foreign_protocol_never_joins_queue_to_request(self):
        for key, value in [('request_nonce', 'ff' * 16), ('protocol', 'udp')]:
            probe, echo = self.pair(); capture = self.capture(probe); capture['requests'][0][key] = value
            with self.assertRaises(ValueError):layers.combine(probe, echo, [capture])

    def test_pending_value_clock_scope_and_negative_duration_are_rejected(self):
        for mode in ('pending', 'clock', 'negative'):
            probe, echo = self.pair(); capture = self.capture(probe); row = capture['historical_full_packets'][0]['initial_queue_intervals']
            if mode == 'pending':row['pending_queue'] = dict(availability='available', nanoseconds=0)
            elif mode == 'clock':row['clock'] = 'cross_host_clock'
            else:row['dataplane_queue']['nanoseconds'] = -1
            with self.assertRaises(ValueError):layers.combine(probe, echo, [capture])

    def test_old_capture_without_queue_field_stays_unavailable_and_keeps_outcomes(self):
        probe, echo = self.pair(); capture = self.capture(probe); capture['historical_full_packets'][0].pop('initial_queue_intervals')
        report = layers.combine(probe, echo, [capture]); self.assertEqual(report['outcomes']['success'], 2)
        self.assertTrue(all(r['daemon_queue_observations'][0]['intervals']['availability'] == 'unavailable' for r in report['requests']))

    def test_missing_service_does_not_shrink_timeout_or_unsent_denominator(self):
        probe, echo = self.pair(); row = probe['requests'][0]; row.update(status='timeout', reason='response_deadline', rtt_ns=None)
        row = probe['requests'][1]; row.update(status='not_sent', reason='stream_unusable', rtt_ns=None, sent_offset_ns=None)
        echo['application_service_intervals'] = []
        report = layers.combine(probe, echo); self.assertEqual(report['fixed_denominator'], 2)
        self.assertEqual(report['outcomes']['timeout'], 1); self.assertEqual(report['outcomes']['not_sent'], 1)

    def test_socket_total_tampering_cannot_become_request_retransmission(self):
        probe, echo = self.pair(); probe['tcp_observation']['interval']['counters']['invented'] = dict(availability='available', delta=1, unit='packets')
        with self.assertRaises(ValueError):layers.combine(probe, echo)

    def test_native_credit_cannot_be_minted_by_socket_or_layer_inputs(self):
        probe, echo = self.pair(); probe['tcp_observation']['native_owner_credit_verified'] = True
        with self.assertRaises(ValueError):layers.combine(probe, echo)


if __name__ == '__main__':
    unittest.main(verbosity=2)
