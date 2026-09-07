#!/usr/bin/env python3
import datetime
import importlib.util
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
DUAL = (ROOT / 'scripts/dual-end/mini-air-smoke.sh').read_text()
NAT = (ROOT / 'scripts/nat-sim/nat-sim-smoke.sh').read_text()


def shell_function(source, name):
    match = re.search(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}', source, re.M | re.S)
    if match is None:
        raise AssertionError('missing production function ' + name)
    return match.group(0)


class LogFormatCompatibility(unittest.TestCase):
    def invoke(self, source, name, line, *args):
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8') as log:
            log.write(line + '\n')
            log.flush()
            script = 'strip_ansi() { cat; }\n' + shell_function(source, name)
            script += '\n' + name + ' "$@"\n'
            return subprocess.check_output(
                ['bash', '-c', script, 'log-parser', log.name, *args],
                text=True, timeout=5,
            ).strip()

    def test_epoch_parser_accepts_legacy_and_local_offsets(self):
        expected = str(int(datetime.datetime(2026, 9, 7, 0, 0, 0,
                           tzinfo=datetime.timezone.utc).timestamp() * 1000))
        for timestamp in ['2026-09-07T00:00:00.000Z',
                          '2026-09-07T08:00:00.000+08:00',
                          '2026-09-06T19:00:00.000-05:00',
                          '2026-09-07T05:45:00+05:45']:
            with self.subTest(timestamp=timestamp):
                result = self.invoke(DUAL, 'log_first_event_epoch_ms',
                                     timestamp + ' INFO event="ready"', 'ready')
                self.assertEqual(result, expected)

    def test_first_path_parser_preserves_legacy_and_structured_records(self):
        for value in ['Some("relay")', '"relay"']:
            self.assertEqual(self.invoke(DUAL, 'log_first_event_path',
                'INFO event="first" path=' + value, 'first'), 'relay')

    def test_reason_parser_preserves_legacy_and_structured_records(self):
        for value in ['Some("peer_offline")', '"peer_offline"']:
            self.assertEqual(self.invoke(NAT, 'node_failure_code',
                'relay_unavailable_or_first_packet_expired reason_code=' + value),
                'peer_offline')

    def test_production_availability_accepts_nonduplicated_local_timestamp_records(self):
        path = ROOT / 'scripts/dual-end/production-availability-parser.py'
        spec = importlib.util.spec_from_file_location('production_availability', path)
        parser = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(parser)
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8') as log:
            log.write('2026-09-07T08:00:00.000+08:00 INFO event="relay_transport_ready_peer" '
                      't_ms=100 detail="peer=air generation=7"\n')
            log.write('2026-09-07T08:00:00.040+08:00 INFO event="first_real_business_ingress" '
                      't_ms=140 detail="peer=air generation=7" path="relay"\n')
            log.flush()
            self.assertEqual(parser.first_business_info(log.name, 'air'), 'relay|40|7|ok')


if __name__ == '__main__':
    unittest.main()
