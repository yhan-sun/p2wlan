#!/usr/bin/env python3
import datetime
import importlib.util
import pathlib
import json
import os
import shlex
import signal
import sys
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

# These are controlled function-boundary processes, not HTTP/NAT acceptance.
_PAIR_CHILD = r"""
import json
import os
from pathlib import Path
import sys
import time

root = Path(sys.argv[1])
arguments = sys.argv[2:]
if len(arguments) != 13:
    raise RuntimeError('unexpected request argument count')
role, sequence, side = arguments[:3]
if side not in ('a', 'b') or role != 'http-barrier-1-' + side or sequence != '1':
    raise RuntimeError('request role/sequence/side mismatch')
ends = [int(value) for value in arguments[4:7]]
start = time.monotonic_ns()
cutoff = min(ends)
if start // 1_000_000 >= cutoff:
    raise RuntimeError('request entered after its fixed input end')

def new_json(path, value):
    temporary = path.with_name(path.name + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(value, output, sort_keys=True)
        output.write('\n')
    os.replace(temporary, path)

record = {'pid': os.getpid(), 'ppid': os.getppid(), 'side': side,
          'entered_ns': start, 'arguments': arguments, 'fixed_ends_ms': ends}
new_json(root / (side + '.entered.json'), record)
other = root / (('b' if side == 'a' else 'a') + '.entered.json')
while not other.is_file():
    if time.monotonic_ns() // 1_000_000 >= cutoff:
        raise RuntimeError('other endpoint did not enter before the same fixed end')
    time.sleep(0.005)
peer = json.loads(other.read_text())
if peer['side'] == side or peer['pid'] == os.getpid() or peer['ppid'] != os.getppid():
    raise RuntimeError('handshake identities do not describe two owned children')
metadata = Path(arguments[12])
with metadata.open('x') as output:
    os.fchmod(output.fileno(), 0o600)
    output.write('1\n200\n\n')
new_json(Path(arguments[10]), {'fixture_only': True, 'side': side})
record['peer_entered_ns'] = peer['entered_ns']
record['ended_ns'] = time.monotonic_ns()
new_json(root / (side + '.ended.json'), record)
"""

_EXHAUST_INPUT_CHILD = r"""
import json
import os
from pathlib import Path
import sys
import time

root = Path(sys.argv[1])
request_timeout = int(sys.argv[2])
ends = [int(value) for value in sys.argv[3:6]]
start = time.monotonic_ns()
cutoff = min(ends)
if not 0 < cutoff - start // 1_000_000 <= 1000:
    raise RuntimeError('first bounded input was not entered within its original one-second window')
with (root / 'fetch-called').open('x') as output:
    os.fchmod(output.fileno(), 0o600)
    output.write('first\n')
while time.monotonic_ns() // 1_000_000 < cutoff:
    remaining = (cutoff * 1_000_000 - time.monotonic_ns()) / 1_000_000_000
    if remaining > 0:
        time.sleep(min(remaining, 0.01))
record = {'fixture_only': True, 'request_timeout': request_timeout,
          'fixed_ends_ms': ends, 'entered_ns': start,
          'ended_ns': time.monotonic_ns(), 'input_end_ms': cutoff}
with (root / 'fetch-ended.json').open('x') as output:
    os.fchmod(output.fileno(), 0o600)
    json.dump(record, output, sort_keys=True)
    output.write('\n')
"""


def bounded_pair_shell(program, root):
    """Use the existing clock harness' 4s protocol/1s infra teardown limits."""
    path = root / 'controller.sh'
    with path.open('x') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(program)
    process = subprocess.Popen(
        ['/bin/bash', str(path)], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True,
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
    )
    try:
        stdout, stderr = process.communicate(timeout=4)
    except subprocess.TimeoutExpired as error:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate(timeout=1)
        raise AssertionError('pair fixture protocol timeout; infra cleanup is not acceptance') from error
    for name, payload in (('stdout.log', stdout), ('stderr.log', stderr)):
        with (root / name).open('xb') as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(payload)
    if len(stdout) > 256 * 1024 or len(stderr) > 256 * 1024:
        raise AssertionError('pair fixture output exceeded its bounded diagnostic capacity')
    return process.returncode, stdout.decode(), stderr.decode()


def capture_window_harness(test):
    # A module alias is intentional: unittest discovery must not rediscover
    # the imported TestCase. We invoke only run_shell, never an old test method.
    path = ROOT / 'scripts/nat-sim/test_capture_window_observation.py'
    spec = importlib.util.spec_from_file_location('compat_capture_window_harness', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    harness = module.CaptureWindowObservationTests()
    harness._testMethodName = test._testMethodName
    test.addCleanup(harness.doCleanups)
    return harness


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

    def test_nat_barrier_status_fetches_both_nodes_concurrently(self):
        pair = shell_function(NAT, 'fetch_relay_barrier_status_pair')
        with tempfile.TemporaryDirectory(prefix='p2wlan-log-compat-pair-') as location:
            root = pathlib.Path(location)
            prelude = '\n'.join([
                'set -euxo pipefail', 'umask 077',
                'ROOT_DIR=' + shlex.quote(str(ROOT)),
                'ROUND_DIR=' + shlex.quote(str(root)),
                'PIDS=(); RELAY_PIDS=(); overall=0',
                'unset ROUND_CLOCK_ORIGIN_MONOTONIC_MS ROUND_CLOCK_ORIGIN_UNIX_MS '
                'ROUND_CLOCK_ORIGIN_UNIX_S ROUND_CLOCK_ORIGIN_SECONDS',
                'source "$ROOT_DIR/scripts/nat-sim/round_cleanup.sh"',
                'round_init', 'unset SECONDS; SECONDS=100',
                'ROUND_DEADLINE=102; WORK_DEADLINE=102',
                'NODE_A_RUNTIME="$ROUND_DIR/a-runtime"; NODE_B_RUNTIME="$ROUND_DIR/b-runtime"',
                'DIAG_A_PORT=12345; DIAG_B_PORT=12346',
                'fetch_required_json() { :; }',
                'p2wlan_diagnostics_curl() { :; }',
                'p2wlan_read_diagnostics_token() { :; }',
                shell_function(NAT, 'deadline_remaining_s'),
                'round_http_exec_request() { exec ' + shlex.quote(sys.executable)
                + ' -c ' + shlex.quote(_PAIR_CHILD) + ' "$ROUND_DIR" "$@"; }',
                pair,
                'fixed_end=$(( $(_round_now) + 1000 ))',
                'fetch_relay_barrier_status_pair 1 "$fixed_end" "$fixed_end" "$fixed_end"',
                '_round_owner_lines > "$ROUND_DIR/owners.tsv"',
                'printf "%s\\t%s\\t%s\\n" "$$" "${#PIDS[@]}" "$_ROUND_HTTP_PAIR_SEQUENCE" '
                '> "$ROUND_DIR/controller.tsv"',
                'printf "%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n" '
                '"$BARRIER_FETCH_A_OK" "$BARRIER_FETCH_A_HTTP" "$BARRIER_FETCH_A_REASON" '
                '"$BARRIER_FETCH_B_OK" "$BARRIER_FETCH_B_HTTP" "$BARRIER_FETCH_B_REASON" '
                '> "$ROUND_DIR/metadata.tsv"',
            ]) + '\n'
            status, _, trace = bounded_pair_shell(prelude, root)
            self.assertEqual(status, 0, trace)
            caller, pending, sequence = (root / 'controller.tsv').read_text().strip().split('\t')
            self.assertEqual((pending, sequence), ('0', '1'))
            owners = [line.split('\t') for line in (root / 'owners.tsv').read_text().splitlines()]
            self.assertEqual(len(owners), 2)
            records = {side: json.loads((root / (side + '.ended.json')).read_text())
                       for side in ('a', 'b')}
            self.assertNotEqual(records['a']['pid'], records['b']['pid'])
            self.assertLessEqual(max(row['entered_ns'] for row in records.values()),
                                 min(row['ended_ns'] for row in records.values()))
            for side, row in records.items():
                self.assertEqual(row['ppid'], int(caller))
                self.assertEqual(row['arguments'][:4], ['http-barrier-1-' + side, '1', side, '1'])
                self.assertLess(row['entered_ns'] // 1_000_000, min(row['fixed_ends_ms']))
                self.assertEqual(next(owner for owner in owners if owner[0].endswith('-' + side)),
                                 ['http-barrier-1-' + side, str(row['pid']), '1', '0', '0'])
                registered = '+ round_register_process http-barrier-1-' + side + ' ' + str(row['pid'])
                waited = '+ wait ' + str(row['pid'])
                recorded = '+ round_record_wait ' + str(row['pid']) + ' 0'
                for command in (registered, waited, recorded):
                    self.assertEqual(trace.splitlines().count(command), 1, trace)
                self.assertLess(trace.splitlines().index(registered), trace.splitlines().index(waited))
                self.assertLess(trace.splitlines().index(waited), trace.splitlines().index(recorded))
            self.assertEqual((root / 'metadata.tsv').read_text(), '1\t200\t\t1\t200\t\n')
            self.assertFalse((root / '.barrier-a-fetch').exists())
            self.assertFalse((root / '.barrier-b-fetch').exists())

    def test_nat_barrier_keeps_original_deadline_instead_of_extending_it(self):
        harness = capture_window_harness(self)
        prefix = ('unset ROUND_CLOCK_ORIGIN_MONOTONIC_MS ROUND_CLOCK_ORIGIN_UNIX_MS '
                  'ROUND_CLOCK_ORIGIN_UNIX_S ROUND_CLOCK_ORIGIN_SECONDS\n'
                  + shell_function(NAT, 'deadline_pause') + '\n')
        for label, stage, round_end, work_end in (('stage-zero', 100, 120, 120),
                                                  ('round-zero', 120, 100, 120),
                                                  ('work-zero', 120, 120, 100)):
            with self.subTest(bound=label):
                body = (prefix + 'ROUND_DEADLINE=' + str(round_end) + '\nWORK_DEADLINE='
                        + str(work_end) + '\n'
                        'fetch_relay_barrier_status_pair() { touch "$ROUND_DIR/unexpected-fetch"; return 1; }\n'
                        'wait_for_relay_confirmation_barrier ' + str(stage) + '\n'
                        'printf "%s\\t%s\\n" "$ROUND_DEADLINE" "$WORK_DEADLINE"')
                result = harness.run_shell(body, label, barrier=True)
                self.assertEqual(result[0], 0, result[4])
                self.assertFalse((result[1] / 'unexpected-fetch').exists())
                self.assertEqual(result[2]['result'], 'barrier_timeout')
                footer = json.loads((result[1] / 'relay-barrier.readiness.json').read_text())
                self.assertEqual((footer['result'], footer['reason_code']),
                                 ('barrier_timeout', 'relay_peer_confirmation_timeout'))
                self.assertEqual(result[3].strip(), str(round_end) + '\t' + str(work_end))
        body = prefix + '\n'.join([
            'touch "$ROUND_DIR/node-a.log" "$ROUND_DIR/node-b.log"',
            'node_task_health_ok() { printf "1\\n"; }',
            'fetch_relay_barrier_status_pair() {',
            '  ' + shlex.quote(sys.executable) + ' -c ' + shlex.quote(_EXHAUST_INPUT_CHILD)
            + ' "$ROUND_DIR" "$@"',
            '  BARRIER_FETCH_A_OK=1; BARRIER_FETCH_B_OK=1',
            '  BARRIER_FETCH_A_HTTP=200; BARRIER_FETCH_B_HTTP=200',
            '  BARRIER_FETCH_A_REASON=""; BARRIER_FETCH_B_REASON=""',
            '}',
            'wait_for_relay_confirmation_barrier 102',
            'printf "%s\\t%s\\n" "$ROUND_DEADLINE" "$WORK_DEADLINE"',
        ])
        result = harness.run_shell(body, 'later-poll', barrier=True)
        self.assertEqual(result[0], 0, result[4])
        witness = json.loads((result[1] / 'fetch-ended.json').read_text())
        self.assertEqual((result[1] / 'fetch-called').read_text(), 'first\n')
        self.assertLess(witness['entered_ns'] // 1_000_000, witness['input_end_ms'])
        self.assertGreaterEqual(witness['ended_ns'] // 1_000_000, witness['input_end_ms'])
        self.assertEqual(witness['input_end_ms'], min(witness['fixed_ends_ms']))
        self.assertLess(witness['fixed_ends_ms'][0], min(witness['fixed_ends_ms'][1:]))
        self.assertEqual(int(result[2]['end']), witness['fixed_ends_ms'][1])
        self.assertEqual(result[3].strip(), '120\t120')
        self.assertEqual(result[2]['result'], 'barrier_timeout')
        footer = json.loads((result[1] / 'relay-barrier.readiness.json').read_text())
        self.assertEqual((footer['result'], footer['reason_code']),
                         ('barrier_timeout', 'relay_peer_confirmation_timeout'))

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
