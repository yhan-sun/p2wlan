import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String? _daemonPath() {
  final configured = Platform.environment['P2WLAN_DAEMON_BIN'];
  if (configured != null && configured.trim().isNotEmpty) {
    return configured;
  }
  const fallback = '../../target/release/p2wlan-daemon.exe';
  return File(fallback).existsSync() ? fallback : null;
}

Future<ProcessResult> _runDaemon(String daemon, List<String> arguments) async {
  final result = await Process.run(
    daemon,
    arguments,
    stdoutEncoding: utf8,
    stderrEncoding: utf8,
  ).timeout(const Duration(seconds: 20));
  expect(
    result.exitCode,
    0,
    reason: 'daemon lifecycle command failed\n'
        'args=$arguments\nstdout=${result.stdout}\nstderr=${result.stderr}',
  );
  return result;
}

void main() {
  test(
    'release daemon survives repeated probe startup and clean exit',
    () async {
      final daemon = _daemonPath();
      expect(daemon, isNotNull, reason: 'P2WLAN_DAEMON_BIN was not provided');

      final seenPids = <int>{};
      for (var cycle = 0; cycle < 12; cycle++) {
        final result = await _runDaemon(daemon!, const ['--binary-probe']);
        final payload = jsonDecode(result.stdout as String) as Map<String, dynamic>;
        expect(payload['status'], 'ok', reason: 'cycle=$cycle payload=$payload');
        expect(payload['protocol_version'], 1);
        final pid = payload['pid'] as int?;
        expect(pid, isNotNull);
        expect(pid, greaterThan(0));
        expect(seenPids.add(pid!), isTrue, reason: 'cycle=$cycle reused pid=$pid');
      }
    },
    skip: !Platform.isWindows,
    timeout: const Timeout(Duration(minutes: 2)),
  );

  test(
    'release daemon tray source drains and exits cleanly across cycles',
    () async {
      final daemon = _daemonPath();
      expect(daemon, isNotNull, reason: 'P2WLAN_DAEMON_BIN was not provided');

      for (var cycle = 0; cycle < 8; cycle++) {
        final event = jsonEncode({
          'event_type': 'status',
          'sequence': cycle + 1,
          'emitted_at_ms': 1700000000000 + cycle,
          'connection_generation': cycle + 100,
          'payload': {'state': 'stopping', 'cycle': cycle},
        });
        final result = await _runDaemon(daemon!, [
          '--test-tray-event-source',
          '--test-tray-event',
          event,
          '--test-tray-event-count',
          '3',
          '--test-tray-event-delay-ms',
          '2',
        ]);
        final lines = const LineSplitter()
            .convert(result.stdout as String)
            .where((line) => line.trim().isNotEmpty)
            .toList(growable: false);
        expect(lines, hasLength(3), reason: 'cycle=$cycle lines=$lines');
        for (var index = 0; index < lines.length; index++) {
          final envelope = jsonDecode(lines[index]) as Map<String, dynamic>;
          final emitted = envelope['event'] as Map<String, dynamic>;
          expect(emitted['sequence'], cycle + index + 1);
          expect(emitted['connection_generation'], cycle + 100);
        }
      }
    },
    skip: !Platform.isWindows,
    timeout: const Timeout(Duration(minutes: 2)),
  );
}
