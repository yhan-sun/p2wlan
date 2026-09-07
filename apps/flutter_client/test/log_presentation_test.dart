import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/shared/log_presentation.dart';

void main() {
  test('UTC and offset timestamps represent the same instant locally', () {
    final instant = DateTime.utc(2026, 9, 7, 1, 2, 3, 456);
    final expected = '${formatLocalLogTimestamp(instant)} INFO ready';
    for (final raw in [
      '2026-09-07T01:02:03.456Z INFO ready',
      '2026-09-07T09:02:03.456+08:00 INFO ready',
      '2026-09-06T20:02:03.456-05:00 INFO ready',
      '2026-09-07T06:47:03.456+05:45 INFO ready',
    ]) {
      expect(presentDaemonLogs(raw), expected);
    }
  });

  test('unknown and malformed lines are preserved rather than guessed', () {
    const raw =
        'not-a-timestamp INFO ready\n2026-99-99 nonsense\n  stack frame';
    expect(presentDaemonLogs(raw), raw);
  });

  test(
    'only consecutive identical records collapse and identity is retained',
    () {
      const raw =
          '2026-09-07T01:00:00Z WARN peer=a reason=timeout\n'
          '2026-09-07T01:00:01Z WARN peer=a reason=timeout\n'
          '2026-09-07T01:00:02Z WARN peer=b reason=timeout\n'
          '2026-09-07T01:00:03Z WARN peer=a reason=timeout';
      final display = presentDaemonLogs(raw);
      expect(display, contains('Repeated 2 times'));
      expect(display, contains('peer=b'));
      expect(display, isNot(contains('Repeated 3 times')));
      expect(
        presentDaemonLogs(raw, collapseRepeats: false),
        isNot(contains('Repeated')),
      );
    },
  );

  test('level filters and search do not remove unknown diagnostic lines', () {
    const raw =
        '2026-09-07T01:00:00Z DEBUG peer=a poll\n'
        '2026-09-07T01:00:01Z INFO peer=a ready\n'
        '2026-09-07T01:00:02Z ERROR peer=b failed\n'
        '  useful stack frame';
    expect(presentDaemonLogs(raw), isNot(contains('DEBUG')));
    final warnings = presentDaemonLogs(raw, filter: LogLevelFilter.warnings);
    expect(warnings, isNot(contains('INFO')));
    expect(warnings, contains('ERROR'));
    expect(warnings, contains('useful stack frame'));
    final selected = presentDaemonLogs(
      raw,
      filter: LogLevelFilter.all,
      search: 'PEER=A',
    );
    expect(selected, contains('DEBUG'));
    expect(selected, contains('INFO'));
    expect(selected, isNot(contains('peer=b')));
  });

  test(
    'formatter receives each original instant including cross-day offsets',
    () {
      final instants = <DateTime>[];
      presentDaemonLogs(
        '2026-09-07T00:15:00+05:45 INFO one\n'
        '2026-09-07T00:15:00-03:30 INFO two',
        timestampFormatter: (value) {
          instants.add(value.toUtc());
          return 'local';
        },
      );
      expect(instants, [
        DateTime.utc(2026, 9, 6, 18, 30),
        DateTime.utc(2026, 9, 7, 3, 45),
      ]);
    },
  );
}
