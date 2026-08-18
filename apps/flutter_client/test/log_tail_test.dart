import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/shared/log_tail.dart';

void main() {
  late Directory tmp;

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('p2wlan_tail_');
  });
  tearDown(() async {
    if (await tmp.exists()) await tmp.delete(recursive: true);
  });

  File f(String name, String content) =>
      File('${tmp.path}/$name')..writeAsStringSync(content);

  test('small file returns all lines (within window)', () async {
    final file = f('small.log', 'a\nb\nc\n');
    final out = await tailLines(file, lines: 120);
    expect(out.split('\n'), ['a', 'b', 'c']);
  });

  test('returns only the last [lines] for a large file', () async {
    final lines = List.generate(1000, (i) => 'line-$i');
    final file = f('big.log', lines.join('\n'));
    final out = await tailLines(file, lines: 10);
    expect(out.split('\n'), List.generate(10, (i) => 'line-${990 + i}'));
  });

  test(
    'memory is bounded by maxBytes even when maxBytes < file size',
    () async {
      // ~3000 lines * ~10 bytes = ~30KB. Requesting maxBytes=1024 must not
      // throw and must return only lines from the last ~1KB window.
      final lines = List.generate(3000, (i) => 'xxxxx-$i');
      final file = f('mem.log', lines.join('\n'));
      final out = await tailLines(file, lines: 5, maxBytes: 1024);
      final outLines = out.split('\n');
      expect(outLines.length, lessThanOrEqualTo(5));
      // The returned lines must be the tail of the file (high line numbers).
      final last = outLines.last;
      expect(last, contains('2999'));
    },
  );

  test('a partial first line at the byte boundary is dropped', () async {
    // ~40-byte lines; request a 1KB window so the boundary lands mid-line.
    final lines = List.generate(2000, (i) => 'value-${'y' * 30}-$i');
    final file = f('partial.log', lines.join('\n'));
    final out = await tailLines(file, lines: 120, maxBytes: 1024);
    final outLines = out.split('\n');
    // Every returned line must be a complete "value-...-N" line: the truncated
    // boundary fragment is dropped, so no line is missing its trailing number.
    expect(outLines, isNotEmpty);
    for (final l in outLines) {
      expect(
        RegExp(r'^value-y+-\d+$').hasMatch(l),
        isTrue,
        reason: 'line should be complete: $l',
      );
    }
  });

  test('empty and missing files return empty string', () async {
    expect(await tailLines(File('${tmp.path}/nope.log')), '');
    final empty = f('empty.log', '');
    expect(await tailLines(empty), '');
  });
}
