enum LogLevelFilter { information, warnings, all }

final _logTimestamp = RegExp(
  r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))(?=\s)',
);
final _logLevel = RegExp(r'^\s*(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR)\b');

String formatLocalLogTimestamp(DateTime instant) {
  final local = instant.toLocal();
  String pad(int value, [int width = 2]) =>
      value.toString().padLeft(width, '0');
  final offset = local.timeZoneOffset;
  final minutes = offset.inMinutes.abs();
  final sign = offset.isNegative ? '-' : '+';
  return '${pad(local.year, 4)}-${pad(local.month)}-${pad(local.day)}T'
      '${pad(local.hour)}:${pad(local.minute)}:${pad(local.second)}.'
      '${pad(local.millisecond, 3)}$sign${pad(minutes ~/ 60)}:${pad(minutes % 60)}';
}

String presentDaemonLogs(
  String raw, {
  LogLevelFilter filter = LogLevelFilter.information,
  String search = '',
  bool collapseRepeats = true,
  bool isZh = false,
  String Function(DateTime)? timestampFormatter,
}) {
  final format = timestampFormatter ?? formatLocalLogTimestamp;
  final query = search.trim().toLowerCase();
  final entries =
      <({String original, String body, String display, bool visible})>[];
  for (final line in raw.split('\n')) {
    final match = _logTimestamp.firstMatch(line);
    final originalTime = match?.group(1);
    final time = originalTime == null ? null : DateTime.tryParse(originalTime);
    final body = time == null ? line : line.substring(match!.end);
    final level = _logLevel.firstMatch(body)?.group(0)?.trim();
    final accepted = switch (filter) {
      LogLevelFilter.all => true,
      LogLevelFilter.information => level != 'DEBUG' && level != 'TRACE',
      LogLevelFilter.warnings =>
        level == null ||
            level == 'WARN' ||
            level == 'WARNING' ||
            level == 'ERROR',
    };
    final matchesSearch = query.isEmpty || line.toLowerCase().contains(query);
    entries.add((
      original: line,
      body: body,
      display: time == null ? line : '${format(time)}$body',
      visible: accepted && matchesSearch,
    ));
  }
  final output = <String>[];
  for (var index = 0; index < entries.length; index++) {
    final entry = entries[index];
    if (!entry.visible) continue;
    var count = 1;
    if (collapseRepeats && entry.body.trim().isNotEmpty) {
      while (index + count < entries.length &&
          entries[index + count].visible &&
          entries[index + count].body == entry.body) {
        count += 1;
      }
    }
    if (count == 1) {
      output.add(entry.display);
    } else {
      final last = entries[index + count - 1];
      output.add(entry.display);
      output.add(
        isZh
            ? '  ↳ 连续重复 $count 次；最后一条：${last.display}'
            : '  ↳ Repeated $count times; last entry: ${last.display}',
      );
    }
    index += count - 1;
  }
  return output.join('\n');
}
