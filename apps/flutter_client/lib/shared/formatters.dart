String dash(String? value) {
  if (value == null || value.trim().isEmpty) return '—';
  return value;
}

String shortId(String value) {
  if (value.length <= 12) return dash(value);
  return '${value.substring(0, 12)}...';
}

String formatBool(bool value) => value ? 'yes' : 'no';

String formatOptionalBool(bool? value) =>
    value == null ? '—' : formatBool(value);

String formatInt(int value) => value.toString();

String formatBytes(int value) {
  const units = ['B', 'KB', 'MB', 'GB'];
  var size = value.toDouble();
  var index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  final text = index == 0 ? size.toStringAsFixed(0) : size.toStringAsFixed(1);
  return '$text ${units[index]}';
}

/// Formats an observed peer throughput using the compact units used by the
/// device lists. The value is the combined sent + received rate in bytes per
/// second; null means that two samples are not available yet.
String formatTransferRate(int? bytesPerSecond) {
  if (bytesPerSecond == null || bytesPerSecond < 0) return '—';

  const kilo = 1024.0;
  const mega = kilo * 1024;
  const giga = mega * 1024;
  final (value, unit) = switch (bytesPerSecond.toDouble()) {
    >= giga => (bytesPerSecond / giga, 'G/S'),
    >= mega => (bytesPerSecond / mega, 'M/S'),
    _ => (bytesPerSecond / kilo, 'K/S'),
  };
  final text = value == value.roundToDouble()
      ? value.toStringAsFixed(0)
      : value.toStringAsFixed(value >= 100 ? 0 : 1);
  return '$text $unit';
}

String formatLatency(int? latencyMs) {
  if (latencyMs == null) return '—';
  return '$latencyMs ms';
}

String formatDateTime(DateTime? value) {
  if (value == null) return '—';
  final local = value.toLocal();
  String two(int n) => n.toString().padLeft(2, '0');
  return '${two(local.hour)}:${two(local.minute)}:${two(local.second)}';
}

String formatDuration(Duration? value) {
  if (value == null) return '—';
  if (value.inMilliseconds < 1000) return '${value.inMilliseconds} ms';
  final seconds = value.inMilliseconds / 1000;
  return '${seconds.toStringAsFixed(1)} s';
}

String pathLabel(String path) {
  switch (path) {
    case 'direct':
      return 'Direct';
    case 'relay':
      return 'Relay';
    case 'direct_trial':
      return 'Direct trial';
    case 'offline':
      return 'Offline';
    default:
      return dash(path);
  }
}
