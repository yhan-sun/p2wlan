String dash(String? value) {
  if (value == null || value.trim().isEmpty) return '-';
  return value;
}

String shortId(String value) {
  if (value.length <= 12) return dash(value);
  return '${value.substring(0, 12)}...';
}

String formatBool(bool value) => value ? 'yes' : 'no';

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

String formatLatency(int? latencyMs) {
  if (latencyMs == null) return '-';
  return '$latencyMs ms';
}

String formatDateTime(DateTime? value) {
  if (value == null) return '-';
  final local = value.toLocal();
  String two(int n) => n.toString().padLeft(2, '0');
  return '${two(local.hour)}:${two(local.minute)}:${two(local.second)}';
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
      return path.isEmpty ? '-' : path;
  }
}
