part of '../diagnostics_page.dart';

class _LogPreview {
  const _LogPreview({
    required this.path,
    required this.content,
    required this.shownLineCount,
    this.error,
  });

  final String path;
  final String content;
  final int shownLineCount;
  final String? error;
}

// Permission types are provided by the shared, testable preflight module
// (core/capabilities/permission_preflight.dart). Private aliases keep the
// panel widgets stable.
typedef _PermissionSnapshot = PermissionPreflight;
typedef _PermissionCheck = PermissionCheck;

Future<_PermissionSnapshot> _checkPermissions() => runPermissionPreflight();

Future<_LogPreview> _loadLogPreview() async {
  const previewLines = 120;
  final path =
      '${defaultP2WlanLogDir().path}${Platform.pathSeparator}p2wlan-daemon.log';
  final file = File(path);
  try {
    if (!await file.exists()) {
      return _LogPreview(path: path, content: '', shownLineCount: 0);
    }
    // Bounded tail read: memory cost is O(preview window), never O(file size).
    // A 100 MB log previews identically cheaply to a small one.
    final content = await tailLines(file, lines: previewLines);
    // We only read a bounded window, so we do not (and cannot, without an
    // O(size) scan) report the total file line count. The shown count is
    // bounded by the window; the UI labels it accordingly.
    final shownLines = content.isEmpty ? 0 : content.split('\n').length;
    return _LogPreview(
      path: path,
      content: redactLines(content.split('\n')),
      shownLineCount: shownLines,
    );
  } catch (error) {
    return _LogPreview(
      path: path,
      content: '',
      shownLineCount: 0,
      error: 'Failed to read $path: $error',
    );
  }
}

JsonMap _map(dynamic value) {
  if (value is Map) return Map<String, dynamic>.from(value);
  return {};
}

String _value(dynamic value) {
  if (value == null) return '—';
  if (value is bool) return value ? 'yes' : 'no';
  if (value is num) return value.toString();
  if (value is Iterable) return value.join(', ');
  if (value is Map) return jsonEncode(value);
  final text = value.toString().trim();
  return text.isEmpty ? '—' : text;
}
