part of '../diagnostics_page.dart';

/// Bounded log preview used by the Recent Logs panel. Exposed so tests can
/// inject a loader via `DiagnosticsPage.logPreviewLoader`.
class DiagnosticsLogPreview {
  const DiagnosticsLogPreview({
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

Future<_PermissionSnapshot> _checkPermissions() => runPermissionPreflight();

Future<void> _openLogsDefault() async {
  final dir = defaultP2WlanLogDir();
  await dir.create(recursive: true);
  if (Platform.isMacOS) {
    await Process.start('open', [dir.path]);
  } else if (Platform.isWindows) {
    await Process.start('explorer', [dir.path]);
  } else {
    await Process.start('xdg-open', [dir.path]);
  }
}

Future<DiagnosticsLogPreview> _loadLogPreview() async {
  const previewLines = 120;
  final path =
      '${defaultP2WlanLogDir().path}${Platform.pathSeparator}p2wlan-daemon.log';
  final file = File(path);
  try {
    if (!await file.exists()) {
      return DiagnosticsLogPreview(path: path, content: '', shownLineCount: 0);
    }
    // Bounded tail read: memory cost is O(preview window), never O(file size).
    final content = await tailLines(file, lines: previewLines);
    final shownLines = content.isEmpty ? 0 : content.split('\n').length;
    return DiagnosticsLogPreview(
      path: path,
      content: content,
      shownLineCount: shownLines,
    );
  } catch (error) {
    return DiagnosticsLogPreview(
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

/// Tone surface colors for overview/issue surfaces. Reuses the same semantic
/// status palette as StatusBadge / dashboard via [P2WlanColors].
({Color bg, Color border, Color text}) _tonePanelColors(
  BuildContext context,
  StatusTone tone,
) {
  final c = P2WlanColors.of(context);
  return switch (tone) {
    StatusTone.good => (
      bg: c.successSurface,
      border: c.successBorder,
      text: c.successText,
    ),
    StatusTone.warn => (
      bg: c.warningSurface,
      border: c.warningBorder,
      text: c.warningText,
    ),
    StatusTone.bad => (
      bg: c.dangerSurface,
      border: c.dangerBorder,
      text: c.dangerText,
    ),
    StatusTone.neutral => (
      bg: c.neutralSurface,
      border: c.neutralBorder,
      text: c.neutralText,
    ),
  };
}

StatusTone _severityTone(DiagnosticSeverity severity) => switch (severity) {
  DiagnosticSeverity.good => StatusTone.good,
  DiagnosticSeverity.warning => StatusTone.warn,
  DiagnosticSeverity.bad => StatusTone.bad,
  DiagnosticSeverity.neutral => StatusTone.neutral,
};
