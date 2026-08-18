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
typedef _PermissionCheck = PermissionCheck;

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

/// Tone surface colors for overview/issue surfaces. Reuses the existing
/// semantic status tokens (same mapping as StatusBadge / dashboard).
({Color bg, Color border, Color text}) _tonePanelColors(
  BuildContext context,
  StatusTone tone,
) {
  final theme = Theme.of(context);
  final isDark = theme.brightness == Brightness.dark;
  if (isDark) {
    return switch (tone) {
      StatusTone.good => (
        bg: AppTokens.colorDarkGoodBg,
        border: AppTokens.colorDarkGoodBorder,
        text: AppTokens.colorDarkGoodText,
      ),
      StatusTone.warn => (
        bg: AppTokens.colorDarkWarnBg,
        border: AppTokens.colorDarkWarnBorder,
        text: AppTokens.colorDarkWarnText,
      ),
      StatusTone.bad => (
        bg: AppTokens.colorDarkBadBg,
        border: AppTokens.colorDarkBadBorder,
        text: AppTokens.colorDarkBadText,
      ),
      StatusTone.neutral => (
        bg: theme.colorScheme.surfaceContainerHighest,
        border: theme.colorScheme.outline,
        text: theme.colorScheme.onSurfaceVariant,
      ),
    };
  }
  return switch (tone) {
    StatusTone.good => (
      bg: AppTokens.colorGoodBg,
      border: AppTokens.colorGoodBorder,
      text: AppTokens.colorGoodText,
    ),
    StatusTone.warn => (
      bg: AppTokens.colorWarnBg,
      border: AppTokens.colorWarnBorder,
      text: AppTokens.colorWarnText,
    ),
    StatusTone.bad => (
      bg: AppTokens.colorBadBg,
      border: AppTokens.colorBadBorder,
      text: AppTokens.colorBadText,
    ),
    StatusTone.neutral => (
      bg: theme.colorScheme.surfaceContainerHighest,
      border: theme.colorScheme.outline,
      text: theme.colorScheme.onSurfaceVariant,
    ),
  };
}

StatusTone _severityTone(DiagnosticSeverity severity) => switch (severity) {
  DiagnosticSeverity.good => StatusTone.good,
  DiagnosticSeverity.warning => StatusTone.warn,
  DiagnosticSeverity.bad => StatusTone.bad,
  DiagnosticSeverity.neutral => StatusTone.neutral,
};
