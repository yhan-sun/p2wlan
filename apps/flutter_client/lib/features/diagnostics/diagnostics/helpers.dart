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
  final dir = await resolveP2WlanLogDir();
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
  var path = '';
  try {
    final dir = await resolveP2WlanLogDir();
    path = '${dir.path}${Platform.pathSeparator}p2wlan-daemon.log';
    final file = File(path);
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

String _dash(String? value) {
  final trimmed = value?.trim() ?? '';
  return trimmed.isEmpty ? '—' : trimmed;
}

/// Section header used inside the Advanced disclosure (keeps technical areas
/// from turning into a stack of oversized cards).
class _AdvancedSectionHeader extends StatelessWidget {
  const _AdvancedSectionHeader({required this.title});

  final String title;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Row(
      children: [
        Container(
          width: 3,
          height: 14,
          decoration: BoxDecoration(
            color: theme.colorScheme.primary,
            borderRadius: BorderRadius.circular(2),
          ),
        ),
        const SizedBox(width: AppTokens.space8),
        Expanded(
          child: Text(
            title,
            style: TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.w600,
              color: theme.colorScheme.onSurface,
            ),
          ),
        ),
      ],
    );
  }
}

/// Compact label/value row used by the network & route and runtime panels.
class _KvRow extends StatelessWidget {
  const _KvRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final c = P2WlanColors.of(context);
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final labelText = Text(
            label,
            style: TextStyle(
              fontSize: 12,
              color: c.textSecondary,
              fontWeight: FontWeight.w600,
            ),
          );
          final valueText = Text(
            value,
            style: TextStyle(
              fontSize: 13,
              color: theme.colorScheme.onSurface,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          );
          if (constraints.maxWidth < 360) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [labelText, const SizedBox(height: 3), valueText],
            );
          }
          final labelWidth = constraints.maxWidth < 460 ? 112.0 : 140.0;
          return Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(width: labelWidth, child: labelText),
              Expanded(child: valueText),
            ],
          );
        },
      ),
    );
  }
}

/// Inline result banner for network actions (repair / restart success/failure).
/// Never a modal; quiet by default, error-tinted only when something failed.
class _NetworkMessage extends StatelessWidget {
  const _NetworkMessage({required this.message, this.isError = false});

  final String message;
  final bool isError;

  @override
  Widget build(BuildContext context) {
    final c = P2WlanColors.of(context);
    final colors = isError
        ? (bg: c.dangerSurface, border: c.dangerBorder, text: c.dangerText)
        : (bg: c.warningSurface, border: c.warningBorder, text: c.warningText);
    return DecoratedBox(
      decoration: BoxDecoration(
        color: colors.bg,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: colors.border),
      ),
      child: Padding(
        padding: const EdgeInsets.all(AppTokens.space12),
        child: Text(
          message,
          style: TextStyle(color: colors.text, fontSize: 13, height: 1.35),
        ),
      ),
    );
  }
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
