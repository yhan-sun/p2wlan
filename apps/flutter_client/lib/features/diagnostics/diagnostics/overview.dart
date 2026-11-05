part of '../diagnostics_page.dart';

/// First visual layer: "is P2WLAN OK right now?" answered with an overall
/// state, a user-facing title, and a plain-language detail line.
///
/// The conclusion stays readable while refreshing. Recheck and support actions
/// follow the actionable issues, keeping the result ahead of its tools.
class _SystemStatusCard extends StatelessWidget {
  const _SystemStatusCard({required this.model});

  final DiagnosticsModel model;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final tone = switch (model.overall) {
      DiagnosticOverall.healthy => StatusTone.good,
      DiagnosticOverall.attention =>
        model.issues.any((issue) => issue.severity == DiagnosticSeverity.bad)
            ? StatusTone.bad
            : StatusTone.warn,
      DiagnosticOverall.unavailable => StatusTone.neutral,
      DiagnosticOverall.stale => StatusTone.warn,
    };
    final colors = _tonePanelColors(context, tone);
    final icon = switch (model.overall) {
      DiagnosticOverall.healthy => Icons.check_circle_outline,
      DiagnosticOverall.attention => Icons.warning_amber_rounded,
      DiagnosticOverall.unavailable => Icons.monitor_heart_outlined,
      DiagnosticOverall.stale => Icons.schedule_rounded,
    };
    final c = P2WlanColors.of(context);
    return Container(
      key: const Key('diagnostics-system-status'),
      decoration: BoxDecoration(
        color: c.surface,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        border: Border.all(color: c.border),
      ),
      padding: const EdgeInsets.all(AppTokens.space16),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              color: colors.bg,
              borderRadius: BorderRadius.circular(AppTokens.radiusMd),
            ),
            child: Icon(icon, size: 24, color: colors.text),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  strings.systemStatus,
                  style: TextStyle(
                    fontSize: 12,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  model.title,
                  style: TextStyle(
                    fontSize: 18,
                    height: 1.3,
                    fontWeight: FontWeight.w700,
                    color: theme.colorScheme.onSurface,
                  ),
                ),
                const SizedBox(height: 6),
                Text(
                  model.detail,
                  style: TextStyle(
                    fontSize: 13,
                    height: 1.5,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _DiagnosticsActions extends StatelessWidget {
  const _DiagnosticsActions({
    required this.refreshing,
    required this.onRecheck,
    this.onCopySummary,
  });

  final bool refreshing;
  final VoidCallback? onRecheck;
  final VoidCallback? onCopySummary;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return Wrap(
      key: const Key('diagnostics-primary-actions'),
      spacing: 12,
      runSpacing: 4,
      children: [
        OutlinedButton.icon(
          onPressed: onRecheck,
          icon: refreshing
              ? const SizedBox.square(
                  dimension: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.refresh_rounded, size: 16),
          label: Text(refreshing ? strings.rechecking : strings.checkAgain),
        ),
        if (onCopySummary != null)
          TextButton.icon(
            onPressed: onCopySummary,
            icon: const Icon(Icons.copy_all_outlined, size: 17),
            label: Text(strings.copyDiagnosticsSummary),
          ),
      ],
    );
  }
}
