part of '../diagnostics_page.dart';

/// First visual layer: "is P2WLAN OK right now?" answered with an overall
/// state, a user-facing title, and a plain-language detail line.
class _OverviewCard extends StatelessWidget {
  const _OverviewCard({required this.model});

  final DiagnosticsModel model;

  @override
  Widget build(BuildContext context) {
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
    return Container(
      decoration: BoxDecoration(
        color: colors.bg,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        border: Border.all(color: colors.border),
      ),
      padding: const EdgeInsets.all(16),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.only(top: 1),
            child: Icon(icon, size: 26, color: colors.text),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  model.title,
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w700,
                    color: theme.colorScheme.onSurface,
                  ),
                ),
                const SizedBox(height: 3),
                Text(
                  model.detail,
                  style: TextStyle(
                    fontSize: 13,
                    height: 1.4,
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
