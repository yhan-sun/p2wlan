part of '../diagnostics_page.dart';

/// First visual layer: "is P2WLAN OK right now?" answered with an overall
/// state, a user-facing title, and a plain-language detail line.
///
/// The quiet "recheck" action lives here (low weight, bottom-left), never a
/// full-page spinner — last-known information stays readable while refreshing.
class _SystemStatusCard extends StatelessWidget {
  const _SystemStatusCard({
    required this.model,
    required this.refreshing,
    required this.onRecheck,
  });

  final DiagnosticsModel model;
  final bool refreshing;
  final VoidCallback? onRecheck;

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
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // "System status" is the page's first visual — not a copy/refresh bar.
        _AdvancedSectionHeader(title: strings.systemStatus),
        const SizedBox(height: AppTokens.space10),
        Container(
          decoration: BoxDecoration(
            color: colors.bg,
            borderRadius: BorderRadius.circular(AppTokens.radiusLg),
            border: Border.all(color: colors.border),
          ),
          padding: const EdgeInsets.all(AppTokens.space16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Padding(
                    padding: const EdgeInsets.only(top: 1),
                    child: Icon(icon, size: 26, color: colors.text),
                  ),
                  const SizedBox(width: AppTokens.space12),
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
              const SizedBox(height: AppTokens.space12),
              // Recheck is deliberately a small low-weight outline action —
              // never the page's first visual.
              OutlinedButton.icon(
                onPressed: onRecheck,
                icon: refreshing
                    ? const SizedBox.square(
                        dimension: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.refresh_rounded, size: 16),
                label: Text(
                  refreshing ? strings.rechecking : strings.checkAgain,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }
}
