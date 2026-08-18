part of '../diagnostics_page.dart';

/// The three user-value checks: service, control service, device connections.
class _ChecksPanel extends StatelessWidget {
  const _ChecksPanel({required this.checks});

  final List<DiagnosticCheck> checks;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AppPanel(
      title: strings.healthChecks,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          for (var index = 0; index < checks.length; index++) ...[
            _CheckRow(check: checks[index]),
            if (index != checks.length - 1)
              Divider(color: Theme.of(context).colorScheme.outlineVariant),
          ],
        ],
      ),
    );
  }
}

class _CheckRow extends StatelessWidget {
  const _CheckRow({required this.check});

  final DiagnosticCheck check;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = _tonePanelColors(context, _severityTone(check.severity));
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 9),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.only(top: 2),
            child: Icon(
              switch (check.severity) {
                DiagnosticSeverity.good => Icons.check_circle_outline,
                DiagnosticSeverity.warning ||
                DiagnosticSeverity.bad => Icons.warning_amber_rounded,
                DiagnosticSeverity.neutral => Icons.help_outline_rounded,
              },
              size: 18,
              color: colors.text,
            ),
          ),
          const SizedBox(width: AppTokens.space10),
          Expanded(
            child: Text(
              check.title,
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w600,
                color: theme.colorScheme.onSurface,
              ),
            ),
          ),
          const SizedBox(width: AppTokens.space12),
          Flexible(
            child: Text(
              check.value,
              textAlign: TextAlign.end,
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w600,
                color: colors.text,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
