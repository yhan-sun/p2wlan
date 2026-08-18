part of '../diagnostics_page.dart';

/// User-actionable issues only. Raw technical strings never appear here; any
/// redacted technical detail lives in [DiagnosticIssue.technicalDetail] for the
/// advanced section.
class _IssuesPanel extends StatelessWidget {
  const _IssuesPanel({required this.issues});

  final List<DiagnosticIssue> issues;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final hasBad = issues.any(
      (issue) => issue.severity == DiagnosticSeverity.bad,
    );
    return AppPanel(
      title: strings.diagnosticIssues,
      trailing: StatusBadge(
        label: issues.isEmpty ? strings.noActionNeeded : strings.needsAttention,
        tone: issues.isEmpty
            ? StatusTone.good
            : hasBad
            ? StatusTone.bad
            : StatusTone.warn,
      ),
      child: issues.isEmpty
          ? _IssueRow(
              issue: DiagnosticIssue(
                title: strings.noActionNeeded,
                detail: strings.diagnosticNoIssues,
                severity: DiagnosticSeverity.good,
              ),
            )
          : Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                for (var index = 0; index < issues.length; index++) ...[
                  _IssueRow(issue: issues[index]),
                  if (index != issues.length - 1)
                    Divider(
                      color: Theme.of(context).colorScheme.outlineVariant,
                    ),
                ],
              ],
            ),
    );
  }
}

class _IssueRow extends StatelessWidget {
  const _IssueRow({required this.issue});

  final DiagnosticIssue issue;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = _tonePanelColors(context, _severityTone(issue.severity));
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.only(top: 1),
            child: Icon(
              issue.severity == DiagnosticSeverity.good
                  ? Icons.check_circle_outline
                  : Icons.info_outline_rounded,
              color: colors.text,
              size: 18,
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  issue.title,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface,
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  issue.detail,
                  style: TextStyle(
                    color: theme.colorScheme.onSurfaceVariant,
                    fontSize: 12,
                    height: 1.35,
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
