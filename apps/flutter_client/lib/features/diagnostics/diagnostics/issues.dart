part of '../diagnostics_page.dart';

/// User-actionable issues only, placed before the basic checks. Rendered only
/// when there is at least one issue — a healthy page never shows a redundant
/// "no issues" card. Each issue may offer one safe, real action (recheck,
/// view devices, open settings); issues without a real operation get a plain
/// explanation instead of a fabricated "auto fix".
class _IssuesPanel extends StatelessWidget {
  const _IssuesPanel({
    required this.issues,
    required this.refreshing,
    this.onRecheck,
    this.onOpenDevices,
    this.onOpenSettings,
  });

  final List<DiagnosticIssue> issues;
  final bool refreshing;
  final VoidCallback? onRecheck;
  final VoidCallback? onOpenDevices;
  final VoidCallback? onOpenSettings;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AppPanel(
      title: strings.needsAttention,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          for (var index = 0; index < issues.length; index++) ...[
            if (index != 0) const SizedBox(height: AppTokens.space10),
            _IssueRow(
              issue: issues[index],
              refreshing: refreshing,
              onRecheck: onRecheck,
              onOpenDevices: onOpenDevices,
              onOpenSettings: onOpenSettings,
            ),
          ],
        ],
      ),
    );
  }
}

class _IssueRow extends StatelessWidget {
  const _IssueRow({
    required this.issue,
    required this.refreshing,
    this.onRecheck,
    this.onOpenDevices,
    this.onOpenSettings,
  });

  final DiagnosticIssue issue;
  final bool refreshing;
  final VoidCallback? onRecheck;
  final VoidCallback? onOpenDevices;
  final VoidCallback? onOpenSettings;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final colors = _tonePanelColors(context, _severityTone(issue.severity));
    final action = _issueAction(strings);
    return Container(
      decoration: BoxDecoration(
        color: colors.bg,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: colors.border),
      ),
      padding: const EdgeInsets.all(AppTokens.space12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Padding(
                padding: const EdgeInsets.only(top: 1),
                child: Icon(
                  issue.severity == DiagnosticSeverity.bad
                      ? Icons.error_outline_rounded
                      : Icons.info_outline_rounded,
                  color: colors.text,
                  size: 18,
                ),
              ),
              const SizedBox(width: AppTokens.space10),
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
          if (action != null) ...[
            const SizedBox(height: AppTokens.space10),
            Align(alignment: Alignment.centerLeft, child: action),
          ],
        ],
      ),
    );
  }

  /// A safe, real action for this issue kind — or null when no real operation
  /// exists (relay, critical task, control plane, service health).
  Widget? _issueAction(AppStrings strings) {
    switch (issue.kind) {
      case DiagnosticIssueKind.stale:
      case DiagnosticIssueKind.serviceUnavailable:
      case DiagnosticIssueKind.statusUnavailable:
        if (onRecheck == null) return null;
        return OutlinedButton.icon(
          onPressed: refreshing ? null : onRecheck,
          icon: const Icon(Icons.refresh_rounded, size: 16),
          label: Text(strings.checkAgain),
        );
      case DiagnosticIssueKind.peerPath:
        if (onOpenDevices == null) return null;
        return OutlinedButton.icon(
          onPressed: onOpenDevices,
          icon: const Icon(Icons.hub_outlined, size: 16),
          label: Text(strings.openDevices),
        );
      case DiagnosticIssueKind.reauthRequired:
        if (onOpenSettings == null) return null;
        return OutlinedButton.icon(
          onPressed: onOpenSettings,
          icon: const Icon(Icons.settings_outlined, size: 16),
          label: Text(strings.openSettings),
        );
      case DiagnosticIssueKind.serviceHealth:
      case DiagnosticIssueKind.criticalTask:
      case DiagnosticIssueKind.controlDisconnected:
      case DiagnosticIssueKind.relay:
        // No invented auto-fix: explain, do not fake an operation.
        return null;
    }
  }
}
