part of '../diagnostics_page.dart';

class _Summary extends StatelessWidget {
  const _Summary({required this.statusStore, required this.snapshot});

  final StatusStore statusStore;
  final DiagnosticsSnapshot? snapshot;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final health = snapshot?.health;
    return AppPanel(
      title: strings.summary,
      trailing: StatusBadge(
        label: statusStore.online ? strings.statusLoaded : strings.noSnapshot,
        tone: statusStore.online ? StatusTone.good : StatusTone.bad,
      ),
      child: Wrap(
        spacing: 24,
        runSpacing: 4,
        children: [
          MetricTile(
            label: 'GET /health',
            value: statusStore.healthReachable
                ? strings.reachable
                : strings.offline,
            detail: strings.statusMessage(statusStore.lastHealthError),
          ),
          MetricTile(
            label: 'GET /status',
            value: strings.endpointStatusLabel(
              statusReachable: statusStore.statusReachable,
              healthReachable: statusStore.healthReachable,
            ),
            detail: strings.statusMessage(statusStore.lastStatusError),
          ),
          MetricTile(
            label: strings.serviceHealth,
            value: health == null
                ? '—'
                : strings.healthStatusLabel(health.status),
          ),
          MetricTile(
            label: strings.controlConnected,
            value: strings.optionalBoolLabel(health?.controlConnected),
          ),
          MetricTile(
            label: strings.reauthRequired,
            value: strings.optionalBoolLabel(health?.reauthRequired),
          ),
          MetricTile(
            label: strings.udpSockets,
            value: snapshot == null ? '—' : formatInt(snapshot!.udpSocketCount),
          ),
          MetricTile(
            label: strings.socketPoolActive,
            value: strings.optionalBoolLabel(snapshot?.udpSocketPoolActive),
          ),
          MetricTile(
            label: strings.relayConnected,
            value: strings.optionalBoolLabel(snapshot?.relayConnected),
          ),
          MetricTile(
            label: strings.peerCount,
            value: snapshot == null
                ? '—'
                : formatInt(snapshot!.stats.totalPeers),
          ),
          MetricTile(
            label: strings.lastRefresh,
            value: formatDateTime(statusStore.lastFetchedAt),
          ),
          MetricTile(
            label: strings.requestDuration,
            value: formatDuration(statusStore.lastRequestDuration),
          ),
          if (statusStore.lastError != null)
            MetricTile(
              label: strings.lastError,
              value:
                  strings.statusMessage(statusStore.lastError) ??
                  statusStore.lastError!,
            ),
          if (health?.reason != null)
            MetricTile(label: strings.healthReason, value: health!.reason!),
        ],
      ),
    );
  }
}

class _IssuesPanel extends StatelessWidget {
  const _IssuesPanel({required this.statusStore, required this.snapshot});

  final StatusStore statusStore;
  final DiagnosticsSnapshot? snapshot;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final issues = _collectIssues(strings);
    return AppPanel(
      title: strings.diagnosticIssues,
      trailing: StatusBadge(
        label: issues.isEmpty ? strings.noActionNeeded : strings.needsAttention,
        tone: issues.isEmpty ? StatusTone.good : StatusTone.warn,
      ),
      child: issues.isEmpty
          ? _IssueRow(
              title: strings.noActionNeeded,
              detail: strings.diagnosticNoIssues,
              tone: StatusTone.good,
            )
          : Column(
              children: [
                for (var index = 0; index < issues.length; index++) ...[
                  issues[index],
                  if (index != issues.length - 1)
                    Divider(
                      color: Theme.of(context).colorScheme.outlineVariant,
                    ),
                ],
              ],
            ),
    );
  }

  List<_IssueRow> _collectIssues(AppStrings strings) {
    final issues = <_IssueRow>[];
    if (!statusStore.healthReachable) {
      issues.add(
        _IssueRow(
          title: 'GET /health',
          detail:
              strings.statusMessage(statusStore.lastHealthError) ??
              statusStore.lastHealthError ??
              strings.offline,
          tone: StatusTone.bad,
        ),
      );
    }
    if (statusStore.healthReachable && !statusStore.statusReachable) {
      issues.add(
        _IssueRow(
          title: 'GET /status',
          detail:
              strings.statusMessage(statusStore.lastStatusError) ??
              statusStore.lastStatusError ??
              strings.unavailable,
          tone: StatusTone.warn,
        ),
      );
    }

    final health = snapshot?.health;
    if (health?.reauthRequired == true) {
      issues.add(
        _IssueRow(
          title: strings.reauthRequired,
          detail: strings.issueReauthRequired,
          tone: StatusTone.bad,
        ),
      );
    }
    if (health != null && !health.controlConnected) {
      issues.add(
        _IssueRow(
          title: strings.controlPlane,
          detail: strings.issueControlDisconnected,
          tone: StatusTone.warn,
        ),
      );
    }
    final reason = health?.reason?.trim();
    if (reason != null && reason.isNotEmpty) {
      issues.add(
        _IssueRow(
          title: strings.healthReason,
          detail: reason,
          tone: StatusTone.warn,
        ),
      );
    }
    if (snapshot != null && !snapshot!.relayConnected) {
      issues.add(
        _IssueRow(
          title: strings.relay,
          detail: strings.issueRelayDisconnected,
          tone: StatusTone.warn,
        ),
      );
    }
    final failedTasks =
        health?.criticalTasks
            .where((task) => task.error != null && task.error!.isNotEmpty)
            .toList(growable: false) ??
        const <TaskStatusSnapshot>[];
    for (final task in failedTasks.take(3)) {
      issues.add(
        _IssueRow(
          title: '${strings.criticalTasks}: ${task.name}',
          detail: task.error!,
          tone: StatusTone.bad,
        ),
      );
    }
    final peerWarnings =
        snapshot?.peers.where((peer) => peer.lastError != null).length ?? 0;
    if (peerWarnings > 0) {
      issues.add(
        _IssueRow(
          title: strings.attentionDevices,
          detail: strings.peerWarnings(peerWarnings),
          tone: StatusTone.warn,
        ),
      );
    }
    if (statusStore.lastError != null && issues.isEmpty) {
      issues.add(
        _IssueRow(
          title: strings.lastError,
          detail:
              strings.statusMessage(statusStore.lastError) ??
              statusStore.lastError!,
          tone: StatusTone.warn,
        ),
      );
    }
    return issues;
  }
}

class _IssueRow extends StatelessWidget {
  const _IssueRow({
    required this.title,
    required this.detail,
    required this.tone,
  });

  final String title;
  final String detail;
  final StatusTone tone;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final iconColor = switch (tone) {
      StatusTone.good =>
        theme.brightness == Brightness.dark
            ? AppTokens.colorDarkGoodText
            : AppTokens.colorGoodText,
      StatusTone.warn =>
        theme.brightness == Brightness.dark
            ? AppTokens.colorDarkWarnText
            : AppTokens.colorWarnText,
      StatusTone.bad =>
        theme.brightness == Brightness.dark
            ? AppTokens.colorDarkBadText
            : AppTokens.colorBadText,
      StatusTone.neutral => theme.colorScheme.onSurfaceVariant,
    };
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.only(top: 1),
            child: Icon(
              tone == StatusTone.good
                  ? Icons.check_circle_outline
                  : Icons.info_outline_rounded,
              color: iconColor,
              size: 18,
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface,
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  detail,
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
