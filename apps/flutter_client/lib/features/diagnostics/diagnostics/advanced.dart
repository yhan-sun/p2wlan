part of '../diagnostics_page.dart';

/// Progressive disclosure for the technical section. Defaults to collapsed;
/// the open state lives only in the page state, never persisted. Children are
/// only constructed when [open] is true (the page passes an empty list while
/// collapsed), so nothing inside runs until the user expands it.
class _AdvancedDisclosure extends StatelessWidget {
  const _AdvancedDisclosure({
    required this.open,
    required this.onToggle,
    required this.children,
  });

  final bool open;
  final VoidCallback onToggle;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final trailingLabel = open
        ? strings.disclosureCollapse
        : strings.disclosureExpand;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Material(
          type: MaterialType.transparency,
          child: InkWell(
            key: const Key('diagnostics-advanced'),
            borderRadius: BorderRadius.circular(AppTokens.radiusLg),
            onTap: onToggle,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(AppTokens.radiusLg),
                border: Border.all(color: theme.colorScheme.outlineVariant),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          strings.advancedDiagnostics,
                          style: TextStyle(
                            fontSize: 15,
                            fontWeight: FontWeight.w600,
                            color: theme.colorScheme.onSurface,
                          ),
                        ),
                        const SizedBox(height: 3),
                        Text(
                          strings.advancedDiagnosticsSubtitle,
                          style: TextStyle(
                            fontSize: 12,
                            height: 1.35,
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 12),
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        trailingLabel,
                        style: TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                          color: theme.colorScheme.primary,
                        ),
                      ),
                      const SizedBox(width: 4),
                      Icon(
                        open ? Icons.expand_less : Icons.expand_more,
                        size: 20,
                        color: theme.colorScheme.primary,
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
        if (open)
          Padding(
            padding: const EdgeInsets.fromLTRB(2, 10, 2, 2),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: children,
            ),
          ),
      ],
    );
  }
}

/// Technical endpoint/runtime metrics moved into the advanced section. Raw
/// error strings only appear here (redacted), never in the default view.
class _RuntimeDetailsPanel extends StatelessWidget {
  const _RuntimeDetailsPanel({
    required this.statusStore,
    required this.snapshot,
  });

  final StatusStore statusStore;
  final DiagnosticsSnapshot? snapshot;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final health = snapshot?.health;
    return AppPanel(
      title: strings.runtimeDetails,
      child: Wrap(
        spacing: 24,
        runSpacing: 4,
        children: [
          MetricTile(
            label: strings.healthEndpoint,
            value: statusStore.healthReachable
                ? strings.reachable
                : strings.offline,
            detail: _redactedError(statusStore.lastHealthError),
          ),
          MetricTile(
            label: strings.statusEndpoint,
            value: strings.endpointStatusLabel(
              statusReachable: statusStore.statusReachable,
              healthReachable: statusStore.healthReachable,
            ),
            detail: _redactedError(statusStore.lastStatusError),
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
            label: strings.udpSockets,
            value: snapshot == null ? '—' : formatInt(snapshot!.udpSocketCount),
          ),
          MetricTile(
            label: strings.socketPoolActive,
            value: strings.optionalBoolLabel(snapshot?.udpSocketPoolActive),
          ),
          MetricTile(
            label: strings.relay,
            value: snapshot?.relayConnected == true
                ? strings.connected
                : strings.notConnected,
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
              value: redactSensitive(statusStore.lastError!),
            ),
          if (health?.reason != null)
            MetricTile(
              label: strings.healthReason,
              value: redactSensitive(health!.reason!),
            ),
        ],
      ),
    );
  }

  static String? _redactedError(String? value) {
    if (value == null) return null;
    return redactSensitive(value);
  }
}
