part of '../nodes_page.dart';

class _LocalNodeProfileResult {
  const _LocalNodeProfileResult({
    required this.deviceName,
    required this.virtualIp,
  });

  final String deviceName;
  final String virtualIp;
}

/// Compact local-device section: name, virtual IP, connection status, and a
/// quiet edit affordance. No Node ID, no sync text, no big panel — the
/// details live in the edit dialog.
class _LocalNodePanel extends StatelessWidget {
  const _LocalNodePanel({
    required this.snapshot,
    required this.settings,
    required this.snapshotStale,
    required this.daemonReachable,
    required this.onEdit,
  });

  final DiagnosticsSnapshot? snapshot;
  final AppSettings settings;
  final bool snapshotStale;
  final bool daemonReachable;
  final VoidCallback onEdit;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final theme = Theme.of(context);
    final c = P2WlanColors.of(context);
    final deviceName = settings.deviceName.trim();
    final virtualIp = snapshot?.virtualIp.trim() ?? '';
    // Real daemon reachability signals only; never claim "offline" when the
    // daemon is actually reachable but the snapshot is unavailable.
    final online = snapshot != null && !snapshotStale;
    final statusLabel = snapshot != null && snapshotStale
        ? strings.stale
        : online
        ? strings.connected
        : daemonReachable
        ? strings.unavailable
        : strings.offline;
    final statusColor = snapshot != null && snapshotStale
        ? c.warningText
        : online
        ? c.direct
        : c.offline;

    final leading = Container(
      width: 32,
      height: 32,
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
      ),
      child: Icon(
        localDeviceIcon(context),
        size: 17,
        color: theme.colorScheme.primary,
      ),
    );
    final edit = IconButton(
      key: const Key('nodes-edit-local'),
      tooltip: strings.renameDevice,
      onPressed: onEdit,
      iconSize: 18,
      icon: const Icon(Icons.edit_outlined),
    );
    final status = Wrap(
      spacing: 6,
      runSpacing: 4,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        Container(
          width: 8,
          height: 8,
          decoration: BoxDecoration(color: statusColor, shape: BoxShape.circle),
        ),
        Text(
          statusLabel,
          style: TextStyle(
            color: statusColor,
            fontSize: 12,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Material(
          type: MaterialType.transparency,
          child: InkWell(
            key: const Key('nodes-local-row'),
            onTap: onEdit,
            child: Padding(
              padding: const EdgeInsets.symmetric(
                horizontal: AppTokens.space14,
                vertical: 12,
              ),
              child: LayoutBuilder(
                builder: (context, constraints) {
                  final stacked =
                      constraints.maxWidth < 320 ||
                      MediaQuery.textScalerOf(context).scale(12) > 16;
                  final localLabel = Text(
                    strings.thisDeviceTitle,
                    style: TextStyle(
                      fontSize: 12,
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  );
                  final identity = Expanded(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          dash(deviceName),
                          maxLines: stacked ? 2 : 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            fontSize: 14,
                            height: 1.3,
                            fontWeight: FontWeight.w700,
                            color: theme.colorScheme.onSurface,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Wrap(
                          spacing: 8,
                          runSpacing: 2,
                          crossAxisAlignment: WrapCrossAlignment.center,
                          children: [
                            localLabel,
                            Text(
                              dash(virtualIp),
                              style: TextStyle(
                                fontSize: 12,
                                color: theme.colorScheme.onSurfaceVariant,
                                fontFeatures: AppTokens.tabularFontFeatures,
                                height: 1.3,
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  );
                  final row = Row(
                    children: [
                      leading,
                      const SizedBox(width: AppTokens.space10),
                      identity,
                      if (!stacked) ...[
                        const SizedBox(width: AppTokens.space10),
                        status,
                      ],
                      edit,
                    ],
                  );
                  if (!stacked) return row;
                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      row,
                      const SizedBox(height: 8),
                      Padding(
                        padding: const EdgeInsets.only(left: 42),
                        child: status,
                      ),
                    ],
                  );
                },
              ),
            ),
          ),
        ),
      ],
    );
  }
}

/// One bounded surface for the toolbar, local identity and peer catalog.
class _NodesDevicePanel extends StatelessWidget {
  const _NodesDevicePanel({required this.children});

  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final colors = P2WlanColors.of(context);
    return Material(
      key: const Key('nodes-device-panel'),
      color: colors.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        side: BorderSide(color: colors.border),
      ),
      clipBehavior: Clip.antiAlias,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: children,
      ),
    );
  }
}

class _NodesSectionLabel extends StatelessWidget {
  const _NodesSectionLabel({required this.title, this.showMetrics = false});

  final String title;
  final bool showMetrics;

  @override
  Widget build(BuildContext context) {
    final color = Theme.of(context).colorScheme.onSurfaceVariant;
    final strings = stringsOf(context);
    final titleWidget = Text(
      title,
      style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w600),
    );
    return Padding(
      padding: const EdgeInsets.fromLTRB(14, 12, 14, 4),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final columns =
              showMetrics &&
              constraints.maxWidth >= 472 &&
              MediaQuery.textScalerOf(context).scale(12) <= 16;
          if (!columns) return titleWidget;
          return Row(
            children: [
              Expanded(child: titleWidget),
              SizedBox(
                width: 202,
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    Tooltip(
                      message: strings.transferSpeed,
                      child: _PeerMetricText(
                        value: strings.isZh ? '速率' : 'Rate',
                        width: 72,
                        color: color,
                      ),
                    ),
                    const SizedBox(width: 8),
                    Tooltip(
                      message: strings.latency,
                      child: _PeerMetricText(
                        value: 'RTT',
                        width: 48,
                        color: color,
                      ),
                    ),
                    const SizedBox(width: 8),
                    _PeerMetricText(
                      value: strings.isZh ? '连接' : 'Path',
                      width: 60,
                      color: color,
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 26),
            ],
          );
        },
      ),
    );
  }
}
