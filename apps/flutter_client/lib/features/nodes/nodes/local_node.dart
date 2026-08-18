part of '../nodes_page.dart';

class _LocalNodeProfileResult {
  const _LocalNodeProfileResult({
    required this.deviceName,
    required this.virtualIp,
  });

  final String deviceName;
  final String virtualIp;
}

class _LocalNodePanel extends StatelessWidget {
  const _LocalNodePanel({
    required this.snapshot,
    required this.settings,
    required this.daemonReachable,
    required this.onEdit,
  });

  final DiagnosticsSnapshot? snapshot;
  final AppSettings settings;
  final bool daemonReachable;
  final VoidCallback onEdit;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final theme = Theme.of(context);
    final deviceName = settings.deviceName.trim();
    final nodeId = snapshot?.nodeId.trim() ?? '';
    final virtualIp = snapshot?.virtualIp.trim() ?? '';
    final canSync =
        !settings.manualMode &&
        settings.authToken.trim().isNotEmpty &&
        nodeId.isNotEmpty;
    final syncText = canSync
        ? (strings.isZh ? '控制面同步就绪' : 'Control sync ready')
        : (strings.isZh ? '本地保存' : 'Saved locally');
    // Real daemon reachability signals only; never claim "offline" when the
    // daemon is actually reachable but the snapshot is unavailable.
    final statusLabel = snapshot != null
        ? strings.connected
        : daemonReachable
        ? strings.unavailable
        : strings.offline;
    final statusTone = snapshot != null ? StatusTone.good : StatusTone.neutral;

    return AppPanel(
      title: strings.isZh ? '本机节点' : 'This device',
      trailing: OutlinedButton.icon(
        onPressed: onEdit,
        icon: const Icon(Icons.edit_outlined, size: 16),
        label: Text(strings.renameDevice),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Container(
            width: 36,
            height: 36,
            decoration: BoxDecoration(
              color: theme.colorScheme.surfaceContainerHighest,
              borderRadius: BorderRadius.circular(AppTokens.radiusMd),
              border: Border.all(color: theme.colorScheme.outlineVariant),
            ),
            child: Icon(
              Icons.computer_rounded,
              size: 19,
              color: theme.colorScheme.primary,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  dash(deviceName),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    fontSize: 15,
                    fontWeight: FontWeight.w700,
                    color: theme.colorScheme.onSurface,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  [
                    '${strings.nodeId} ${nodeId.isEmpty ? '—' : shortId(nodeId)}',
                    '${strings.virtualIp} ${virtualIp.isEmpty ? '—' : virtualIp}',
                    syncText,
                  ].join(' · '),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    fontSize: 11.5,
                    color: theme.colorScheme.onSurfaceVariant,
                    fontFeatures: AppTokens.tabularFontFeatures,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: 12),
          StatusBadge(label: statusLabel, tone: statusTone),
        ],
      ),
    );
  }
}
