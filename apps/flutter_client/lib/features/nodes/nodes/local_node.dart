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
    required this.onEdit,
  });

  final DiagnosticsSnapshot? snapshot;
  final AppSettings settings;
  final VoidCallback onEdit;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final deviceName = settings.deviceName.trim();
    final nodeId = snapshot?.nodeId.trim() ?? '';
    final virtualIp = snapshot?.virtualIp.trim() ?? '';
    final canSync =
        !settings.manualMode &&
        settings.authToken.trim().isNotEmpty &&
        nodeId.isNotEmpty;
    final syncText = canSync
        ? (strings.isZh ? '服务端同步已就绪' : 'Control sync ready')
        : (strings.isZh
              ? '本地保存，启动并登录后同步'
              : 'Saved locally; sync after sign-in');

    return AppPanel(
      title: strings.isZh ? '本机节点' : 'This device',
      trailing: OutlinedButton.icon(
        onPressed: onEdit,
        icon: const Icon(Icons.edit_outlined, size: 16),
        label: Text(strings.isZh ? '修改名称' : 'Rename'),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 38,
                height: 38,
                decoration: BoxDecoration(
                  color: theme.colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(AppTokens.radiusMd),
                  border: Border.all(color: theme.colorScheme.outlineVariant),
                ),
                child: Icon(
                  Icons.computer_rounded,
                  size: 20,
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
                        fontSize: 16,
                        fontWeight: FontWeight.w700,
                        color: theme.colorScheme.onSurface,
                      ),
                    ),
                    const SizedBox(height: 3),
                    Text(
                      strings.isZh
                          ? '修改后会同步到控制面，其他设备刷新后会看到新名称。'
                          : 'Renames sync to the control plane and appear on other devices after refresh.',
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        fontSize: 12,
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
              StatusBadge(
                label: snapshot == null ? strings.offline : strings.connected,
                tone: snapshot == null ? StatusTone.neutral : StatusTone.good,
              ),
            ],
          ),
          const SizedBox(height: 14),
          Wrap(
            spacing: 24,
            runSpacing: 2,
            children: [
              MetricTile(
                label: strings.virtualIp,
                value: virtualIp.isEmpty ? '—' : virtualIp,
              ),
              MetricTile(
                label: strings.nodeId,
                value: nodeId.isEmpty ? '—' : shortId(nodeId),
              ),
              MetricTile(
                label: strings.isZh ? '同步状态' : 'Sync',
                value: syncText,
                minWidth: 210,
              ),
            ],
          ),
        ],
      ),
    );
  }
}
