part of '../diagnostics_page.dart';

class _DiagnosticsActions extends StatelessWidget {
  const _DiagnosticsActions({
    required this.statusStore,
    required this.snapshot,
  });

  final StatusStore statusStore;
  final DiagnosticsSnapshot? snapshot;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return Wrap(
      spacing: 10,
      runSpacing: 8,
      children: [
        OutlinedButton.icon(
          onPressed: () => _copySummary(context),
          icon: const Icon(Icons.copy_all_outlined, size: 17),
          label: Text(strings.isZh ? '复制摘要' : 'Copy summary'),
        ),
        OutlinedButton.icon(
          onPressed: () => _openLogs(context),
          icon: const Icon(Icons.folder_open_outlined, size: 17),
          label: Text(strings.openLogs),
        ),
        FilledButton.icon(
          onPressed: statusStore.refreshing ? null : statusStore.refresh,
          icon: statusStore.refreshing
              ? const SizedBox.square(
                  dimension: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.refresh_rounded, size: 17),
          label: Text(
            statusStore.refreshing ? strings.refreshing : strings.refreshNow,
          ),
        ),
      ],
    );
  }

  Future<void> _copySummary(BuildContext context) async {
    final strings = AppStringsScope.of(context);
    final health = snapshot?.health;
    final stats = snapshot?.stats;
    final lines = [
      'P2WLAN diagnostics',
      'platform=${Platform.operatingSystem}',
      'health_endpoint=${statusStore.healthReachable}',
      'status_endpoint=${statusStore.statusReachable}',
      'service_health=${health?.status ?? "n/a"}',
      'control_connected=${health?.controlConnected ?? false}',
      'reauth_required=${health?.reauthRequired ?? false}',
      'node_id=${snapshot?.nodeId ?? "n/a"}',
      'virtual_ip=${snapshot?.virtualIp ?? "n/a"}',
      'network=${snapshot?.networkId ?? "n/a"}',
      'udp=${snapshot?.udpLocalAddr ?? "n/a"}',
      'peers=${stats?.totalPeers ?? 0} direct=${stats?.directConnections ?? 0} relay=${stats?.relayConnections ?? 0}',
      if (statusStore.lastError != null) 'last_error=${statusStore.lastError}',
      if (health?.reason != null) 'health_reason=${health!.reason}',
    ];
    await Clipboard.setData(ClipboardData(text: lines.join('\n')));
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(strings.isZh ? '诊断摘要已复制' : 'Diagnostics summary copied'),
      ),
    );
  }

  Future<void> _openLogs(BuildContext context) async {
    final strings = AppStringsScope.of(context);
    final dir = defaultP2WlanLogDir();
    await dir.create(recursive: true);
    if (Platform.isMacOS) {
      await Process.start('open', [dir.path]);
    } else if (Platform.isWindows) {
      await Process.start('explorer', [dir.path]);
    } else {
      await Process.start('xdg-open', [dir.path]);
    }
    if (!context.mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text('${strings.openLogs}: ${dir.path}')));
  }
}
