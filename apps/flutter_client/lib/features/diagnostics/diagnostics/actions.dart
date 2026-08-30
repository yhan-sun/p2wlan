part of '../diagnostics_page.dart';

/// Support-friendly summary, offered from Advanced → Support tools. Everything
/// that could carry a credential is passed through [redactSensitive] before it
/// reaches the clipboard.
Future<void> _copySummary(BuildContext context, StatusStore statusStore) async {
  final strings = AppStringsScope.of(context);
  final snapshot = statusStore.snapshot;
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
  final safeSummary = redactSensitive(lines.join('\n'));
  await Clipboard.setData(ClipboardData(text: safeSummary));
  if (!context.mounted) return;
  ScaffoldMessenger.of(context)
      .showSnackBar(SnackBar(content: Text(strings.diagnosticsSummaryCopied)));
}
