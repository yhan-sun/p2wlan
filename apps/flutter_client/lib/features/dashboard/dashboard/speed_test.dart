part of '../dashboard_page.dart';

class _SpeedTestPanel extends StatelessWidget {
  const _SpeedTestPanel({
    required this.snapshot,
    required this.running,
    required this.result,
    required this.error,
    required this.runningPeerVirtualIp,
    required this.onRun,
  });

  final DiagnosticsSnapshot? snapshot;
  final bool running;
  final SpeedTestResult? result;
  final String? error;
  final String? runningPeerVirtualIp;
  final Future<void> Function(PeerSnapshot peer) onRun;

  @override
  Widget build(BuildContext context) {
    final peer = _bestDirectPeer(snapshot);
    if (peer == null && !running && result == null && error == null) {
      return const SizedBox.shrink();
    }

    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final displayPeer = peer?.displayName ?? result?.peerVirtualIp ?? '—';
    return Padding(
      padding: const EdgeInsets.only(top: 12),
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: theme.colorScheme.surface,
          borderRadius: BorderRadius.circular(AppTokens.radiusMd),
          border: Border.all(color: theme.colorScheme.outlineVariant),
        ),
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      strings.speedTestPeer(displayPeer),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        color: theme.colorScheme.onSurfaceVariant,
                        fontSize: 12,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: 5),
                    Text(
                      _speedTestStatus(strings),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        color: error == null
                            ? theme.colorScheme.onSurface
                            : theme.colorScheme.error,
                        fontSize: 15,
                        fontWeight: FontWeight.w800,
                        fontFeatures: AppTokens.tabularFontFeatures,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              FilledButton.icon(
                key: const Key('dashboard-speedtest-button'),
                onPressed: peer == null || running ? null : () => onRun(peer),
                icon: running
                    ? SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: theme.colorScheme.onPrimary,
                        ),
                      )
                    : const Icon(Icons.speed_rounded, size: 18),
                label: Text(running ? strings.speedTesting : strings.speedTest),
              ),
            ],
          ),
        ),
      ),
    );
  }

  String _speedTestStatus(AppStrings strings) {
    if (running) {
      final peer = runningPeerVirtualIp == null || runningPeerVirtualIp!.isEmpty
          ? ''
          : ' · $runningPeerVirtualIp';
      return '${strings.speedTesting}$peer';
    }
    final message = error;
    if (message != null && message.isNotEmpty) {
      return strings.speedTestFailed(message);
    }
    final value = result;
    if (value == null) return strings.speedTestReady;
    return strings.speedTestResult(value.downloadMbps, value.uploadMbps);
  }
}

PeerSnapshot? _bestDirectPeer(DiagnosticsSnapshot? snapshot) {
  final peers = snapshot?.peers
      .where((peer) => peer.online && peer.path == 'direct' && !peer.isRelay)
      .toList();
  if (peers == null || peers.isEmpty) return null;
  peers.sort(
    (a, b) => (a.latencyMs ?? (1 << 30)).compareTo(b.latencyMs ?? (1 << 30)),
  );
  return peers.first;
}
