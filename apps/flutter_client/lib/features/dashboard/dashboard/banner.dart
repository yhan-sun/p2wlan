part of '../dashboard_page.dart';

class _ConnectionBanner extends StatelessWidget {
  const _ConnectionBanner({
    required this.snapshot,
    required this.daemonReachable,
    required this.healthReachable,
    required this.statusReachable,
    required this.refreshing,
    required this.daemonBusy,
    required this.error,
    required this.healthError,
    required this.statusError,
    required this.daemonManualCommand,
    required this.snapshotStale,
    required this.lastFetchedAt,
    required this.requestDuration,
    required this.onStartDaemon,
    required this.onStopDaemon,
    required this.onRefresh,
  });

  final DiagnosticsSnapshot? snapshot;
  final bool daemonReachable;
  final bool healthReachable;
  final bool statusReachable;
  final bool refreshing;
  final bool daemonBusy;
  final String? error;
  final String? healthError;
  final String? statusError;
  final String? daemonManualCommand;
  final bool snapshotStale;
  final DateTime? lastFetchedAt;
  final Duration? requestDuration;
  final Future<void> Function() onStartDaemon;
  final Future<void> Function() onStopDaemon;
  final Future<void> Function() onRefresh;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final daemonAvailable = _daemonAvailable;
    final tone = _overallTone();
    final issueMessage =
        _statusMessage(strings, daemonAvailable) ?? _attentionMessage(strings);
    final showIssueNote = issueMessage != null && daemonAvailable;
    return _DashboardSurface(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const _DashboardSurfaceHeader(),
          const SizedBox(height: 16),
          _ConnectionOverview(
            snapshot: snapshot,
            daemonAvailable: daemonAvailable,
            tone: tone,
            healthReachable: healthReachable,
            statusReachable: statusReachable,
            snapshotStale: snapshotStale,
          ),
          const SizedBox(height: 16),
          _DashboardActions(
            daemonAvailable: daemonAvailable,
            daemonBusy: daemonBusy,
            refreshing: refreshing,
            onStartDaemon: () => _handleStart(context),
            onStopDaemon: onStopDaemon,
            onRefresh: onRefresh,
          ),
          if (daemonAvailable) ...[
            const SizedBox(height: 16),
            const Divider(),
            const SizedBox(height: 14),
            _DashboardMetrics(
              snapshot: snapshot,
              lastFetchedAt: lastFetchedAt,
              requestDuration: requestDuration,
              snapshotStale: snapshotStale,
            ),
          ],
          const SizedBox(height: 16),
          _NatProfilePanel(snapshot: snapshot),
          if (showIssueNote) ...[
            const SizedBox(height: 12),
            _StatusNote(
              label: strings.reviewRecommended,
              message: issueMessage,
              tone: StatusTone.warn,
            ),
          ],
          if (daemonManualCommand != null) ...[
            const SizedBox(height: 14),
            _ManualDaemonCommand(command: daemonManualCommand!),
          ],
        ],
      ),
    );
  }

  bool get _daemonAvailable => daemonReachable || statusReachable;

  String? _statusMessage(AppStrings strings, bool daemonAvailable) {
    if (!daemonAvailable) return strings.offlineSnapshotMessage;
    if (snapshotStale) return strings.staleSnapshotMessage;
    if (!statusReachable && statusError != null) {
      return strings.statusMessage(statusError) ?? statusError;
    }
    if (!healthReachable && healthError != null) {
      return strings.statusMessage(healthError) ?? healthError;
    }
    if (_overallTone() != StatusTone.good && error != null) {
      return strings.statusMessage(error) ?? error;
    }
    return null;
  }

  String? _attentionMessage(AppStrings strings) {
    final health = snapshot?.health;
    if (health?.reauthRequired == true) return strings.issueReauthRequired;
    if (health != null && !health.controlConnected) {
      return strings.issueControlDisconnected;
    }
    final reason = health?.reason?.trim();
    if (reason != null && reason.isNotEmpty) return reason;
    return null;
  }

  Future<void> _handleStart(BuildContext context) async {
    if (defaultTargetPlatform == TargetPlatform.macOS) {
      final strings = AppStringsScope.of(context);
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (dialogContext) {
          return AlertDialog(
            title: Text(strings.macosAuthorizationTitle),
            content: Text(strings.macosAuthorizationBody),
            actions: [
              TextButton(
                onPressed: () => Navigator.of(dialogContext).pop(false),
                child: Text(strings.cancel),
              ),
              FilledButton(
                onPressed: () => Navigator.of(dialogContext).pop(true),
                child: Text(strings.continueAction),
              ),
            ],
          );
        },
      );
      if (confirmed != true) return;
    }
    await onStartDaemon();
  }

  StatusTone _overallTone() {
    if (!_daemonAvailable) return StatusTone.neutral;
    if (snapshotStale) return StatusTone.warn;
    if (!healthReachable) return StatusTone.bad;
    if (!statusReachable) return StatusTone.warn;
    return switch (snapshot?.health.status.toLowerCase()) {
      'healthy' => StatusTone.good,
      'degraded' => StatusTone.warn,
      _ => StatusTone.bad,
    };
  }
}
