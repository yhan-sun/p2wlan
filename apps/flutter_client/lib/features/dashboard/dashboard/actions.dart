part of '../dashboard_page.dart';

/// Daemon recovery actions. Weight follows state: Start is the primary action
/// only when the daemon is stopped and locally controllable; a healthy
/// network gets only a compact secondary Stop action. Never two equal-weight
/// buttons, and no fake "connected" primary.
class _HomeActions extends StatelessWidget {
  const _HomeActions({
    required this.status,
    required this.daemonBusy,
    required this.initialProbePending,
    required this.canControlLocalDaemon,
    required this.onStartDaemon,
    required this.onStopDaemon,
  });

  final _NetworkStatus status;
  final bool daemonBusy;
  final bool initialProbePending;
  final bool canControlLocalDaemon;
  final Future<void> Function() onStartDaemon;
  final Future<void> Function() onStopDaemon;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);

    final Widget start = FilledButton.icon(
      key: const Key('dashboard-start-button'),
      onPressed: daemonBusy || initialProbePending ? null : onStartDaemon,
      icon: daemonBusy
          ? const _ButtonSpinner()
          : const Icon(Icons.play_arrow_rounded, size: 18),
      label: Text(daemonBusy ? strings.daemonWorking : strings.startP2wlan),
    );

    // Stop is destructive but common enough to remain visible. A compact
    // tinted outline gives it a clear danger signal without making it look
    // like the primary action for a healthy network.
    final Widget stop = OutlinedButton.icon(
      key: const Key('dashboard-stop-button'),
      onPressed: daemonBusy ? null : onStopDaemon,
      style: OutlinedButton.styleFrom(
        foregroundColor: colors.dangerText,
        backgroundColor: colors.dangerSurface,
        side: BorderSide(color: colors.dangerBorder),
        minimumSize: const Size(0, 40),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        ),
      ),
      icon: daemonBusy
          ? _ButtonSpinner(color: colors.dangerText)
          : const Icon(Icons.stop_rounded, size: 17),
      label: Text(daemonBusy ? strings.daemonWorking : strings.stopP2wlan),
    );

    // Status detection is automatic and intentionally has no foreground
    // refresh action. Polling may rebuild this widget, but it never turns into
    // a visible "syncing" task or asks the user to initiate data refresh.
    return switch (status) {
      _NetworkStatus.stopped when canControlLocalDaemon => start,
      _NetworkStatus.healthy ||
      _NetworkStatus.degraded ||
      _NetworkStatus.stale when canControlLocalDaemon => stop,
      _ => const SizedBox.shrink(),
    };
  }
}

class _ButtonSpinner extends StatelessWidget {
  const _ButtonSpinner({this.color});

  final Color? color;

  @override
  Widget build(BuildContext context) {
    return SizedBox.square(
      dimension: 14,
      child: CircularProgressIndicator(
        strokeWidth: 2,
        valueColor: AlwaysStoppedAnimation<Color>(
          color ?? Theme.of(context).colorScheme.onPrimary,
        ),
      ),
    );
  }
}
