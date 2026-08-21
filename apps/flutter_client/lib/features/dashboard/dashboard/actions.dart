part of '../dashboard_page.dart';

/// Daemon recovery actions. Weight follows state: Start is the primary action
/// only when the daemon is stopped and locally controllable; a healthy
/// network gets only a compact secondary Stop action. Never two equal-weight
/// buttons, and no fake "connected" primary.
class _HomeActions extends StatelessWidget {
  const _HomeActions({
    required this.status,
    required this.loading,
    required this.daemonAvailable,
    required this.daemonBusy,
    required this.canControlLocalDaemon,
    required this.refreshing,
    required this.onStartDaemon,
    required this.onStopDaemon,
    required this.onRefresh,
  });

  final _NetworkStatus status;
  final bool loading;
  final bool daemonAvailable;
  final bool daemonBusy;
  final bool canControlLocalDaemon;
  final bool refreshing;
  final Future<void> Function() onStartDaemon;
  final Future<void> Function() onStopDaemon;
  final Future<void> Function() onRefresh;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final busy = daemonBusy || refreshing;

    final Widget start = FilledButton.icon(
      key: const Key('dashboard-start-button'),
      onPressed: daemonBusy ? null : onStartDaemon,
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

    final Widget checkAgain = OutlinedButton.icon(
      key: const Key('dashboard-check-button'),
      onPressed: refreshing ? null : onRefresh,
      icon: refreshing
          ? const SizedBox.square(
              dimension: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : const Icon(Icons.refresh_rounded, size: 17),
      label: Text(refreshing ? strings.refreshing : strings.checkAgain),
    );

    final Widget refresh =
        (status == _NetworkStatus.healthy ||
            status == _NetworkStatus.degraded ||
            status == _NetworkStatus.stale)
        ? TextButton.icon(
            key: const Key('dashboard-refresh-button'),
            onPressed: busy ? null : onRefresh,
            icon: refreshing
                ? const SizedBox.square(
                    dimension: 14,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.refresh_rounded, size: 16),
            label: Text(refreshing ? strings.refreshing : strings.refresh),
          )
        : OutlinedButton.icon(
            key: const Key('dashboard-refresh-button'),
            onPressed: busy ? null : onRefresh,
            icon: refreshing
                ? const SizedBox.square(
                    dimension: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.refresh_rounded, size: 17),
            label: Text(refreshing ? strings.refreshing : strings.refresh),
          );

    final actions = switch (status) {
      _NetworkStatus.stopped when canControlLocalDaemon => [start, refresh],
      _NetworkStatus.stopped || _NetworkStatus.unavailable => [checkAgain],
      // Healthy: the shell already owns refresh; only the red Stop action
      // remains. Degraded / stale keep an inline refresh because it is a
      // contextual recovery action there.
      _NetworkStatus.healthy => [if (canControlLocalDaemon) stop],
      _ => [if (canControlLocalDaemon) stop, refresh],
    };

    if (actions.isEmpty) return const SizedBox.shrink();

    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 320) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              actions.first,
              if (actions.length > 1) ...[
                const SizedBox(height: AppTokens.space8),
                actions[1],
              ],
            ],
          );
        }
        return Wrap(
          spacing: 10,
          runSpacing: 8,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: actions,
        );
      },
    );
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
