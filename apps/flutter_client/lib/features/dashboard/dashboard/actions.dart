part of '../dashboard_page.dart';

class _DashboardActions extends StatelessWidget {
  const _DashboardActions({
    required this.daemonAvailable,
    required this.daemonBusy,
    required this.canControlLocalDaemon,
    required this.refreshing,
    required this.onStartDaemon,
    required this.onStopDaemon,
    required this.onRefresh,
  });

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
    final busy = daemonBusy || refreshing;
    final primaryAction = _PrimaryDaemonButton(
      daemonAvailable: daemonAvailable,
      daemonBusy: daemonBusy,
      onStartDaemon: onStartDaemon,
      onStopDaemon: onStopDaemon,
    );
    final refreshAction = OutlinedButton.icon(
      key: const Key('dashboard-refresh-button'),
      onPressed: busy ? null : onRefresh,
      icon: refreshing
          ? const SizedBox.square(
              dimension: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : const Icon(Icons.refresh_rounded, size: 17),
      label: Text(refreshing ? strings.refreshing : strings.refreshNow),
    );
    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 520) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (canControlLocalDaemon) ...[
                primaryAction,
                const SizedBox(height: AppTokens.space8),
              ],
              refreshAction,
            ],
          );
        }

        return Wrap(
          spacing: 10,
          runSpacing: 8,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [if (canControlLocalDaemon) primaryAction, refreshAction],
        );
      },
    );
  }
}

class _PrimaryDaemonButton extends StatelessWidget {
  const _PrimaryDaemonButton({
    required this.daemonAvailable,
    required this.daemonBusy,
    required this.onStartDaemon,
    required this.onStopDaemon,
  });

  final bool daemonAvailable;
  final bool daemonBusy;
  final Future<void> Function() onStartDaemon;
  final Future<void> Function() onStopDaemon;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    if (daemonAvailable) {
      return FilledButton.icon(
        key: const Key('dashboard-stop-button'),
        onPressed: daemonBusy ? null : onStopDaemon,
        icon: daemonBusy
            ? const _ButtonSpinner()
            : const Icon(Icons.stop_rounded, size: 17),
        label: Text(daemonBusy ? strings.daemonWorking : strings.stopP2wlan),
      );
    }

    return FilledButton.icon(
      key: const Key('dashboard-start-button'),
      onPressed: daemonBusy ? null : onStartDaemon,
      icon: daemonBusy
          ? const _ButtonSpinner()
          : const Icon(Icons.play_arrow_rounded, size: 18),
      label: Text(daemonBusy ? strings.daemonWorking : strings.startP2wlan),
    );
  }
}

class _ButtonSpinner extends StatelessWidget {
  const _ButtonSpinner();

  @override
  Widget build(BuildContext context) {
    return SizedBox.square(
      dimension: 14,
      child: CircularProgressIndicator(
        strokeWidth: 2,
        valueColor: AlwaysStoppedAnimation<Color>(
          Theme.of(context).colorScheme.onPrimary,
        ),
      ),
    );
  }
}
