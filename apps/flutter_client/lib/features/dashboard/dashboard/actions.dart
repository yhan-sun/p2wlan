part of '../dashboard_page.dart';

class _DashboardActions extends StatelessWidget {
  const _DashboardActions({
    required this.daemonAvailable,
    required this.daemonBusy,
    required this.refreshing,
    required this.autoRefreshEnabled,
    required this.onStartDaemon,
    required this.onStopDaemon,
    required this.onRefresh,
    required this.onAutoRefreshChanged,
  });

  final bool daemonAvailable;
  final bool daemonBusy;
  final bool refreshing;
  final bool autoRefreshEnabled;
  final Future<void> Function() onStartDaemon;
  final Future<void> Function() onStopDaemon;
  final Future<void> Function() onRefresh;
  final ValueChanged<bool> onAutoRefreshChanged;

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
    final autoRefreshAction = _AutoRefreshButton(
      autoRefreshEnabled: autoRefreshEnabled,
      daemonBusy: daemonBusy,
      onAutoRefreshChanged: onAutoRefreshChanged,
    );

    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 520) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              primaryAction,
              const SizedBox(height: 8),
              refreshAction,
              const SizedBox(height: 8),
              autoRefreshAction,
            ],
          );
        }

        return Wrap(
          spacing: 10,
          runSpacing: 8,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [primaryAction, refreshAction, autoRefreshAction],
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

class _AutoRefreshButton extends StatelessWidget {
  const _AutoRefreshButton({
    required this.autoRefreshEnabled,
    required this.daemonBusy,
    required this.onAutoRefreshChanged,
  });

  final bool autoRefreshEnabled;
  final bool daemonBusy;
  final ValueChanged<bool> onAutoRefreshChanged;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final label = strings.autoRefresh(
      StatusStore.defaultAutoRefreshInterval.inSeconds,
    );

    return Tooltip(
      message: strings.autoRefreshTooltip,
      child: OutlinedButton.icon(
        key: const Key('auto-refresh-toggle'),
        onPressed: daemonBusy
            ? null
            : () => onAutoRefreshChanged(!autoRefreshEnabled),
        icon: AnimatedSwitcher(
          duration: AppTokens.durationMedium,
          switchInCurve: AppTokens.curveEase,
          switchOutCurve: Curves.easeIn,
          transitionBuilder: (child, animation) {
            return FadeTransition(
              opacity: animation,
              child: ScaleTransition(scale: animation, child: child),
            );
          },
          child: Icon(
            autoRefreshEnabled ? Icons.timer_rounded : Icons.timer_off_outlined,
            key: ValueKey(autoRefreshEnabled),
            size: 17,
          ),
        ),
        label: Text(label),
        style: OutlinedButton.styleFrom(
          foregroundColor: autoRefreshEnabled
              ? colorScheme.primary
              : colorScheme.onSurfaceVariant,
          backgroundColor: autoRefreshEnabled
              ? colorScheme.surfaceContainerHighest
              : Colors.transparent,
          side: BorderSide(
            color: autoRefreshEnabled
                ? colorScheme.primary.withValues(alpha: 0.34)
                : colorScheme.outline,
          ),
        ),
      ),
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
