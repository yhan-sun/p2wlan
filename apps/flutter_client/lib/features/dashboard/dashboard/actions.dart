part of '../dashboard_page.dart';

/// Daemon recovery actions. Start is the primary action only when the daemon
/// is stopped and locally controllable. Stop lives in the Network status
/// header so it is close to the state it changes, rather than being separated
/// from the status card by the metrics and device sections.
class _HomeActions extends StatelessWidget {
  const _HomeActions({
    required this.status,
    required this.daemonBusy,
    required this.initialProbePending,
    required this.canControlLocalDaemon,
    required this.onStartDaemon,
  });

  final _NetworkStatus status;
  final bool daemonBusy;
  final bool initialProbePending;
  final bool canControlLocalDaemon;
  final Future<void> Function() onStartDaemon;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final Widget start = FilledButton.icon(
      key: const Key('dashboard-start-button'),
      onPressed: daemonBusy || initialProbePending ? null : onStartDaemon,
      icon: daemonBusy
          ? const _ButtonSpinner()
          : const Icon(Icons.play_arrow_rounded, size: 18),
      label: Text(daemonBusy ? strings.daemonWorking : strings.startP2wlan),
    );

    // Status detection is automatic and intentionally has no foreground
    // refresh action. Polling may rebuild this widget, but it never turns into
    // a visible "syncing" task or asks the user to initiate data refresh.
    return switch (status) {
      _NetworkStatus.stopped when canControlLocalDaemon => start,
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
