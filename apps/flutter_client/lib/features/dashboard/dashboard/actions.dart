part of '../dashboard_page.dart';

/// Room selection is the stopped Home's main entry. The configured primary
/// network remains available through the original daemon authority.
class _HomeActions extends StatelessWidget {
  const _HomeActions({
    required this.status,
    required this.daemonBusy,
    required this.initialProbePending,
    required this.canControlLocalDaemon,
    required this.configuredRoom,
    required this.onStartDaemon,
    this.onOpenRooms,
  });

  final _NetworkStatus status;
  final bool daemonBusy;
  final bool initialProbePending;
  final bool canControlLocalDaemon;
  final bool configuredRoom;
  final Future<void> Function() onStartDaemon;
  final VoidCallback? onOpenRooms;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final hasRoomEntry = onOpenRooms != null;
    final onStart = daemonBusy || initialProbePending ? null : onStartDaemon;
    final startLabel = daemonBusy
        ? strings.daemonWorking
        : !hasRoomEntry
        ? strings.startP2wlan
        : configuredRoom
        ? (strings.isZh ? '连接当前配置房间' : 'Connect configured room')
        : (strings.isZh ? '启动个人网络' : 'Start personal network');
    final Widget configuredStart = hasRoomEntry
        ? OutlinedButton.icon(
            key: const Key('dashboard-start-button'),
            onPressed: onStart,
            icon: daemonBusy
                ? _ButtonSpinner(color: Theme.of(context).colorScheme.primary)
                : const Icon(Icons.play_arrow_rounded, size: 18),
            label: Text(startLabel),
          )
        : FilledButton.icon(
            key: const Key('dashboard-start-button'),
            onPressed: onStart,
            icon: daemonBusy
                ? const _ButtonSpinner()
                : const Icon(Icons.play_arrow_rounded, size: 18),
            label: Text(startLabel),
          );

    // Status detection is automatic and intentionally has no foreground
    // refresh action. Polling may rebuild this widget, but it never turns into
    // a visible "syncing" task or asks the user to initiate data refresh.
    return switch (status) {
      _NetworkStatus.stopped when canControlLocalDaemon =>
        hasRoomEntry
            ? Wrap(
                spacing: AppTokens.space12,
                runSpacing: AppTokens.space12,
                children: [
                  FilledButton.icon(
                    key: const Key('home-open-rooms'),
                    onPressed: onOpenRooms,
                    icon: const Icon(Icons.meeting_room_outlined, size: 18),
                    label: Text(strings.isZh ? '选择并连接房间' : 'Choose a room'),
                  ),
                  configuredStart,
                ],
              )
            : configuredStart,
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
