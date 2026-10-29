part of '../nodes_page.dart';

/// Mobile/web devices state. A remote-management client cannot read the live
/// peer/path snapshot from the desktop daemon through localhost, so it must
/// not render an invented offline local node or empty live peer catalog.
class _RemoteOnlyNodesState extends StatelessWidget {
  const _RemoteOnlyNodesState({this.onOpenRooms});

  final VoidCallback? onOpenRooms;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final theme = Theme.of(context);
    final c = P2WlanColors.of(context);
    return AppPanel(
      title: strings.mobileModeTitle,
      trailing: StatusBadge(
        label: strings.mobileModeBadge,
        tone: StatusTone.neutral,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(
                Icons.devices_other_rounded,
                color: theme.colorScheme.primary,
              ),
              const SizedBox(width: AppTokens.space12),
              Expanded(
                child: Text(
                  strings.mobileModeDetail,
                  style: TextStyle(
                    color: c.textMuted,
                    fontSize: 13,
                    height: 1.45,
                  ),
                ),
              ),
            ],
          ),
          if (onOpenRooms != null) ...[
            const SizedBox(height: AppTokens.space12),
            OutlinedButton.icon(
              key: const Key('remote-nodes-open-rooms'),
              onPressed: onOpenRooms,
              icon: const Icon(Icons.meeting_room_outlined, size: 18),
              label: Text(strings.isZh ? '查看房间与设备' : 'View rooms and devices'),
            ),
          ],
        ],
      ),
    );
  }
}
