part of '../diagnostics_page.dart';

/// The shell status includes these independent runtime owners. Keep them
/// visible here, and send recovery to their own room instead of the primary
/// daemon's restart action.
class _RoomConnectionsPanel extends StatelessWidget {
  const _RoomConnectionsPanel({
    required this.scopes,
    this.onOpenRoom,
    this.onOpenRooms,
  });

  final List<NetworkScopeSnapshot> scopes;
  final ValueChanged<String>? onOpenRoom;
  final VoidCallback? onOpenRooms;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AppPanel(
      title: strings.isZh ? '房间连接' : 'Rooms',
      trailing: onOpenRooms == null
          ? null
          : TextButton(
              key: const Key('diagnostics-open-rooms'),
              onPressed: onOpenRooms,
              child: Text(strings.isZh ? '所有房间' : 'All rooms'),
            ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            strings.isZh ? '每个房间独立运行。选择房间查看设备或处理连接问题。' : 'Each room runs independently. Open a room to check its devices or connection.',
            style: TextStyle(
              fontSize: 13,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: AppTokens.space12),
          for (var index = 0; index < scopes.length; index++) ...[
            if (index > 0) const Divider(height: AppTokens.space20),
            _RoomConnectionRow(
              scope: scopes[index],
              onOpen: onOpenRoom != null
                  ? () => onOpenRoom!(scopes[index].roomId!)
                  : onOpenRooms,
            ),
          ],
        ],
      ),
    );
  }
}

class _RoomConnectionRow extends StatelessWidget {
  const _RoomConnectionRow({required this.scope, this.onOpen});

  final NetworkScopeSnapshot scope;
  final VoidCallback? onOpen;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = _tonePanelColors(
      context,
      networkDisplayStateTone(scope.state),
    );
    final content = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          networkScopeLabel(strings, scope),
          style: const TextStyle(fontWeight: FontWeight.w600),
        ),
        const SizedBox(height: AppTokens.space6),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
          decoration: BoxDecoration(
            color: colors.bg,
            border: Border.all(color: colors.border),
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          ),
          child: Text(
            networkDisplayStateLabel(strings, scope.state),
            style: TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w600,
              color: colors.text,
            ),
          ),
        ),
      ],
    );
    if (onOpen == null) return content;
    final action = OutlinedButton.icon(
      key: ValueKey('diagnostics-room-${scope.roomId}'),
      onPressed: onOpen,
      icon: const Icon(Icons.arrow_forward_rounded, size: 16),
      label: Text(strings.isZh ? '查看房间' : 'Open room'),
    );
    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 440 ||
            MediaQuery.textScalerOf(context).scale(14) > 20) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              content,
              const SizedBox(height: AppTokens.space8),
              action,
            ],
          );
        }
        return Row(
          children: [
            Expanded(child: content),
            const SizedBox(width: AppTokens.space12),
            action,
          ],
        );
      },
    );
  }
}
