part of '../diagnostics_page.dart';

/// A summary follows the primary conclusion. Room details are only built when
/// requested; each action still opens the room that owns that runtime.
class _RoomConnectionsPanel extends StatelessWidget {
  const _RoomConnectionsPanel({
    required this.scopes,
    required this.open,
    required this.onToggle,
    this.onOpenRoom,
    this.onOpenRooms,
  });

  final List<NetworkScopeSnapshot> scopes;
  final bool open;
  final VoidCallback onToggle;
  final ValueChanged<String>? onOpenRoom;
  final VoidCallback? onOpenRooms;

  static int _priority(NetworkDisplayState state) => switch (state) {
    NetworkDisplayState.failed => 0,
    NetworkDisplayState.unavailable => 1,
    NetworkDisplayState.attention => 2,
    NetworkDisplayState.stale => 3,
    NetworkDisplayState.starting => 4,
    NetworkDisplayState.stopping => 5,
    NetworkDisplayState.stopped => 6,
    NetworkDisplayState.running => 7,
  };

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    final attention = scopes
        .where((scope) => _priority(scope.state) <= 3)
        .length;
    final running = scopes.where((scope) => scope.isRunning).length;
    final summary = attention > 0
        ? (strings.isZh
              ? '${scopes.length} 个房间 · $attention 个需处理'
              : '${scopes.length} rooms · $attention ${attention == 1 ? 'needs' : 'need'} attention')
        : (strings.isZh
              ? '${scopes.length} 个房间 · $running 个运行中'
              : '${scopes.length} rooms · $running running');
    final ordered = scopes.indexed.toList()
      ..sort((a, b) {
        final priority = _priority(a.$2.state).compareTo(_priority(b.$2.state));
        return priority != 0 ? priority : a.$1.compareTo(b.$1);
      });
    return Material(
      color: colors.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        side: BorderSide(color: colors.border),
      ),
      clipBehavior: Clip.antiAlias,
      child: Column(
        children: [
          Semantics(
            button: true,
            expanded: open,
            onTap: onToggle,
            child: InkWell(
              key: const Key('diagnostics-room-connections-toggle'),
              excludeFromSemantics: true,
              onTap: onToggle,
              child: Padding(
                padding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 14,
                ),
                child: Row(
                  children: [
                    Icon(
                      Icons.meeting_room_outlined,
                      size: 20,
                      color: attention > 0
                          ? colors.warningText
                          : colors.textSecondary,
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            strings.isZh ? '房间连接' : 'Rooms',
                            style: const TextStyle(
                              fontSize: 14,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            summary,
                            style: TextStyle(
                              fontSize: 13,
                              height: 1.4,
                              color: attention > 0
                                  ? colors.warningText
                                  : colors.textSecondary,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 12),
                    Icon(
                      open
                          ? Icons.expand_less_rounded
                          : Icons.expand_more_rounded,
                      color: colors.textSecondary,
                      size: 20,
                    ),
                  ],
                ),
              ),
            ),
          ),
          if (open)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
              child: Column(
                children: [
                  for (var index = 0; index < ordered.length; index++) ...[
                    Divider(height: 1, color: colors.divider),
                    _RoomConnectionRow(
                      scope: ordered[index].$2,
                      onOpen: onOpenRoom != null
                          ? () => onOpenRoom!(ordered[index].$2.roomId!)
                          : onOpenRooms,
                    ),
                  ],
                  if (onOpenRooms != null)
                    Align(
                      alignment: Alignment.centerRight,
                      child: TextButton(
                        key: const Key('diagnostics-open-rooms'),
                        onPressed: onOpenRooms,
                        child: Text(strings.isZh ? '所有房间' : 'All rooms'),
                      ),
                    ),
                ],
              ),
            ),
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
    return ListTile(
      key: ValueKey('diagnostics-room-${scope.roomId}'),
      contentPadding: EdgeInsets.zero,
      minVerticalPadding: 10,
      title: Text(
        networkScopeLabel(strings, scope),
        style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600),
      ),
      subtitle: Text(
        networkDisplayStateLabel(strings, scope.state),
        style: TextStyle(fontSize: 12, height: 1.5, color: colors.text),
      ),
      trailing: onOpen == null
          ? null
          : const Icon(Icons.chevron_right_rounded, size: 20),
      onTap: onOpen,
    );
  }
}
