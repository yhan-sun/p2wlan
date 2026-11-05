part of '../nodes_page.dart';

/// An empty runtime catalog is not evidence that a room has no registered
/// devices. Describe only the selected connection scopes and offer their roster.
class _EmptyNetworkDevices extends StatelessWidget {
  const _EmptyNetworkDevices({required this.scopes, this.onOpenRooms});

  final List<NetworkScopeSnapshot> scopes;
  final VoidCallback? onOpenRooms;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final starting = scopes.any(
      (scope) => scope.state == NetworkDisplayState.starting,
    );
    final current = scopes.any((scope) => scope.isRunning);
    final stopped = scopes.every(
      (scope) => scope.state == NetworkDisplayState.stopped,
    );
    final (title, body) = starting
        ? (
            strings.isZh ? '正在连接网络' : 'Connecting to the network',
            strings.isZh
                ? '连接完成后，设备状态会显示在这里。'
                : 'Device status will appear when the connection is ready.',
          )
        : current
        ? (
            strings.noPeersTitle,
            strings.isZh ? '可在房间中查看已加入的设备，或邀请其他设备加入同一房间。' : 'Open a room to view its registered devices or invite another device.',
          )
        : stopped
        ? (
            strings.isZh ? '本机尚未连接网络' : 'This device is not connected',
            strings.isZh ? '连接房间后查看实时设备状态；已加入的设备仍可在房间中查看。' : 'Connect to a room to see live device status. Registered devices remain available in Rooms.',
          )
        : (
            strings.isZh
                ? '暂时没有可用的设备状态'
                : 'Device status is currently unavailable',
            strings.isZh ? '请检查连接状态；已加入房间的设备名册仍可在房间中查看。' : 'Check the connection status. Open a room to view its registered devices.',
          );
    return _NodesEmptyState(
      icon: Icons.devices_other_rounded,
      title: title,
      body: body,
      actionLabel: stopped
          ? (strings.isZh ? '选择房间连接' : 'Choose a room to connect')
          : (strings.isZh ? '查看房间与设备' : 'View rooms and devices'),
      onAction: onOpenRooms,
    );
  }
}

/// Scope detail stays available without putting the room directory before the
/// device list. A selected room needs only its current state and local address.
class _NetworkScopesSummary extends StatefulWidget {
  const _NetworkScopesSummary({
    required this.scopes,
    required this.selectedId,
    this.onOpenRoom,
  });

  final List<NetworkScopeSnapshot> scopes;
  final String? selectedId;
  final ValueChanged<String>? onOpenRoom;

  @override
  State<_NetworkScopesSummary> createState() => _NetworkScopesSummaryState();
}

class _NetworkScopesSummaryState extends State<_NetworkScopesSummary> {
  var _expanded = false;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final colors = P2WlanColors.of(context);
    final rooms = widget.scopes.where((scope) => !scope.isPrimary).toList();
    if (rooms.isEmpty) return const SizedBox.shrink();
    if (widget.selectedId != null && rooms.length == 1) {
      final scope = rooms.single;
      final text = [
        networkDisplayStateLabel(strings, scope.state),
        if (scope.snapshot?.virtualIp.isNotEmpty == true)
          '${strings.isZh ? '本机 IP' : 'Local IP'} ${scope.snapshot!.virtualIp}',
      ].join(' · ');
      return Semantics(
        label: networkScopeLabel(strings, scope),
        child: InkWell(
          key: Key('nodes-network-scope-${scope.id}'),
          onTap: widget.onOpenRoom == null
              ? null
              : () => widget.onOpenRoom!(scope.roomId!),
          child: ConstrainedBox(
            constraints: const BoxConstraints(
              minHeight: AppTokens.minTouchTarget,
            ),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      text,
                      style: TextStyle(
                        fontSize: 12,
                        color: colors.textSecondary,
                      ),
                    ),
                  ),
                  if (widget.onOpenRoom != null)
                    const Icon(Icons.chevron_right_rounded, size: 18),
                ],
              ),
            ),
          ),
        ),
      );
    }

    final attention = rooms.where(networkScopeNeedsAttention).length;
    int count(NetworkDisplayState state) =>
        rooms.where((scope) => scope.state == state).length;
    final running = count(NetworkDisplayState.running);
    final starting = count(NetworkDisplayState.starting);
    final stopping = count(NetworkDisplayState.stopping);
    final stopped = count(NetworkDisplayState.stopped);
    final summary = [
      strings.isZh ? '${rooms.length} 个房间' : '${rooms.length} rooms',
      if (attention > 0)
        strings.isZh ? '$attention 个需处理' : '$attention need attention',
      if (running > 0) strings.isZh ? '$running 个运行中' : '$running running',
      if (starting > 0)
        strings.isZh ? '$starting 个连接中' : '$starting connecting',
      if (stopping > 0)
        strings.isZh ? '$stopping 个断开中' : '$stopping disconnecting',
      if (stopped > 0) strings.isZh ? '$stopped 个未连接' : '$stopped disconnected',
    ].join(' · ');
    return Column(
      key: const Key('nodes-scopes-summary'),
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.only(left: 14, right: 6),
          child: LayoutBuilder(
            builder: (context, constraints) {
              final label = Text(
                summary,
                style: TextStyle(
                  fontSize: 12,
                  color: attention > 0
                      ? colors.warningText
                      : colors.textSecondary,
                ),
              );
              final action = MergeSemantics(
                child: Semantics(
                  expanded: _expanded,
                  child: TextButton.icon(
                    key: const Key('nodes-scopes-toggle'),
                    onPressed: () => setState(() => _expanded = !_expanded),
                    icon: Icon(
                      _expanded
                          ? Icons.expand_less_rounded
                          : Icons.expand_more_rounded,
                      size: 18,
                    ),
                    label: Text(strings.isZh ? '网络详情' : 'Network details'),
                    iconAlignment: IconAlignment.end,
                  ),
                ),
              );
              if (constraints.maxWidth < 300 ||
                  MediaQuery.textScalerOf(context).scale(14) > 18) {
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [label, action],
                );
              }
              return Row(
                children: [
                  Expanded(child: label),
                  action,
                ],
              );
            },
          ),
        ),
        if (_expanded)
          for (final scope in rooms)
            _RoomNodeScopeSummary(scope: scope, onOpenRoom: widget.onOpenRoom),
      ],
    );
  }
}

class _RoomNodeScopeSummary extends StatelessWidget {
  const _RoomNodeScopeSummary({required this.scope, this.onOpenRoom});
  final NetworkScopeSnapshot scope;
  final ValueChanged<String>? onOpenRoom;
  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    return Padding(
      padding: const EdgeInsets.only(top: 8),
      child: ListTile(
        key: Key('nodes-network-scope-${scope.id}'),
        contentPadding: const EdgeInsets.symmetric(horizontal: 14),
        leading: const Icon(Icons.hub_outlined, size: 21),
        title: Text(
          networkScopeLabel(strings, scope),
          style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600),
        ),
        subtitle: Text(
          [
            networkDisplayStateLabel(strings, scope.state),
            if (scope.snapshot?.virtualIp.isNotEmpty == true)
              '${strings.isZh ? '本机' : 'This device'}: ${scope.snapshot!.virtualIp}',
          ].join(' · '),
          style: const TextStyle(fontSize: 12, height: 1.4),
        ),
        trailing: const Icon(Icons.chevron_right_rounded, size: 20),
        onTap: onOpenRoom == null ? null : () => onOpenRoom!(scope.roomId!),
      ),
    );
  }
}
