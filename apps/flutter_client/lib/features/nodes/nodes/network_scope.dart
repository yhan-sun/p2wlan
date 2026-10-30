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
