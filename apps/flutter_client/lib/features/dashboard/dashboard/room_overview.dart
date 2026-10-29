part of '../dashboard_page.dart';

class _RoomHomeOverview extends StatelessWidget {
  const _RoomHomeOverview({
    required this.overview,
    required this.selectedId,
    this.onOpenDevices,
    this.onOpenRooms,
    this.onOpenRoom,
    this.onOpenPeer,
  });

  final NetworkOverview overview;
  final String? selectedId;
  final VoidCallback? onOpenDevices;
  final VoidCallback? onOpenRooms;
  final ValueChanged<String>? onOpenRoom;
  final ValueChanged<PeerSnapshot>? onOpenPeer;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final scopes = overview.selected(selectedId);
    final peers = [for (final scope in scopes) ...scope.peers];
    final online = peers.where((item) => item.online).toList();
    final available = peers.where((item) => item.available).length;
    final (tone, label, _) = networkOverviewStatus(strings, overview);
    final selected = selectedId == null ? null : scopes.first;
    final displayedScopes = scopes.where(
      (scope) => !scope.isPrimary || scope.state != NetworkDisplayState.stopped,
    );
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _HeroSurface(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Wrap(
                alignment: WrapAlignment.spaceBetween,
                crossAxisAlignment: WrapCrossAlignment.center,
                spacing: 12,
                runSpacing: 8,
                children: [
                  Text(
                    strings.homeNetworkTitle,
                    style: const TextStyle(
                      fontSize: 15,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  StatusBadge(
                    label: selected == null
                        ? label
                        : networkDisplayStateLabel(strings, selected.state),
                    tone: selected == null
                        ? tone
                        : networkDisplayStateTone(selected.state),
                  ),
                ],
              ),
              const SizedBox(height: AppTokens.space16),
              Container(
                padding: const EdgeInsets.all(AppTokens.space16),
                decoration: BoxDecoration(
                  color: P2WlanColors.of(context).surfaceMuted,
                  borderRadius: BorderRadius.circular(AppTokens.radiusMd),
                ),
                child: Row(
                  children: [
                    Expanded(
                      child: _RoomHomeMetric(
                        label: strings.isZh ? '运行房间' : 'Running rooms',
                        value:
                            '${scopes.where((scope) => !scope.isPrimary && scope.isRunning).length}',
                      ),
                    ),
                    Expanded(
                      child: _RoomHomeMetric(
                        label: strings.isZh ? '在线连接' : 'Online connections',
                        value: '${online.length}',
                      ),
                    ),
                    Expanded(
                      child: _RoomHomeMetric(
                        label: strings.isZh ? '确认链路' : 'Confirmed paths',
                        value: '$available',
                        tooltip: strings.isZh ? '本机已确认的直连或中继路径；在线设备不一定已有可用路径。' : 'Direct or relay paths confirmed by this device. An online device may still be establishing a path.',
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: AppTokens.space16),
              for (final scope in displayedScopes)
                Material(
                  type: MaterialType.transparency,
                  child: ListTile(
                    key: Key('home-network-scope-${scope.id}'),
                    contentPadding: EdgeInsets.zero,
                    leading: Container(
                      width: 36,
                      height: 36,
                      decoration: BoxDecoration(
                        color: P2WlanColors.of(context).selectedSurface,
                        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
                      ),
                      child: Icon(
                        Icons.hub_outlined,
                        size: 19,
                        color: theme.colorScheme.primary,
                      ),
                    ),
                    title: Text(
                      networkScopeLabel(strings, scope),
                      style: const TextStyle(
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    subtitle: Text(
                      [
                        if (scope.snapshot?.virtualIp.isNotEmpty == true)
                          scope.snapshot!.virtualIp,
                        networkDisplayStateLabel(strings, scope.state),
                      ].join(' · '),
                      style: const TextStyle(fontSize: 12),
                    ),
                    trailing: const Icon(Icons.chevron_right_rounded, size: 20),
                    onTap: scope.roomId == null
                        ? onOpenDevices
                        : () => onOpenRoom?.call(scope.roomId!),
                  ),
                ),
              if (onOpenRooms != null)
                Align(
                  alignment: Alignment.centerLeft,
                  child: TextButton.icon(
                    onPressed: onOpenRooms,
                    icon: const Icon(Icons.meeting_room_outlined, size: 18),
                    label: Text(strings.isZh ? '管理房间' : 'Manage rooms'),
                  ),
                ),
            ],
          ),
        ),
        const SizedBox(height: AppTokens.space16),
        _DashboardSectionSurface(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Wrap(
                alignment: WrapAlignment.spaceBetween,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  Text(
                    strings.devices,
                    style: const TextStyle(
                      fontSize: 15,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  TextButton(
                    key: const Key('home-view-all-devices'),
                    onPressed: onOpenDevices,
                    child: Text(strings.viewAllDevices),
                  ),
                ],
              ),
              if (online.isEmpty) ...[
                const SizedBox(height: 8),
                Text(
                  strings.noDevicesOnline,
                  style: const TextStyle(
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  strings.isZh ? '查看房间的连接状态，或邀请其他设备加入同一房间。' : 'Check the room connection or invite another device to the same room.',
                  style: TextStyle(
                    fontSize: 12,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
                if (onOpenRooms != null)
                  Align(
                    alignment: Alignment.centerLeft,
                    child: OutlinedButton.icon(
                      onPressed: onOpenRooms,
                      icon: const Icon(Icons.group_add_outlined, size: 18),
                      label: Text(
                        strings.isZh ? '查看房间与邀请' : 'Rooms and invitations',
                      ),
                    ),
                  ),
              ] else
                for (final item in online.take(5))
                  _DeviceRow(
                    peer: item.peer,
                    scopeIdentity: item.identity,
                    roomName:
                        item.roomName ??
                        (strings.isZh ? '当前网络' : 'Current network'),
                    speedBytesPerSecond: item.transferBytesPerSecond,
                    onTap: item.isPrimary
                        ? (onOpenPeer == null
                              ? onOpenDevices
                              : () => onOpenPeer!(item.peer))
                        : () => onOpenRoom?.call(item.roomId!),
                  ),
            ],
          ),
        ),
      ],
    );
  }
}

class _RoomHomeMetric extends StatelessWidget {
  const _RoomHomeMetric({
    required this.label,
    required this.value,
    this.tooltip,
  });
  final String label;
  final String value;
  final String? tooltip;
  @override
  Widget build(BuildContext context) {
    final content = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(
          value,
          style: const TextStyle(
            fontSize: 28,
            fontWeight: FontWeight.w700,
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          label,
          style: TextStyle(
            fontSize: 12,
            height: 1.4,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
      ],
    );
    return tooltip == null
        ? content
        : Tooltip(message: tooltip!, child: content);
  }
}

class _RoomEntryAction extends StatelessWidget {
  const _RoomEntryAction({required this.onOpenRooms});
  final VoidCallback onOpenRooms;
  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final colors = P2WlanColors.of(context);
    return Material(
      color: colors.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        side: BorderSide(color: colors.border),
      ),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        key: const Key('home-open-rooms'),
        onTap: onOpenRooms,
        excludeFromSemantics: true,
        child: Semantics(
          container: true,
          button: true,
          onTap: onOpenRooms,
          child: Padding(
            padding: const EdgeInsets.all(AppTokens.space20),
            child: Row(
              children: [
                Container(
                  width: 40,
                  height: 40,
                  decoration: BoxDecoration(
                    color: colors.selectedSurface,
                    borderRadius: BorderRadius.circular(AppTokens.radiusMd),
                  ),
                  child: Icon(
                    Icons.group_add_outlined,
                    size: 21,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
                const SizedBox(width: AppTokens.space14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        strings.isZh ? '加入或创建房间' : 'Join or create a room',
                        style: const TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        strings.isZh
                            ? '与好友或自己的其他设备互联。'
                            : 'Connect with friends and your other devices.',
                        style: TextStyle(
                          fontSize: 12,
                          height: 1.5,
                          color: colors.textSecondary,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: AppTokens.space12),
                Icon(
                  Icons.arrow_forward_rounded,
                  size: 20,
                  color: colors.textSecondary,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
