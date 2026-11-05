part of '../dashboard_page.dart';

class _RoomHomeOverview extends StatelessWidget {
  const _RoomHomeOverview({
    required this.overview,
    required this.selectedId,
    required this.trafficSection,
    required this.statusStore,
    this.onOpenDevices,
    this.onOpenRooms,
    this.onOpenRoom,
    this.onOpenPeer,
    this.onOpenRoomDevice,
    this.onOpenTroubleshooting,
    this.onReauthenticate,
  });

  final NetworkOverview overview;
  final String? selectedId;
  final Widget trafficSection;
  final VoidCallback? onOpenDevices;
  final VoidCallback? onOpenRooms;
  final ValueChanged<String>? onOpenRoom;
  final ValueChanged<PeerSnapshot>? onOpenPeer;
  final void Function(String roomId, String deviceId)? onOpenRoomDevice;
  final VoidCallback? onOpenTroubleshooting;
  final VoidCallback? onReauthenticate;
  final StatusStore statusStore;

  String _issueReason(AppStrings strings, NetworkScopeSnapshot scope) {
    final health = scope.snapshot?.health;
    if (health?.reauthRequired == true) return strings.issueReauthRequired;
    final message = scope.roomId == null
        ? null
        : statusStore.parallelRooms.sessions[scope.roomId]?.message;
    if (message != null && message.trim().isNotEmpty) {
      return RoomStrings(strings.isZh).runtimeText(message);
    }
    if (scope.state == NetworkDisplayState.stale) return strings.homeStaleNote;
    if (health != null && !health.controlConnected) {
      if (health.controlApiReachable && !health.deviceLeaseHealthy) {
        return strings.issueDeviceLeaseLost;
      }
      return strings.issueControlDisconnected;
    }
    if (health?.criticalTasks.any((task) => task.error != null) == true) {
      return strings.issueCriticalTaskDetail;
    }
    if (scope.snapshot?.relaySelection.lastError?.isNotEmpty == true) {
      return strings.issueRelayDetail;
    }
    if (scope.state == NetworkDisplayState.attention) {
      return strings.issueServiceStatusDetail;
    }
    return networkDisplayStateLabel(strings, scope.state);
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final scopes = overview.selected(selectedId);
    final peers = [for (final scope in scopes) ...scope.peers];
    final online = peers.where((item) => item.online).toList();
    final available = peers.where((item) => item.available).length;
    final running = scopes
        .where((scope) => !scope.isPrimary && scope.isRunning)
        .length;
    final (tone, label, _) = networkOverviewStatus(strings, overview);
    final selected = selectedId == null ? null : scopes.first;
    final selectedRoomId = selected?.roomId;
    final VoidCallback? roomAction =
        selectedRoomId != null && onOpenRoom != null
        ? () => onOpenRoom!(selectedRoomId)
        : onOpenRooms;
    final hasRunning = scopes.any((scope) => scope.isRunning);
    final hasRoom = scopes.any((scope) => scope.roomId != null);
    final roomActionLabel = !hasRoom
        ? (strings.isZh ? '查看房间' : 'View rooms')
        : !hasRunning
        ? (strings.isZh ? '连接房间' : 'Connect a room')
        : selectedRoomId != null && onOpenRoom != null
        ? (strings.isZh ? '邀请设备' : 'Invite a device')
        : (strings.isZh ? '选择房间邀请' : 'Choose a room to invite');
    final displayedScopes = scopes
        .where(
          (scope) =>
              !scope.isPrimary || scope.state != NetworkDisplayState.stopped,
        )
        .toList();
    final issues = displayedScopes.where(networkScopeNeedsAttention).toList();
    final issue = issues.isEmpty ? null : issues.first;
    final requiresReauth = issue?.snapshot?.health.reauthRequired == true;
    final VoidCallback? recovery = issue == null
        ? null
        : requiresReauth && onReauthenticate != null
        ? onReauthenticate
        : issue.roomId != null && onOpenRoom != null
        ? () => onOpenRoom!(issue.roomId!)
        : onOpenTroubleshooting;
    final colors = P2WlanColors.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _HeroSurface(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (issue != null)
                _HomeIssueBanner(
                  key: const Key('home-room-issue'),
                  title: strings.isZh
                      ? '${issues.length} 个网络需处理'
                      : '${issues.length} ${issues.length == 1 ? 'network needs' : 'networks need'} attention',
                  message:
                      '${networkScopeLabel(strings, issue)}${strings.isZh ? '：' : ': '}${_issueReason(strings, issue)}',
                  tone: StatusTone.warn,
                  onOpenTroubleshooting: recovery,
                  actionLabel: requiresReauth && onReauthenticate != null
                      ? (strings.isZh ? '重新登录' : 'Sign in again')
                      : issue.roomId != null && onOpenRoom != null
                      ? (strings.isZh ? '处理此房间' : 'Resolve this room')
                      : (strings.isZh ? '查看连接问题' : 'Review connection issues'),
                  actionKey: const Key('home-resolve-room-issue'),
                  primaryAction: true,
                )
              else
                Wrap(
                  alignment: WrapAlignment.spaceBetween,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  spacing: AppTokens.space12,
                  runSpacing: AppTokens.space8,
                  children: [
                    StatusBadge(
                      label: selected == null
                          ? label
                          : networkDisplayStateLabel(strings, selected.state),
                      tone: selected == null
                          ? tone
                          : networkDisplayStateTone(selected.state),
                    ),
                    if (roomAction != null)
                      FilledButton.icon(
                        key: const Key('home-room-action'),
                        onPressed: roomAction,
                        icon: const Icon(Icons.group_add_outlined, size: 18),
                        label: Text(roomActionLabel),
                      ),
                  ],
                ),
              const SizedBox(height: AppTokens.space8),
              Wrap(
                spacing: AppTokens.space16,
                runSpacing: AppTokens.space6,
                children: [
                  _RoomHomeMetric(
                    label: strings.isZh ? '运行房间' : 'Running rooms',
                    value: '$running',
                  ),
                  _RoomHomeMetric(
                    label: strings.isZh ? '在线连接' : 'Online connections',
                    value: '${online.length}',
                  ),
                  _RoomHomeMetric(
                    label: strings.isZh ? '确认链路' : 'Confirmed paths',
                    value: '$available',
                    tooltip: strings.isZh ? '本机已确认的直连或中继路径；在线设备不一定已有可用路径。' : 'Direct or relay paths confirmed by this device. An online device may still be establishing a path.',
                  ),
                ],
              ),
              if (displayedScopes.isNotEmpty)
                ExpansionTile(
                  key: const Key('home-room-connections-details'),
                  tilePadding: EdgeInsets.zero,
                  childrenPadding: const EdgeInsets.only(top: AppTokens.space4),
                  minTileHeight: AppTokens.minTouchTarget,
                  dense: true,
                  shape: const Border(),
                  collapsedShape: const Border(),
                  expansionAnimationStyle: AppMotion.expansionStyleOf(context),
                  title: Text(
                    strings.isZh ? '房间连接详情' : 'Room connection details',
                    style: TextStyle(fontSize: 13, color: colors.textSecondary),
                  ),
                  children: [
                    for (final scope in displayedScopes)
                      ListTile(
                        key: Key('home-network-scope-${scope.id}'),
                        contentPadding: EdgeInsets.zero,
                        dense: true,
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
                        trailing: const Icon(
                          Icons.chevron_right_rounded,
                          size: 20,
                        ),
                        onTap: scope.roomId == null
                            ? onOpenDevices
                            : () => onOpenRoom?.call(scope.roomId!),
                      ),
                  ],
                ),
            ],
          ),
        ),
        const SizedBox(height: AppTokens.space16),
        _DashboardDetailsLayout(
          traffic: trafficSection,
          devices: _DashboardSectionSurface(
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
                  const SizedBox(height: AppTokens.space8),
                  Text(
                    strings.noDevicesOnline,
                    style: const TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: AppTokens.space4),
                  Text(
                    strings.isZh ? '邀请其他设备加入同一房间，连接后即可在这里查看。' : 'Invite another device to the same room to see it here.',
                    style: TextStyle(fontSize: 13, color: colors.textSecondary),
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
                          : () {
                              if (onOpenRoomDevice != null) {
                                onOpenRoomDevice!(
                                  item.roomId!,
                                  item.peer.nodeId,
                                );
                              } else {
                                onOpenRoom?.call(item.roomId!);
                              }
                            },
                    ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

/// A compact, wrapping summary rather than a separate dashboard tile.
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
    final content = Wrap(
      spacing: AppTokens.space4,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        Text(
          value,
          style: const TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w600,
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
        Text(
          label,
          style: TextStyle(
            fontSize: 13,
            color: P2WlanColors.of(context).textSecondary,
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
