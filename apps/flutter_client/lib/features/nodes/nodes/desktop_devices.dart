part of '../nodes_page.dart';

class _DesktopDevices extends StatelessWidget {
  const _DesktopDevices({
    required this.state,
    required this.overview,
    required this.scopes,
    required this.selectedScopeId,
    required this.allPeers,
    required this.visiblePeers,
    required this.snapshot,
    required this.settings,
    required this.canManageDevices,
    required this.showLocal,
    required this.primaryStale,
  });

  final _NodesPageState state;
  final NetworkOverview overview;
  final List<NetworkScopeSnapshot> scopes;
  final String? selectedScopeId;
  final List<NetworkPeerSnapshot> allPeers;
  final List<NetworkPeerSnapshot> visiblePeers;
  final DiagnosticsSnapshot? snapshot;
  final AppSettings settings;
  final bool canManageDevices;
  final bool showLocal;
  final bool primaryStale;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final colors = P2WlanColors.of(context);
    final theme = Theme.of(context);
    final query = state._searchController.text.trim();
    final canRename =
        canManageDevices &&
        settings.hasAuthenticatedConnection &&
        !isRoomNetwork(settings.networkId) &&
        snapshot?.networkId == settings.networkId &&
        state._busyPeerId == null;
    final scopePicker = overview.hasRooms
        ? state._scopePicker(overview, selectedScopeId)
        : null;
    final header = Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (state.widget.showHeader) ...[
          PageHeading(
            title: strings.devices,
            subtitle: strings.isZh
                ? '查看和管理当前网络中的本机与其他设备。'
                : 'View and manage this device and others on your network.',
            toolbar: scopePicker,
          ),
          const SizedBox(height: AppTokens.space16),
        ] else if (scopePicker != null) ...[
          scopePicker,
          const SizedBox(height: AppTokens.space12),
        ],
        state._toolbar(allPeers, overview.hasRooms, desktop: true),
        if (primaryStale) ...[
          const SizedBox(height: AppTokens.space8),
          Row(
            children: [
              Icon(
                Icons.history_rounded,
                size: AppTokens.iconSm,
                color: colors.warningText,
              ),
              const SizedBox(width: AppTokens.space8),
              Text(
                strings.stale,
                style: theme.textTheme.bodySmall!.copyWith(
                  color: colors.warningText,
                ),
              ),
            ],
          ),
        ],
        if (showLocal) ...[
          const SizedBox(height: AppTokens.space24),
          _DesktopLocalDeviceCard(
            snapshot: snapshot,
            settings: settings,
            snapshotStale: primaryStale,
            daemonReachable: state.widget.statusStore.daemonReachable,
            onEdit: () => state._editLocalNode(snapshot),
          ),
        ],
        if (overview.hasRooms)
          _NetworkScopesSummary(
            scopes: scopes,
            selectedId: selectedScopeId,
            onOpenRoom: state.widget.onOpenRoom,
          ),
        const SizedBox(height: AppTokens.space24),
        _DesktopCatalogHeading(
          items: allPeers,
          scopeConnections: overview.hasRooms && selectedScopeId == null,
        ),
        const SizedBox(height: AppTokens.space12),
      ],
    );
    final Widget? emptyState = allPeers.isEmpty
        ? _EmptyNetworkDevices(
            scopes: scopes,
            onOpenRooms: state.widget.onOpenRooms,
          )
        : visiblePeers.isEmpty
        ? _NodesEmptyState(
            icon: query.isNotEmpty
                ? Icons.search_off_rounded
                : Icons.filter_alt_off_rounded,
            title: query.isNotEmpty
                ? strings.noSearchResultsTitle
                : strings.noFilterResultsTitle,
            body: query.isNotEmpty
                ? strings.noSearchResultsBody
                : strings.noFilterResultsBody,
            actionLabel: query.isNotEmpty
                ? strings.clearSearch
                : strings.clearFilter,
            onAction: query.isNotEmpty
                ? state._clearPeerSearch
                : state._clearPeerFilter,
          )
        : null;
    final rowIndexes = {
      for (final (index, item) in visiblePeers.indexed) item.identity: index,
    };

    return SafeArea(
      child: LayoutBuilder(
        builder: (context, constraints) {
          final gutter = AppTokens.desktopPageGutter(constraints.maxWidth);
          final maxWidth = math.min(
            math.max(0, constraints.maxWidth - gutter * 2),
            AppTokens.desktopPageMaxWidth,
          );
          final horizontalPadding = (constraints.maxWidth - maxWidth) / 2;
          return CustomScrollView(
            controller: state._scrollController,
            slivers: [
              SliverPadding(
                padding: EdgeInsets.fromLTRB(
                  horizontalPadding,
                  AppTokens.space20,
                  horizontalPadding,
                  AppTokens.space24,
                ),
                sliver: SliverMainAxisGroup(
                  slivers: [
                    SliverToBoxAdapter(child: header),
                    if (emptyState != null)
                      SliverToBoxAdapter(child: DesktopCard(child: emptyState))
                    else
                      DecoratedSliver(
                        decoration: DesktopCard.decorationOf(context),
                        sliver: SliverPadding(
                          padding: const EdgeInsets.all(1),
                          sliver: SliverMainAxisGroup(
                            slivers: [
                              const SliverToBoxAdapter(
                                child: DesktopDeviceListHeader(catalog: true),
                              ),
                              SliverList.builder(
                                itemCount: visiblePeers.length,
                                findChildIndexCallback: (key) => switch (key) {
                                  ValueKey<String>(:final value) =>
                                    rowIndexes[value],
                                  _ => null,
                                },
                                itemBuilder: (context, index) {
                                  final item = visiblePeers[index];
                                  final peer = item.peer;
                                  return DesktopDeviceRow(
                                    key: ValueKey(item.identity),
                                    rowKey: Key(
                                      'node-row-${item.isPrimary ? peer.nodeId : item.identity}',
                                    ),
                                    item: item,
                                    catalog: true,
                                    lastInCatalog:
                                        index == visiblePeers.length - 1,
                                    scopeLabel: overview.hasRooms
                                        ? item.roomName ??
                                              (strings.isZh
                                                  ? '当前网络'
                                                  : 'Current network')
                                        : null,
                                    selected:
                                        item.isPrimary &&
                                        state._selectedDesktopPeerId ==
                                            peer.nodeId,
                                    onOpen: () => state._openNetworkPeer(item),
                                    onWake: settings.hasAuthenticatedConnection
                                        ? () => state._openPeerWake(item)
                                        : null,
                                    onDiagnostics: item.isPrimary
                                        ? () => state._openPeer(
                                            peer,
                                            showDiagnostics: true,
                                          )
                                        : null,
                                    onSpeedTest:
                                        item.isPrimary &&
                                            item.current &&
                                            _canRunSpeedTest(peer)
                                        ? () => state._showSpeedTest(peer)
                                        : null,
                                    onRename:
                                        canRename &&
                                            item.isPrimary &&
                                            item.current &&
                                            item.roomId == null
                                        ? () => state._editDesktopPeer(item)
                                        : null,
                                  );
                                },
                              ),
                            ],
                          ),
                        ),
                      ),
                  ],
                ),
              ),
            ],
          );
        },
      ),
    );
  }
}

class _DesktopCatalogHeading extends StatelessWidget {
  const _DesktopCatalogHeading({
    required this.items,
    required this.scopeConnections,
  });

  final List<NetworkPeerSnapshot> items;
  final bool scopeConnections;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final online = items.where((item) => item.online).length;
    final offline = items.where((item) => item.current && !item.online).length;
    final stale = items.length - online - offline;
    final counts = strings.isZh
        ? ['$online 台在线', '$offline 台离线', if (stale > 0) '$stale 台待更新']
        : ['$online online', '$offline offline', if (stale > 0) '$stale stale'];
    return Wrap(
      alignment: WrapAlignment.spaceBetween,
      crossAxisAlignment: WrapCrossAlignment.center,
      spacing: AppTokens.space16,
      runSpacing: AppTokens.space4,
      children: [
        Semantics(
          header: true,
          child: Text(
            scopeConnections
                ? (strings.isZh ? '设备连接' : 'Device connections')
                : (strings.isZh ? '其他设备' : 'Other devices'),
            style: theme.textTheme.titleMedium!.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
        Text(
          counts.join('  ·  '),
          key: const Key('nodes-summary'),
          style: theme.textTheme.bodySmall!.copyWith(
            color: colors.textMuted,
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
      ],
    );
  }
}

class _DesktopLocalDeviceCard extends StatelessWidget {
  const _DesktopLocalDeviceCard({
    required this.snapshot,
    required this.settings,
    required this.snapshotStale,
    required this.daemonReachable,
    required this.onEdit,
  });

  final DiagnosticsSnapshot? snapshot;
  final AppSettings settings;
  final bool snapshotStale;
  final bool daemonReachable;
  final VoidCallback onEdit;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final primary = theme.colorScheme.primary;
    final largeText = MediaQuery.textScalerOf(context).scale(13) > 17;
    final (status, tone) = snapshotStale
        ? (strings.stale, StatusTone.warn)
        : snapshot != null
        ? (strings.online, StatusTone.good)
        : daemonReachable
        ? (strings.unavailable, StatusTone.neutral)
        : (strings.offline, StatusTone.neutral);
    final platform = switch (Platform.operatingSystem) {
      'macos' => 'macOS',
      'windows' => 'Windows',
      'linux' => 'Linux',
      _ => '',
    };
    final identity = Row(
      spacing: AppTokens.space16,
      children: [
        Container(
          width: 48,
          height: 48,
          alignment: Alignment.center,
          decoration: BoxDecoration(
            color: colors.selectedSurface,
            borderRadius: BorderRadius.circular(AppTokens.radiusMd),
          ),
          child: DesktopIcon('monitor', size: 23, color: primary),
        ),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            spacing: AppTokens.space4,
            children: [
              Wrap(
                spacing: AppTokens.space8,
                runSpacing: AppTokens.space4,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  Text(
                    dash(settings.deviceName),
                    maxLines: largeText ? null : 1,
                    overflow: largeText
                        ? TextOverflow.clip
                        : TextOverflow.ellipsis,
                    style: theme.textTheme.titleMedium!.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  DecoratedBox(
                    decoration: BoxDecoration(
                      color: colors.selectedSurface,
                      borderRadius: BorderRadius.circular(100),
                    ),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(
                        horizontal: AppTokens.space8,
                        vertical: AppTokens.space2,
                      ),
                      child: Text(
                        strings.isZh ? '本机' : strings.thisDeviceTitle,
                        style: theme.textTheme.labelSmall!.copyWith(
                          color: colors.successText,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ),
                ],
              ),
              if (platform.isNotEmpty)
                Text(
                  platform,
                  style: theme.textTheme.bodySmall!.copyWith(
                    color: colors.textMuted,
                  ),
                ),
            ],
          ),
        ),
      ],
    );
    final address = Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      spacing: AppTokens.space4,
      children: [
        Text(
          strings.isZh ? '虚拟 IP' : 'Virtual IP',
          style: theme.textTheme.labelSmall!.copyWith(color: colors.textMuted),
        ),
        Text(
          dash(snapshot?.virtualIp ?? ''),
          maxLines: largeText ? null : 1,
          overflow: largeText ? TextOverflow.clip : TextOverflow.ellipsis,
          style: theme.textTheme.bodyMedium!.copyWith(
            fontFeatures: AppTokens.tabularFontFeatures,
            fontWeight: FontWeight.w500,
          ),
        ),
      ],
    );
    final badge = StatusBadge(label: status, tone: tone, compact: true);
    final edit = OutlinedButton.icon(
      key: const Key('nodes-edit-local'),
      onPressed: onEdit,
      style: OutlinedButton.styleFrom(
        foregroundColor: colors.textPrimary,
        side: BorderSide(color: DesktopCard.borderOf(context)),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
        ),
        minimumSize: const Size(104, AppTokens.desktopControlHeight),
        padding: const EdgeInsets.symmetric(horizontal: AppTokens.space12),
        tapTargetSize: MaterialTapTargetSize.shrinkWrap,
      ),
      icon: const DesktopIcon('pencil', size: 14),
      label: Text(strings.isZh ? '编辑本机' : 'Edit device'),
    );
    return DesktopCard(
      key: const Key('nodes-local-row'),
      borderColor: tone == StatusTone.good ? colors.successBorder : null,
      padding: const EdgeInsets.symmetric(
        horizontal: AppTokens.space20,
        vertical: AppTokens.space16,
      ),
      child: ConstrainedBox(
        constraints: const BoxConstraints(minHeight: 64),
        child: LayoutBuilder(
          builder: (context, constraints) {
            if (constraints.maxWidth >= 540 && !largeText) {
              return Row(
                spacing: AppTokens.space24,
                children: [
                  Expanded(child: identity),
                  SizedBox(width: 136, child: address),
                  SizedBox(width: 80, child: badge),
                  edit,
                ],
              );
            }
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              spacing: AppTokens.space12,
              children: [
                identity,
                Wrap(
                  alignment: WrapAlignment.spaceBetween,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  spacing: AppTokens.space16,
                  runSpacing: AppTokens.space8,
                  children: [address, badge, edit],
                ),
              ],
            );
          },
        ),
      ),
    );
  }
}
