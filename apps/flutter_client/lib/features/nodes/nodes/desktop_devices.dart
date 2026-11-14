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
  final bool showLocal;
  final bool primaryStale;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    final colors = P2WlanColors.of(context);
    final theme = Theme.of(context);
    final query = state._searchController.text.trim();
    final catalogHeader = DesktopDeviceListHeader(
      identityLabel: overview.hasRooms
          ? strings.deviceName
          : (strings.isZh ? '其他设备' : 'Other devices'),
    );
    final scopePicker = overview.hasRooms
        ? state._scopePicker(overview, selectedScopeId)
        : null;
    final header = Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (state.widget.showHeader) ...[
          PageHeading(
            title: strings.devices,
            subtitle: '',
            toolbar: scopePicker,
          ),
          const SizedBox(height: AppTokens.space16),
        ] else if (scopePicker != null) ...[
          scopePicker,
          const SizedBox(height: AppTokens.space8),
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
          const SizedBox(height: AppTokens.space16),
          _LocalNodePanel(
            snapshot: snapshot,
            settings: settings,
            snapshotStale: primaryStale,
            daemonReachable: state.widget.statusStore.daemonReachable,
            desktop: true,
            onEdit: () => state._editLocalNode(snapshot),
          ),
        ],
        if (overview.hasRooms)
          _NetworkScopesSummary(
            scopes: scopes,
            selectedId: selectedScopeId,
            onOpenRoom: state.widget.onOpenRoom,
          ),
        const SizedBox(height: AppTokens.space16),
        catalogHeader,
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
      for (final (index, item) in visiblePeers.indexed)
        item.identity: index + 1,
    };

    return SafeArea(
      child: LayoutBuilder(
        builder: (context, constraints) {
          final gutter = constraints.maxWidth < 480
              ? AppTokens.space16
              : AppTokens.desktopPagePadding;
          final maxWidth = math.min(
            math.max(0, constraints.maxWidth - gutter * 2),
            nodesPageMaxWidth,
          );
          final horizontalPadding = (constraints.maxWidth - maxWidth) / 2;
          return ListView.builder(
            controller: state._scrollController,
            padding: EdgeInsets.fromLTRB(
              horizontalPadding,
              AppTokens.space20,
              horizontalPadding,
              AppTokens.space24,
            ),
            itemCount: emptyState == null ? visiblePeers.length + 1 : 2,
            findChildIndexCallback: (key) => switch (key) {
              ValueKey<String>(:final value) => rowIndexes[value],
              _ => null,
            },
            itemBuilder: (context, index) {
              if (index == 0) return header;
              if (emptyState != null) return emptyState;
              final item = visiblePeers[index - 1];
              final peer = item.peer;
              return DesktopDeviceRow(
                key: ValueKey(item.identity),
                rowKey: Key(
                  'node-row-${item.isPrimary ? peer.nodeId : item.identity}',
                ),
                item: item,
                scopeLabel: overview.hasRooms
                    ? (item.roomName ??
                          (strings.isZh ? '当前网络' : 'Current network'))
                    : null,
                selected:
                    item.isPrimary &&
                    state._selectedDesktopPeerId == peer.nodeId,
                onOpen: () => state._openNetworkPeer(item),
                onDiagnostics: item.isPrimary
                    ? () => state._openPeer(peer, showDiagnostics: true)
                    : null,
                onSpeedTest:
                    item.isPrimary && item.current && _canRunSpeedTest(peer)
                    ? () => state._showSpeedTest(peer)
                    : null,
              );
            },
          );
        },
      ),
    );
  }
}
