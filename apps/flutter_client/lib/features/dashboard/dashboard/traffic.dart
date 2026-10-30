part of '../dashboard_page.dart';

class _TrafficOverviewSection extends StatelessWidget {
  const _TrafficOverviewSection({
    required this.statusStore,
    required this.selectedId,
  });
  final StatusStore statusStore;
  final String? selectedId;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final scopes = _trafficScopes(
      NetworkOverview.read(statusStore),
      selectedId,
    );
    final counters = _scopeCounters(scopes);
    final history = TrafficHistoryScope.maybeOf(context);
    final networkId = _trafficNetworkId(scopes, selectedId, statusStore);
    final saved = history?.store.summary(
      settings: history.settings,
      networkId: networkId,
    );
    final muted = Theme.of(context).colorScheme.onSurfaceVariant;
    return _DashboardSectionSurface(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  strings.isZh ? '流量统计' : 'Traffic usage',
                  style: const TextStyle(
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              TextButton.icon(
                key: const Key('home-traffic-details'),
                onPressed: () => showDialog<void>(
                  context: context,
                  builder: (_) => AppStringsScope(
                    strings: strings,
                    child: _TrafficDetailsDialog(
                      statusStore: statusStore,
                      selectedId: selectedId,
                    ),
                  ),
                ),
                label: Text(strings.isZh ? '查看详情' : 'Details'),
                icon: const Icon(Icons.chevron_right_rounded, size: 17),
                iconAlignment: IconAlignment.end,
              ),
            ],
          ),
          const SizedBox(height: 8),
          TrafficTotals(counters: counters, keyPrefix: 'home-traffic-current'),
          const SizedBox(height: 10),
          Wrap(
            spacing: 12,
            runSpacing: 6,
            children: [
              Text(
                scopes.any((scope) => !scope.isRunning)
                    ? (strings.isZh ? '上次记录' : 'Last recorded values')
                    : (strings.isZh ? '当前设备记录' : 'Current device records'),
                style: TextStyle(color: muted, fontSize: 12),
              ),
              if (history != null)
                Text(
                  '${strings.isZh ? '历史累计' : 'Saved total'}  ${formatOptionalBytes(saved?.counters.totalBytes)}',
                  key: const Key('home-traffic-history-total'),
                  style: TextStyle(
                    color: history.store.error == null
                        ? muted
                        : P2WlanColors.of(context).warningText,
                    fontSize: 12,
                    fontWeight: FontWeight.w500,
                  ),
                ),
            ],
          ),
        ],
      ),
    );
  }
}

List<NetworkScopeSnapshot> _trafficScopes(
  NetworkOverview overview,
  String? selectedId,
) => overview
    .selected(selectedId)
    .where(
      (scope) =>
          !scope.isPrimary || scope.snapshot != null || !overview.hasRooms,
    )
    .toList(growable: false);

TrafficCounters _scopeCounters(List<NetworkScopeSnapshot> scopes) =>
    TrafficCounters.combine([
      for (final scope in scopes)
        if (scope.snapshot case final snapshot?)
          TrafficCounters.fromSnapshot(snapshot)
        else
          const TrafficCounters(),
    ]);

String? _trafficNetworkId(
  List<NetworkScopeSnapshot> scopes,
  String? selectedId,
  StatusStore store,
) {
  if (selectedId == null) return null;
  if (selectedId.startsWith('room:')) return selectedId.substring(5);
  if (scopes.length == 1) {
    return scopes.single.snapshot?.networkId ??
        scopes.single.roomId ??
        store.settingsStore.settings.networkId;
  }
  // A removed selected room must never broaden into all-network history.
  return selectedId == NetworkOverview.primaryScopeId
      ? store.settingsStore.settings.networkId
      : '';
}

PeerTransferRate? _scopeRate(NetworkScopeSnapshot scope, StatusStore store) {
  if (!scope.isPrimary || !scope.isRunning || scope.snapshot == null) {
    return null;
  }
  final peers = scope.peers
      .where((item) => item.online)
      .toList(growable: false);
  if (peers.isEmpty) return null;
  final rates = store.peerDirectionalTransferRates;
  if (peers.any((item) => rates[item.peer.nodeId] == null)) return null;
  return PeerTransferRate(
    uploadBytesPerSecond: peers.fold(
      0,
      (sum, item) => sum + rates[item.peer.nodeId]!.uploadBytesPerSecond,
    ),
    downloadBytesPerSecond: peers.fold(
      0,
      (sum, item) => sum + rates[item.peer.nodeId]!.downloadBytesPerSecond,
    ),
  );
}

class _TrafficDetailsDialog extends StatelessWidget {
  const _TrafficDetailsDialog({
    required this.statusStore,
    required this.selectedId,
  });
  final StatusStore statusStore;
  final String? selectedId;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final muted = Theme.of(context).colorScheme.onSurfaceVariant;
    return Dialog(
      insetPadding: const EdgeInsets.all(16),
      child: ConstrainedBox(
        constraints: BoxConstraints(
          maxWidth: 660,
          maxHeight: MediaQuery.sizeOf(context).height * .88,
        ),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Text(
                      strings.isZh ? '流量详情' : 'Traffic details',
                      style: const TextStyle(
                        fontSize: 20,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                  IconButton(
                    onPressed: () => Navigator.of(context).pop(),
                    tooltip: strings.isZh ? '关闭' : 'Close',
                    icon: const Icon(Icons.close_rounded),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              Flexible(
                child: SingleChildScrollView(
                  child: AnimatedBuilder(
                    animation: Listenable.merge([
                      statusStore,
                      statusStore.parallelRooms,
                      statusStore.settingsStore,
                    ]),
                    builder: (context, _) {
                      final scopes = _trafficScopes(
                        NetworkOverview.read(statusStore),
                        selectedId,
                      );
                      return Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          Text(
                            strings.isZh ? '当前记录' : 'Current records',
                            style: const TextStyle(
                              fontSize: 14,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                          const SizedBox(height: 12),
                          TrafficTotals(
                            counters: _scopeCounters(scopes),
                            keyPrefix: 'traffic-detail-current',
                          ),
                          const SizedBox(height: 12),
                          Text(
                            strings.isZh
                                ? '统计本机与设备之间已记录的业务流量。服务重启或设备记录移除后，当前计数可能重置；已保存的历史累计保留。'
                                : 'Recorded traffic between this device and its peers. Current counters may reset after service restart or device-record removal; saved history is retained.',
                            style: TextStyle(
                              fontSize: 12,
                              height: 1.5,
                              color: muted,
                            ),
                          ),
                          const SizedBox(height: 20),
                          TrafficHistorySection(
                            networkId: _trafficNetworkId(
                              scopes,
                              selectedId,
                              statusStore,
                            ),
                          ),
                          const SizedBox(height: 20),
                          const Divider(),
                          const SizedBox(height: 12),
                          Text(
                            scopes.length > 1
                                ? (strings.isZh ? '按网络查看' : 'By network')
                                : (strings.isZh
                                      ? '连接信息'
                                      : 'Connection information'),
                            style: const TextStyle(
                              fontSize: 14,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                          for (final scope in scopes) ...[
                            const SizedBox(height: 14),
                            _NetworkTrafficDetail(
                              scope: scope,
                              statusStore: statusStore,
                              showCounters: scopes.length > 1,
                            ),
                          ],
                          const SizedBox(height: 16),
                          Text(
                            strings.isZh
                                ? '历史仅记录本机观察到的流量；应用未运行、数据缺失或异常退出时可能不完整。'
                                : 'History records traffic observed on this device. It may be incomplete while the app is not running, data is unavailable, or the app exits unexpectedly.',
                            style: TextStyle(
                              fontSize: 12,
                              height: 1.5,
                              color: muted,
                            ),
                          ),
                        ],
                      );
                    },
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _NetworkTrafficDetail extends StatelessWidget {
  const _NetworkTrafficDetail({
    required this.scope,
    required this.statusStore,
    required this.showCounters,
  });
  final NetworkScopeSnapshot scope;
  final StatusStore statusStore;
  final bool showCounters;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final rate = _scopeRate(scope, statusStore);
    final colors = P2WlanColors.of(context);
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: colors.surfaceMuted,
        borderRadius: BorderRadius.circular(10),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Wrap(
            spacing: 12,
            runSpacing: 4,
            children: [
              Text(
                networkScopeLabel(strings, scope),
                style: const TextStyle(fontWeight: FontWeight.w600),
              ),
              Text(
                networkDisplayStateLabel(strings, scope.state),
                style: TextStyle(color: colors.textSecondary, fontSize: 12),
              ),
            ],
          ),
          const SizedBox(height: 12),
          if (showCounters) ...[
            TrafficTotals(
              counters: scope.snapshot == null
                  ? const TrafficCounters()
                  : TrafficCounters.fromSnapshot(scope.snapshot!),
              keyPrefix: 'traffic-network-${scope.id}',
            ),
            const SizedBox(height: 12),
          ],
          Wrap(
            spacing: 16,
            runSpacing: 8,
            children: [
              Text(
                '${strings.isZh ? '上传速度' : 'Upload rate'}  ${formatTransferRate(rate?.uploadBytesPerSecond)}',
              ),
              Text(
                '${strings.isZh ? '下载速度' : 'Download rate'}  ${formatTransferRate(rate?.downloadBytesPerSecond)}',
              ),
              Text(
                '${strings.isZh ? '服务运行时长' : 'Service uptime'}  ${formatElapsedTime(scope.isRunning ? scope.snapshot?.reportedUptimeMs : null, isZh: strings.isZh)}',
              ),
            ],
          ),
        ],
      ),
    );
  }
}
