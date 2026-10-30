part of '../nodes_page.dart';

/// Pure presentation of counters and an optional rate from one owning scope.
class _PeerTrafficSection extends StatelessWidget {
  const _PeerTrafficSection({
    required this.counters,
    required this.strings,
    required this.current,
    this.transferBytesPerSecond,
    this.localScope = false,
    this.serviceUptimeMs,
    this.networkId,
    this.peerId,
  });

  final TrafficCounters counters;
  final AppStrings strings;
  final bool current;
  final int? transferBytesPerSecond;
  final bool localScope;
  final int? serviceUptimeMs;
  final String? networkId;
  final String? peerId;

  @override
  Widget build(BuildContext context) => _DetailSection(
    key: const Key('peer-detail-traffic-card'),
    title: strings.isZh ? '当前记录流量' : 'Current recorded traffic',
    icon: Icons.swap_vert_rounded,
    rows: [
      Padding(
        padding: const EdgeInsets.symmetric(vertical: 8),
        child: TrafficTotals(counters: counters, keyPrefix: 'peer-traffic'),
      ),
      _DetailLine(
        label: strings.isZh ? '当前速率（合计）' : 'Current combined rate',
        value: formatTransferRate(current ? transferBytesPerSecond : null),
      ),
      if (localScope)
        _DetailLine(
          label: strings.isZh ? '服务运行时长' : 'Service uptime',
          value: formatElapsedTime(
            current ? serviceUptimeMs : null,
            isZh: strings.isZh,
          ),
        ),
      Padding(
        padding: const EdgeInsets.only(top: 8, bottom: 10),
        child: Text(
          strings.isZh
              ? '${localScope ? '本机在此网络的业务流量' : '本机与此设备的业务流量'}；服务重启或设备记录移除后重新累计。${current ? '' : ' 当前显示最近一次记录，速率不可用。'}'
              : '${localScope ? 'This client’s data traffic on this network' : 'This client’s data traffic with this device'}; counters restart after service restart or device record removal.${current ? '' : ' Showing the last recorded totals; live rate unavailable.'}',
          style: TextStyle(
            fontSize: 12,
            height: 1.45,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
      ),
      if (networkId != null)
        Padding(
          padding: const EdgeInsets.only(top: 12),
          child: TrafficHistorySection(
            networkId: networkId,
            peerId: localScope ? null : peerId,
          ),
        ),
    ],
  );
}
