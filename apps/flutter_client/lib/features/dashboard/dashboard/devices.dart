part of '../dashboard_page.dart';

/// Online devices preview: a few quiet rows, whole rows tappable into the
/// selected device's detail surface. The right metrics read left-to-right as
/// speed, latency, then connection path without turning every row into a card.
class _OnlineDevicesSection extends StatelessWidget {
  const _OnlineDevicesSection({
    required this.peers,
    required this.peerTransferRates,
    required this.onOpenDevices,
    this.onOpenPeer,
  });

  final List<PeerSnapshot> peers;
  final Map<String, int> peerTransferRates;
  final VoidCallback? onOpenDevices;
  final ValueChanged<PeerSnapshot>? onOpenPeer;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(
              child: Text(
                strings.devices,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: theme.colorScheme.onSurface,
                  fontSize: 15,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 0,
                ),
              ),
            ),
            TextButton(
              key: const Key('home-view-all-devices'),
              onPressed: onOpenDevices,
              style: TextButton.styleFrom(
                visualDensity: VisualDensity.compact,
                padding: const EdgeInsets.symmetric(horizontal: 8),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(strings.viewAllDevices),
                  const SizedBox(width: 2),
                  const Icon(Icons.chevron_right_rounded, size: 16),
                ],
              ),
            ),
          ],
        ),
        const SizedBox(height: AppTokens.space4),
        if (peers.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  strings.noDevicesOnline,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface,
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                    height: 1.3,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  strings.noDevicesOnlineDetail,
                  style: TextStyle(
                    color: theme.colorScheme.onSurfaceVariant,
                    fontSize: 12,
                    height: 1.3,
                  ),
                ),
              ],
            ),
          )
        else
          for (var index = 0; index < peers.length; index++) ...[
            if (index > 0)
              const Padding(
                padding: EdgeInsets.symmetric(vertical: AppTokens.space4),
                child: Divider(height: 1),
              ),
            _DeviceRow(
              peer: peers[index],
              speedBytesPerSecond: peerTransferRates[peers[index].nodeId],
              onTap: onOpenPeer == null
                  ? onOpenDevices
                  : () => onOpenPeer!(peers[index]),
            ),
          ],
      ],
    );
  }
}

class _DeviceRow extends StatelessWidget {
  const _DeviceRow({
    required this.peer,
    required this.speedBytesPerSecond,
    this.onTap,
  });

  final PeerSnapshot peer;
  final int? speedBytesPerSecond;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final statusColor = _peerStatusColor(context, peer);
    final statusLabel = _peerStatusLabel(strings, peer);
    return SizedBox(
      width: double.infinity,
      child: InkWell(
        key: Key('home-device-row-${peer.nodeId}'),
        onTap: onTap,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        child: ConstrainedBox(
          constraints: const BoxConstraints(minHeight: 44),
          child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 6),
            child: LayoutBuilder(
              builder: (context, constraints) {
                final colors = P2WlanColors.of(context);
                final leading = Stack(
                  clipBehavior: Clip.none,
                  children: [
                    Container(
                      width: 32,
                      height: 32,
                      decoration: BoxDecoration(
                        color: colors.selectedSurface,
                        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
                      ),
                      child: Icon(
                        key: Key('home-device-icon-${peer.nodeId}'),
                        peerDeviceIcon(peer),
                        size: 17,
                        color: theme.colorScheme.primary,
                      ),
                    ),
                    Positioned(
                      right: -1,
                      bottom: -1,
                      child: Semantics(
                        label: statusLabel,
                        child: Container(
                          width: 9,
                          height: 9,
                          decoration: BoxDecoration(
                            color: statusColor,
                            shape: BoxShape.circle,
                            border: Border.all(
                              color: colors.surface,
                              width: 1.5,
                            ),
                          ),
                        ),
                      ),
                    ),
                  ],
                );
                final identity = Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Flexible(
                      child: Text(
                        peer.displayName,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                          color: theme.colorScheme.onSurface,
                          fontSize: constraints.maxWidth < 520 ? 11.5 : 13,
                          fontWeight: FontWeight.w600,
                          height: 1.2,
                        ),
                      ),
                    ),
                    Text(
                      ' · ',
                      maxLines: 1,
                      style: TextStyle(
                        color: theme.colorScheme.onSurfaceVariant,
                        fontSize: constraints.maxWidth < 520 ? 10.5 : 11.5,
                      ),
                    ),
                    Flexible(
                      child: Text(
                        dash(peer.virtualIp),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                          color: theme.colorScheme.onSurfaceVariant,
                          fontSize: constraints.maxWidth < 520 ? 10.5 : 11.5,
                          height: 1.2,
                          fontFeatures: AppTokens.tabularFontFeatures,
                        ),
                      ),
                    ),
                  ],
                );
                final chevron = Icon(
                  Icons.chevron_right_rounded,
                  size: 19,
                  color: theme.colorScheme.onSurfaceVariant,
                );
                final metrics = Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    _HomeMetricText(
                      value: formatTransferRate(speedBytesPerSecond),
                      width: constraints.maxWidth < 520 ? 38 : 58,
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                    SizedBox(width: constraints.maxWidth < 520 ? 2 : 6),
                    _HomeMetricText(
                      value: formatLatency(peer.latencyMs),
                      width: constraints.maxWidth < 520 ? 38 : 50,
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                    SizedBox(width: constraints.maxWidth < 520 ? 2 : 6),
                    _HomeMetricText(
                      value: statusLabel,
                      width: constraints.maxWidth < 520 ? 46 : 58,
                      color: statusColor,
                    ),
                  ],
                );

                return Row(
                  crossAxisAlignment: CrossAxisAlignment.center,
                  children: [
                    leading,
                    const SizedBox(width: AppTokens.space10),
                    Expanded(child: identity),
                    SizedBox(
                      width: constraints.maxWidth < 520 ? 132 : 186,
                      child: Align(
                        alignment: Alignment.centerRight,
                        child: metrics,
                      ),
                    ),
                    SizedBox(width: constraints.maxWidth < 520 ? 4 : 8),
                    chevron,
                  ],
                );
              },
            ),
          ),
        ),
      ),
    );
  }
}

class _HomeMetricText extends StatelessWidget {
  const _HomeMetricText({
    required this.value,
    required this.width,
    required this.color,
  });

  final String value;
  final double width;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: width,
      child: Text(
        value,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        textAlign: TextAlign.end,
        style: TextStyle(
          color: color,
          fontSize: 11,
          fontWeight: FontWeight.w600,
          height: 1.2,
          fontFeatures: AppTokens.tabularFontFeatures,
        ),
      ),
    );
  }
}
