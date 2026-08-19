part of '../dashboard_page.dart';

/// Online devices preview: 3–5 rows, dividers instead of cards, whole rows
/// tappable into the Devices page.
class _OnlineDevicesSection extends StatelessWidget {
  const _OnlineDevicesSection({
    required this.peers,
    required this.onOpenDevices,
  });

  final List<PeerSnapshot> peers;
  final VoidCallback? onOpenDevices;

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
            if (index > 0) const Divider(height: 1),
            _DeviceRow(peer: peers[index], onTap: onOpenDevices),
          ],
      ],
    );
  }
}

class _DeviceRow extends StatelessWidget {
  const _DeviceRow({required this.peer, this.onTap});

  final PeerSnapshot peer;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final statusColor = _peerStatusColor(context, peer);
    final statusLabel = _peerStatusLabel(strings, peer);
    return InkWell(
      key: const Key('home-device-row'),
      onTap: onTap,
      child: ConstrainedBox(
        constraints: const BoxConstraints(minHeight: 44),
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 6),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              Container(
                width: 8,
                height: 8,
                decoration: BoxDecoration(
                  color: statusColor,
                  shape: BoxShape.circle,
                ),
              ),
              const SizedBox(width: AppTokens.space10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      peer.displayName,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        color: theme.colorScheme.onSurface,
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                        height: 1.25,
                      ),
                    ),
                    Text(
                      dash(peer.virtualIp),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        color: theme.colorScheme.onSurfaceVariant,
                        fontSize: 11.5,
                        height: 1.2,
                        fontFeatures: AppTokens.tabularFontFeatures,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: AppTokens.space12),
              Text(
                statusLabel,
                maxLines: 1,
                style: TextStyle(
                  color: statusColor,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  height: 1.2,
                ),
              ),
              const SizedBox(width: AppTokens.space8),
              Text(
                _peerLatencyLabel(strings, peer),
                maxLines: 1,
                style: TextStyle(
                  color: theme.colorScheme.onSurface,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  height: 1.2,
                  fontFeatures: AppTokens.tabularFontFeatures,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
