part of '../dashboard_page.dart';

class _PeerOverview extends StatelessWidget {
  const _PeerOverview({
    required this.snapshot,
    required this.peers,
    required this.totalPeers,
    required this.showMap,
  });

  final DiagnosticsSnapshot? snapshot;
  final List<PeerSnapshot> peers;
  final int totalPeers;
  final bool showMap;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          strings.connectionOverview,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            color: theme.colorScheme.onSurface,
            fontSize: 14,
            fontWeight: FontWeight.w700,
            letterSpacing: 0,
          ),
        ),
        const SizedBox(height: 14),
        if (showMap) ...[
          _ConnectionMap(peers: peers),
          const SizedBox(height: 18),
        ],
        if (peers.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 10),
            child: Text(
              strings.noOnlineDevices,
              style: TextStyle(
                color: theme.colorScheme.onSurfaceVariant,
                fontSize: 13,
                height: 1.3,
              ),
            ),
          ),
        for (var index = 0; index < peers.length; index++) ...[
          if (index > 0) const Divider(height: 1),
          _PeerRow(peer: peers[index]),
        ],
        if (totalPeers > peers.length) ...[
          const Divider(height: 1),
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 10),
            child: Text(
              strings.moreDevices(totalPeers - peers.length),
              style: TextStyle(
                color: theme.colorScheme.onSurfaceVariant,
                fontSize: 12,
                height: 1.3,
              ),
            ),
          ),
        ],
      ],
    );
  }
}

class _PeerRow extends StatelessWidget {
  const _PeerRow({required this.peer});

  final PeerSnapshot peer;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final statusColor = _peerStatusColor(context, peer);
    final statusLabel = _peerStatusLabel(strings, peer);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Container(
            width: 9,
            height: 9,
            decoration: BoxDecoration(
              color: statusColor,
              shape: BoxShape.circle,
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Flexible(
                      child: Text(
                        peer.displayName,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                          color: theme.colorScheme.onSurface,
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                          height: 1.2,
                        ),
                      ),
                    ),
                    if (peer.lastError != null) ...[
                      const SizedBox(width: 6),
                      Tooltip(
                        message: peer.lastError!,
                        child: Icon(
                          Icons.warning_amber_rounded,
                          size: 14,
                          color: theme.brightness == Brightness.dark
                              ? AppTokens.colorDarkWarnText
                              : AppTokens.colorWarnText,
                        ),
                      ),
                    ],
                  ],
                ),
                const SizedBox(height: 2),
                Text(
                  dash(peer.virtualIp),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: theme.colorScheme.onSurfaceVariant,
                    fontSize: 11.5,
                    fontWeight: FontWeight.w400,
                    height: 1.2,
                    fontFeatures: AppTokens.tabularFontFeatures,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: 12),
          _PeerStatusBadge(label: statusLabel, color: statusColor),
          const SizedBox(width: 10),
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
    );
  }
}

class _PeerStatusBadge extends StatelessWidget {
  const _PeerStatusBadge({required this.label, required this.color});

  final String label;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 6,
          height: 6,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 5),
        Text(
          label,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            color: color,
            fontSize: 12,
            fontWeight: FontWeight.w600,
            height: 1.2,
          ),
        ),
      ],
    );
  }
}
