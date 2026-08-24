part of '../nodes_page.dart';

/// One continuous device list. The recommended sort already structures the
/// set (attention → direct → relay → probing → offline), so no group headers
/// or per-group badges are needed on the first level.
class _PeerList extends StatelessWidget {
  const _PeerList({
    required this.peers,
    required this.peerTransferRates,
    required this.compact,
    required this.onTap,
  });

  final List<PeerSnapshot> peers;
  final Map<String, int> peerTransferRates;
  final bool compact;
  final ValueChanged<PeerSnapshot> onTap;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    return SizedBox(
      width: double.infinity,
      child: Column(
        children: [
          for (var index = 0; index < peers.length; index++) ...[
            if (index > 0) const SizedBox(height: AppTokens.space4),
            _PeerListRow(
              peer: peers[index],
              speedBytesPerSecond: peerTransferRates[peers[index].nodeId],
              strings: strings,
              compact: compact,
              onTap: onTap,
            ),
          ],
        ],
      ),
    );
  }
}

class _PeerListRow extends StatelessWidget {
  const _PeerListRow({
    required this.peer,
    required this.speedBytesPerSecond,
    required this.strings,
    required this.compact,
    required this.onTap,
  });

  final PeerSnapshot peer;
  final int? speedBytesPerSecond;
  final AppStrings strings;
  final bool compact;
  final ValueChanged<PeerSnapshot> onTap;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        key: Key('node-row-${peer.nodeId}'),
        onTap: () => onTap(peer),
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        child: Padding(
          padding: EdgeInsets.symmetric(
            horizontal: 14,
            vertical: compact ? 10 : 8,
          ),
          child: _RowContent(
            peer: peer,
            speedBytesPerSecond: speedBytesPerSecond,
            strings: strings,
            compact: compact,
          ),
        ),
      ),
    );
  }
}

/// First level: status, name/IP, speed, latency, connection path, and a quiet
/// affordance for opening details. The three metrics stay on one line;
/// technical metadata still stays behind the detail surface.
class _RowContent extends StatelessWidget {
  const _RowContent({
    required this.peer,
    required this.speedBytesPerSecond,
    required this.strings,
    required this.compact,
  });

  final PeerSnapshot peer;
  final int? speedBytesPerSecond;
  final AppStrings strings;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    if (compact) {
      return _CompactRowContent(
        peer: peer,
        speedBytesPerSecond: speedBytesPerSecond,
        strings: strings,
      );
    }
    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        _PeerLeading(peer: peer, strings: strings),
        const SizedBox(width: AppTokens.space10),
        Expanded(
          child: _PeerPrimaryText(peer: peer, strings: strings),
        ),
        const SizedBox(width: AppTokens.space10),
        SizedBox(
          width: compact ? 184 : 202,
          child: Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              _PeerMetricText(
                value: formatTransferRate(speedBytesPerSecond),
                width: 58,
                color: theme.colorScheme.onSurfaceVariant,
              ),
              const SizedBox(width: 8),
              _PeerMetricText(
                value: formatLatency(peer.latencyMs),
                width: 50,
                color: theme.colorScheme.onSurfaceVariant,
              ),
              const SizedBox(width: 8),
              _PeerMetricText(
                value: _rowPathLabel(strings, peer),
                width: 58,
                color: _rowStatusColor(context, peer),
              ),
            ],
          ),
        ),
        const SizedBox(width: AppTokens.space6),
        Icon(
          Icons.chevron_right_rounded,
          size: 20,
          color: theme.colorScheme.onSurfaceVariant,
        ),
      ],
    );
  }
}

/// Phone layout for a peer row. Keep the complete interaction on one compact
/// line: identity, transfer rate, RTT, path, and the detail affordance. The
/// identity truncates gracefully instead of growing the row to two lines.
class _CompactRowContent extends StatelessWidget {
  const _CompactRowContent({
    required this.peer,
    required this.speedBytesPerSecond,
    required this.strings,
  });

  final PeerSnapshot peer;
  final int? speedBytesPerSecond;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final statusLabel = _rowPathLabel(strings, peer);
    final statusColor = _rowStatusColor(context, peer);
    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        _PeerLeading(peer: peer, strings: strings),
        const SizedBox(width: AppTokens.space8),
        Expanded(
          child: _PeerPrimaryText(peer: peer, strings: strings),
        ),
        const SizedBox(width: AppTokens.space4),
        _PeerMetricText(
          value: formatTransferRate(speedBytesPerSecond),
          width: 36,
          color: theme.colorScheme.onSurfaceVariant,
        ),
        const SizedBox(width: 2),
        _PeerMetricText(
          value: formatLatency(peer.latencyMs),
          width: 36,
          color: theme.colorScheme.onSurfaceVariant,
        ),
        const SizedBox(width: 2),
        _PeerMetricText(value: statusLabel, width: 46, color: statusColor),
        const SizedBox(width: 2),
        Icon(
          Icons.chevron_right_rounded,
          size: 20,
          color: theme.colorScheme.onSurfaceVariant,
        ),
      ],
    );
  }
}

class _PeerMetricText extends StatelessWidget {
  const _PeerMetricText({
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
          fontSize: width < 50 ? 10 : 11,
          fontWeight: FontWeight.w600,
          height: 1.2,
          fontFeatures: AppTokens.tabularFontFeatures,
        ),
      ),
    );
  }
}

class _PeerLeading extends StatelessWidget {
  const _PeerLeading({required this.peer, required this.strings});

  final PeerSnapshot peer;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final colors = P2WlanColors.of(context);
    final theme = Theme.of(context);
    final statusColor = _rowStatusColor(context, peer);
    return Semantics(
      label: _rowPathLabel(strings, peer),
      child: SizedBox(
        width: 32,
        height: 32,
        child: Stack(
          clipBehavior: Clip.none,
          children: [
            DecoratedBox(
              decoration: BoxDecoration(
                color: colors.selectedSurface,
                borderRadius: BorderRadius.circular(AppTokens.radiusSm),
              ),
              child: SizedBox.expand(
                child: Icon(
                  key: Key('node-device-icon-${peer.nodeId}'),
                  peerDeviceIcon(peer),
                  size: 17,
                  color: theme.colorScheme.primary,
                ),
              ),
            ),
            Positioned(
              right: -1,
              bottom: -1,
              child: Container(
                width: 9,
                height: 9,
                decoration: BoxDecoration(
                  color: statusColor,
                  shape: BoxShape.circle,
                  border: Border.all(color: colors.surface, width: 1.5),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _PeerPrimaryText extends StatelessWidget {
  const _PeerPrimaryText({required this.peer, required this.strings});

  final PeerSnapshot peer;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final error = peer.lastError?.trim();
    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        Flexible(
          child: Text(
            dash(peer.displayName),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 13.5,
              fontWeight: FontWeight.w700,
              color: theme.colorScheme.onSurface,
            ),
          ),
        ),
        Text(
          ' · ',
          maxLines: 1,
          style: TextStyle(
            fontSize: 11,
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        Flexible(
          child: Text(
            dash(peer.virtualIp),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w600,
              color: theme.colorScheme.onSurfaceVariant,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          ),
        ),
        if (error != null && error.isNotEmpty) ...[
          const SizedBox(width: AppTokens.space6),
          Tooltip(
            message: error,
            child: Icon(
              Icons.warning_amber_rounded,
              size: 15,
              color: P2WlanColors.of(context).probing,
            ),
          ),
        ],
      ],
    );
  }
}

/// Distinct empty states: no devices in the network, no search results, or no
/// filter results — never a single generic "no peers" message.
class _NodesEmptyState extends StatelessWidget {
  const _NodesEmptyState({
    required this.icon,
    required this.title,
    required this.body,
    this.actionLabel,
    this.onAction,
  });

  final IconData icon;
  final String title;
  final String body;
  final String? actionLabel;
  final VoidCallback? onAction;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Center(
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 28, horizontal: 16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 34, color: theme.colorScheme.onSurfaceVariant),
            const SizedBox(height: AppTokens.space10),
            Text(
              title,
              textAlign: TextAlign.center,
              style: TextStyle(
                color: theme.colorScheme.onSurface,
                fontSize: 15,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: AppTokens.space4),
            Text(
              body,
              textAlign: TextAlign.center,
              style: TextStyle(
                color: theme.colorScheme.onSurfaceVariant,
                fontSize: 13,
                height: 1.35,
              ),
            ),
            if (actionLabel != null && onAction != null) ...[
              const SizedBox(height: AppTokens.space12),
              OutlinedButton.icon(
                onPressed: onAction,
                icon: const Icon(Icons.clear_rounded, size: 17),
                label: Text(actionLabel!),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
