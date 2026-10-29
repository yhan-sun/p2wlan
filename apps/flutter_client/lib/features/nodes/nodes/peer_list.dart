part of '../nodes_page.dart';

/// One continuous device list. The recommended sort already structures the
/// set (attention → direct → relay → probing → offline), so no group headers
/// or per-group badges are needed on the first level.
class _PeerList extends StatelessWidget {
  const _PeerList({
    required this.peers,
    required this.showScope,
    required this.compact,
    required this.onTap,
  });

  final List<NetworkPeerSnapshot> peers;
  final bool showScope;
  final bool compact;
  final ValueChanged<NetworkPeerSnapshot> onTap;

  @override
  Widget build(BuildContext context) {
    final strings = stringsOf(context);
    return SizedBox(
      width: double.infinity,
      child: Column(
        children: [
          for (var index = 0; index < peers.length; index++) ...[
            if (index > 0) const Divider(height: 1, indent: 56, endIndent: 14),
            _PeerListRow(
              peer: peers[index].peer,
              scopeIdentity: peers[index].isPrimary
                  ? null
                  : peers[index].identity,
              scopeLabel: showScope
                  ? (peers[index].roomName ??
                        (strings.isZh ? '当前网络' : 'Current network'))
                  : null,
              current: peers[index].current,
              speedBytesPerSecond: peers[index].transferBytesPerSecond,
              strings: strings,
              compact: compact,
              onTap: (_) => onTap(peers[index]),
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
    this.scopeIdentity,
    this.scopeLabel,
    this.current = true,
  });

  final String? scopeIdentity;
  final String? scopeLabel;
  final bool current;
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
        key: Key('node-row-${scopeIdentity ?? peer.nodeId}'),
        onTap: () => onTap(peer),
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
            scopeLabel: scopeLabel,
            current: current,
          ),
        ),
      ),
    );
  }
}

/// First level: status, name/IP, speed, latency, connection path, and a quiet
/// affordance for opening details. The identity uses two short lines so the
/// device name keeps its full width instead of competing with the IP address.
/// The three metrics stay on one line; technical metadata still stays behind
/// the detail surface.
class _RowContent extends StatelessWidget {
  const _RowContent({
    required this.peer,
    required this.speedBytesPerSecond,
    required this.strings,
    required this.compact,
    this.scopeLabel,
    this.current = true,
  });

  final String? scopeLabel;
  final bool current;
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
        scopeLabel: scopeLabel,
        current: current,
      );
    }
    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        _PeerLeading(peer: peer, strings: strings, current: current),
        const SizedBox(width: AppTokens.space10),
        Expanded(
          child: _PeerPrimaryText(
            peer: peer,
            strings: strings,
            scopeLabel: scopeLabel,
          ),
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
                value: formatLatency(current ? peer.latencyMs : null),
                width: 50,
                color: theme.colorScheme.onSurfaceVariant,
              ),
              const SizedBox(width: 8),
              _PeerMetricText(
                value: current ? _rowPathLabel(strings, peer) : strings.stale,
                width: 58,
                color: current
                    ? _rowStatusColor(context, peer)
                    : P2WlanColors.of(context).offline,
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

/// Phone layout for a peer row. Keep the complete interaction in one compact
/// row: a two-line identity on the left, transfer rate, RTT, path, and the
/// detail affordance on the right. The identity grows vertically rather than
/// squeezing the device name and IP into a single line.
class _CompactRowContent extends StatelessWidget {
  const _CompactRowContent({
    required this.peer,
    required this.speedBytesPerSecond,
    required this.strings,
    this.scopeLabel,
    this.current = true,
  });

  final String? scopeLabel;
  final bool current;
  final PeerSnapshot peer;
  final int? speedBytesPerSecond;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final statusLabel = current ? _rowPathLabel(strings, peer) : strings.stale;
    final statusColor = current
        ? _rowStatusColor(context, peer)
        : P2WlanColors.of(context).offline;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            _PeerLeading(peer: peer, strings: strings, current: current),
            const SizedBox(width: AppTokens.space8),
            Expanded(
              child: _PeerPrimaryText(
                peer: peer,
                strings: strings,
                scopeLabel: scopeLabel,
              ),
            ),
            const SizedBox(width: AppTokens.space4),
            Icon(
              Icons.chevron_right_rounded,
              size: 20,
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ],
        ),
        const SizedBox(height: 6),
        Padding(
          padding: const EdgeInsets.only(left: 40),
          child: Wrap(
            spacing: 12,
            runSpacing: 4,
            children: [
              Text(
                statusLabel,
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  color: statusColor,
                ),
              ),
              Text(
                formatLatency(current ? peer.latencyMs : null),
                style: TextStyle(
                  fontSize: 12,
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              Text(
                formatTransferRate(speedBytesPerSecond),
                style: TextStyle(
                  fontSize: 12,
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ],
          ),
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
          fontSize: 12,
          fontWeight: FontWeight.w600,
          height: 1.2,
          fontFeatures: AppTokens.tabularFontFeatures,
        ),
      ),
    );
  }
}

class _PeerLeading extends StatelessWidget {
  const _PeerLeading({
    required this.peer,
    required this.strings,
    this.current = true,
  });

  final bool current;

  final PeerSnapshot peer;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final colors = P2WlanColors.of(context);
    final theme = Theme.of(context);
    final statusColor = current
        ? _rowStatusColor(context, peer)
        : P2WlanColors.of(context).offline;
    return Semantics(
      label: current ? _rowPathLabel(strings, peer) : strings.stale,
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
  const _PeerPrimaryText({
    required this.peer,
    required this.strings,
    this.scopeLabel,
  });

  final String? scopeLabel;

  final PeerSnapshot peer;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final error = peer.lastError?.trim();
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Flexible(
              child: Text(
                dash(peer.displayName),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.w700,
                  color: theme.colorScheme.onSurface,
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
        ),
        const SizedBox(height: 2),
        Text(
          [dash(peer.virtualIp), ?scopeLabel].join(' · '),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w600,
            color: theme.colorScheme.onSurfaceVariant,
            fontFeatures: AppTokens.tabularFontFeatures,
            height: 1.15,
          ),
        ),
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
    final colors = P2WlanColors.of(context);
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 16, 20, 24),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              color: colors.surfaceMuted,
              borderRadius: BorderRadius.circular(AppTokens.radiusMd),
            ),
            child: Icon(
              icon,
              size: 22,
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(width: AppTokens.space12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface,
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: AppTokens.space4),
                Text(
                  body,
                  style: TextStyle(
                    color: theme.colorScheme.onSurfaceVariant,
                    fontSize: 13,
                    height: 1.4,
                  ),
                ),
                if (actionLabel != null && onAction != null) ...[
                  const SizedBox(height: AppTokens.space12),
                  OutlinedButton.icon(
                    onPressed: onAction,
                    icon: Icon(
                      actionLabel == stringsOf(context).clearSearch ||
                              actionLabel == stringsOf(context).clearFilter
                          ? Icons.clear_rounded
                          : Icons.group_add_outlined,
                      size: 16,
                    ),
                    label: Text(actionLabel!),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}
