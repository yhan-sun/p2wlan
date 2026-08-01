part of '../nodes_page.dart';

class _PeerSummary extends StatelessWidget {
  const _PeerSummary({required this.peers});

  final List<PeerSnapshot> peers;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final directCount = peers.where((peer) => peer.path == 'direct').length;
    final relayCount = peers.where((peer) => peer.path == 'relay').length;
    final onlineCount = peers.where((peer) => peer.online).length;
    final offlineCount = peers.where((peer) => !peer.online).length;
    final attentionCount = peers.where(_peerNeedsAttention).length;
    return AppPanel(
      title: strings.peerSummary,
      child: Wrap(
        spacing: 24,
        runSpacing: 4,
        children: [
          MetricTile(label: strings.peerCount, value: formatInt(peers.length)),
          MetricTile(
            label: strings.onlineDevices,
            value: formatInt(onlineCount),
          ),
          MetricTile(label: strings.directPaths, value: formatInt(directCount)),
          MetricTile(label: strings.relayPaths, value: formatInt(relayCount)),
          MetricTile(
            label: strings.offlineDevices,
            value: formatInt(offlineCount),
          ),
          MetricTile(
            label: strings.attentionDevices,
            value: formatInt(attentionCount),
          ),
        ],
      ),
    );
  }
}

class _PeerTable extends StatelessWidget {
  const _PeerTable({
    required this.peers,
    required this.copiedKey,
    required this.onCopy,
    required this.onDetails,
    required this.onEdit,
    required this.onDelete,
  });

  final List<PeerSnapshot> peers;
  final String? copiedKey;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onDetails;
  final Future<void> Function(PeerSnapshot peer) onEdit;
  final Future<void> Function(PeerSnapshot peer) onDelete;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final bodyHeight = (peers.length * _rowHeight)
        .clamp(_rowHeight, _maxBodyHeight)
        .toDouble();
    return AppPanel(
      title: strings.isZh ? '其他设备' : 'Other devices',
      flushContent: true,
      child: ClipRRect(
        borderRadius: const BorderRadius.only(
          bottomLeft: Radius.circular(AppTokens.radiusLg),
          bottomRight: Radius.circular(AppTokens.radiusLg),
        ),
        child: SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          child: SizedBox(
            width: _tableWidth,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                _PeerHeader(strings: strings),
                SizedBox(
                  height: bodyHeight,
                  child: ListView.builder(
                    padding: EdgeInsets.zero,
                    primary: false,
                    itemExtent: _rowHeight,
                    itemCount: peers.length,
                    itemBuilder: (context, index) {
                      return _PeerRow(
                        peer: peers[index],
                        strings: strings,
                        shaded: index.isOdd,
                        copiedKey: copiedKey,
                        onCopy: onCopy,
                        onEdit: onEdit,
                      );
                    },
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  static const _tableWidth = 1196.0;
  static const _maxBodyHeight = 520.0;
  static const _rowHeight = 44.0;
  static const _deviceWidth = 142.0;
  static const _peerIdWidth = 118.0;
  static const _virtualIpWidth = 112.0;
  static const _versionWidth = 96.0;
  static const _stateWidth = 94.0;
  static const _pathWidth = 92.0;
  static const _typeWidth = 122.0;
  static const _routeWidth = 92.0;
  static const _latencyWidth = 86.0;
  static const _endpointWidth = 122.0;
  static const _actionWidth = 120.0;

  static const _columnHeaderStyle = TextStyle(
    fontSize: 12,
    fontWeight: FontWeight.w600,
    color: AppTokens.colorTextSecondary,
  );

  static const _cellStyle = TextStyle(
    fontSize: 13,
    fontWeight: FontWeight.w400,
    color: AppTokens.colorTextPrimary,
  );

  static const _cellStyleBold = TextStyle(
    fontSize: 13,
    fontWeight: FontWeight.w600,
    color: AppTokens.colorTextPrimary,
  );

  static const _cellMonoStyle = TextStyle(
    fontSize: 12,
    fontWeight: FontWeight.w500,
    color: AppTokens.colorTextPrimary,
    fontFeatures: AppTokens.tabularFontFeatures,
  );
}

class _PeerHeader extends StatelessWidget {
  const _PeerHeader({required this.strings});

  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 38,
      decoration: const BoxDecoration(
        color: AppTokens.colorSurfaceSubtle,
        border: Border(bottom: BorderSide(color: AppTokens.colorBorderSubtle)),
      ),
      child: Row(
        children: [
          _PeerCell(
            width: _PeerTable._deviceWidth,
            child: Text(strings.device, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._peerIdWidth,
            child: Text(strings.peerId, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._virtualIpWidth,
            child: Text(
              strings.virtualIp,
              style: _PeerTable._columnHeaderStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._versionWidth,
            child: Text(
              strings.isZh ? '版本' : 'Version',
              style: _PeerTable._columnHeaderStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._stateWidth,
            child: Text(strings.state, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._pathWidth,
            child: Text(strings.path, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._typeWidth,
            child: Text(strings.type, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._routeWidth,
            child: Text(strings.route, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._latencyWidth,
            child: Text(strings.latency, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._endpointWidth,
            child: Text(strings.endpoint, style: _PeerTable._columnHeaderStyle),
          ),
          _PeerCell(
            width: _PeerTable._actionWidth,
            child: Text(
              strings.isZh ? '操作' : 'Actions',
              style: _PeerTable._columnHeaderStyle,
            ),
          ),
        ],
      ),
    );
  }
}

class _PeerRow extends StatelessWidget {
  const _PeerRow({
    required this.peer,
    required this.strings,
    required this.shaded,
    required this.copiedKey,
    required this.onCopy,
    required this.onEdit,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final bool shaded;
  final String? copiedKey;
  final Future<void> Function(String value, String key) onCopy;
  final Future<void> Function(PeerSnapshot peer) onEdit;

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: shaded ? AppTokens.colorSurfaceSubtle : AppTokens.colorSurface,
        border: const Border(
          bottom: BorderSide(color: AppTokens.colorBorderSubtle),
        ),
      ),
      child: Row(
        children: [
          _PeerCell(
            width: _PeerTable._deviceWidth,
            child: Text(
              dash(peer.displayName),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: _PeerTable._cellStyleBold,
            ),
          ),
          _PeerCell(
            width: _PeerTable._peerIdWidth,
            child: Text(shortId(peer.nodeId), style: _PeerTable._cellMonoStyle),
          ),
          _PeerCell(
            width: _PeerTable._virtualIpWidth,
            child: Text(dash(peer.virtualIp), style: _PeerTable._cellMonoStyle),
          ),
          _PeerCell(
            width: _PeerTable._versionWidth,
            child: Text(
              dash(peer.appVersion),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: _PeerTable._cellMonoStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._stateWidth,
            child: Text(
              dash(peer.state),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: _PeerTable._cellStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._pathWidth,
            child: _PathBadge(peer: peer),
          ),
          _PeerCell(
            width: _PeerTable._typeWidth,
            child: Text(
              dash(peer.connectionType),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: _PeerTable._cellStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._routeWidth,
            child: Text(
              _routeLabel(strings, peer),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: _PeerTable._cellStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._latencyWidth,
            child: Align(
              alignment: Alignment.centerRight,
              child: _LatencyText(peer: peer),
            ),
          ),
          _PeerCell(
            width: _PeerTable._endpointWidth,
            child: Text(
              dash(peer.endpoint ?? peer.relayServer),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: _PeerTable._cellMonoStyle,
            ),
          ),
          _PeerCell(
            width: _PeerTable._actionWidth,
            child: _PeerActions(
              peer: peer,
              copiedKey: copiedKey,
              onCopy: onCopy,
              onEdit: onEdit,
            ),
          ),
        ],
      ),
    );
  }
}

class _PeerCell extends StatelessWidget {
  const _PeerCell({required this.width, required this.child});

  final double width;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: width,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12),
        child: Align(alignment: Alignment.centerLeft, child: child),
      ),
    );
  }
}
