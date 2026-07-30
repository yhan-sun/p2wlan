import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/status_store.dart';
import '../../shared/formatters.dart';
import '../../shared/widgets/info_card.dart';
import '../../shared/widgets/page_scaffold.dart';
import '../../shared/widgets/status_badge.dart';

class NodesPage extends StatelessWidget {
  const NodesPage({super.key, required this.statusStore});

  final StatusStore statusStore;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AnimatedBuilder(
      animation: statusStore,
      builder: (context, _) {
        final snapshot = statusStore.snapshot;
        final peers = snapshot?.peers ?? const <PeerSnapshot>[];
        return PageScaffold(
          title: strings.nodes,
          subtitle: strings.nodesSubtitle,
          children: [
            _PeerSummary(snapshot: snapshot, peerCount: peers.length),
            const SizedBox(height: 14),
            if (peers.isEmpty)
              AppPanel(
                title: strings.peers,
                child: Text(
                  strings.noPeers,
                  style: const TextStyle(
                    fontSize: 13,
                    color: AppTokens.colorTextSecondary,
                  ),
                ),
              )
            else
              LayoutBuilder(
                builder: (context, constraints) {
                  if (constraints.maxWidth >= 760) {
                    return _PeerTable(peers: peers);
                  }
                  return _PeerList(peers: peers);
                },
              ),
          ],
        );
      },
    );
  }
}

class _PeerSummary extends StatelessWidget {
  const _PeerSummary({required this.snapshot, required this.peerCount});

  final DiagnosticsSnapshot? snapshot;
  final int peerCount;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final stats = snapshot?.stats;
    return AppPanel(
      title: strings.peerSummary,
      child: Wrap(
        spacing: 24,
        runSpacing: 4,
        children: [
          MetricTile(label: strings.peerCount, value: formatInt(peerCount)),
          MetricTile(
            label: strings.directPaths,
            value: stats == null ? '—' : formatInt(stats.directConnections),
          ),
          MetricTile(
            label: strings.relayPaths,
            value: stats == null ? '—' : formatInt(stats.relayConnections),
          ),
        ],
      ),
    );
  }
}

class _PeerTable extends StatelessWidget {
  const _PeerTable({required this.peers});

  final List<PeerSnapshot> peers;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final bodyHeight = (peers.length * _rowHeight)
        .clamp(_rowHeight, _maxBodyHeight)
        .toDouble();
    return AppPanel(
      title: strings.peers,
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

  static const _tableWidth = 980.0;
  static const _maxBodyHeight = 520.0;
  static const _rowHeight = 44.0;
  static const _deviceWidth = 142.0;
  static const _peerIdWidth = 118.0;
  static const _virtualIpWidth = 112.0;
  static const _stateWidth = 94.0;
  static const _pathWidth = 92.0;
  static const _typeWidth = 122.0;
  static const _routeWidth = 92.0;
  static const _latencyWidth = 86.0;
  static const _endpointWidth = 122.0;

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
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final bool shaded;

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
            child: Text(
              formatLatency(peer.latencyMs),
              style: _PeerTable._cellMonoStyle,
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

class _PeerList extends StatelessWidget {
  const _PeerList({required this.peers});

  final List<PeerSnapshot> peers;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final bodyHeight = (peers.length * _rowHeight)
        .clamp(_rowHeight, _maxBodyHeight)
        .toDouble();
    return AppPanel(
      title: strings.peers,
      flushContent: true,
      child: ClipRRect(
        borderRadius: const BorderRadius.only(
          bottomLeft: Radius.circular(AppTokens.radiusLg),
          bottomRight: Radius.circular(AppTokens.radiusLg),
        ),
        child: SizedBox(
          height: bodyHeight,
          child: ListView.builder(
            padding: EdgeInsets.zero,
            primary: false,
            itemExtent: _rowHeight,
            itemCount: peers.length,
            itemBuilder: (context, index) {
              return _PeerListRow(
                peer: peers[index],
                strings: strings,
                shaded: index.isOdd,
              );
            },
          ),
        ),
      ),
    );
  }

  static const _rowHeight = 76.0;
  static const _maxBodyHeight = 456.0;
}

class _PeerListRow extends StatelessWidget {
  const _PeerListRow({
    required this.peer,
    required this.strings,
    required this.shaded,
  });

  final PeerSnapshot peer;
  final AppStrings strings;
  final bool shaded;

  @override
  Widget build(BuildContext context) {
    final route = _routeLabel(strings, peer);
    final endpoint = dash(peer.endpoint ?? peer.relayServer);
    final detail =
        '${dash(peer.state)} / ${dash(peer.connectionType)} / $route';
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14),
      decoration: BoxDecoration(
        color: shaded ? AppTokens.colorSurfaceSubtle : AppTokens.colorSurface,
        border: const Border(
          bottom: BorderSide(color: AppTokens.colorBorderSubtle),
        ),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  dash(peer.displayName),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    fontSize: 13.5,
                    fontWeight: FontWeight.w700,
                    color: AppTokens.colorTextPrimary,
                  ),
                ),
                const SizedBox(height: 3),
                Text(
                  '${shortId(peer.nodeId)} / ${dash(peer.virtualIp)}',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w500,
                    color: AppTokens.colorTextSecondary,
                    fontFeatures: AppTokens.tabularFontFeatures,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  endpoint == '—' ? detail : '$detail / $endpoint',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    fontSize: 11.5,
                    fontWeight: FontWeight.w400,
                    color: AppTokens.colorTextMuted,
                    fontFeatures: AppTokens.tabularFontFeatures,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: 12),
          Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              _PathBadge(peer: peer),
              const SizedBox(height: 5),
              Text(
                formatLatency(peer.latencyMs),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  color: AppTokens.colorTextSecondary,
                  fontFeatures: AppTokens.tabularFontFeatures,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

String _routeLabel(AppStrings strings, PeerSnapshot peer) =>
    strings.routeLabel(peer.path, peer.isRelay);

class _PathBadge extends StatelessWidget {
  const _PathBadge({required this.peer});

  final PeerSnapshot peer;

  @override
  Widget build(BuildContext context) {
    final tone = switch (peer.path) {
      'direct' => StatusTone.good,
      'relay' => StatusTone.warn,
      _ => StatusTone.neutral,
    };
    return StatusBadge(
      label: AppStringsScope.of(context).pathLabel(peer.path),
      tone: tone,
    );
  }
}
