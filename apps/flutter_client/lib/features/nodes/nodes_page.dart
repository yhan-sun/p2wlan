import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/models/daemon_models.dart';
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

  final DaemonSnapshot? snapshot;
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
    return AppPanel(
      title: strings.peers,
      flushContent: true,
      child: ClipRRect(
        borderRadius: const BorderRadius.only(
          bottomLeft: Radius.circular(AppTokens.radiusMd),
          bottomRight: Radius.circular(AppTokens.radiusMd),
        ),
        child: SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          child: DataTable(
            columnSpacing: 24,
            headingRowHeight: 38,
            dataRowMinHeight: 44,
            dataRowMaxHeight: 48,
            headingRowColor: WidgetStateProperty.all(
              AppTokens.colorSurfaceSubtle,
            ),
            columns: [
              DataColumn(
                label: Text(strings.device, style: _columnHeaderStyle),
              ),
              DataColumn(
                label: Text(strings.peerId, style: _columnHeaderStyle),
              ),
              DataColumn(
                label: Text(strings.virtualIp, style: _columnHeaderStyle),
              ),
              DataColumn(label: Text(strings.state, style: _columnHeaderStyle)),
              DataColumn(label: Text(strings.path, style: _columnHeaderStyle)),
              DataColumn(label: Text(strings.type, style: _columnHeaderStyle)),
              DataColumn(label: Text(strings.route, style: _columnHeaderStyle)),
              DataColumn(
                label: Text(strings.latency, style: _columnHeaderStyle),
              ),
              DataColumn(
                label: Text(strings.endpoint, style: _columnHeaderStyle),
              ),
            ],
            rows: [
              for (final peer in peers)
                DataRow(
                  cells: [
                    DataCell(
                      Text(dash(peer.displayName), style: _cellStyleBold),
                    ),
                    DataCell(
                      SelectableText(
                        shortId(peer.nodeId),
                        style: _cellMonoStyle,
                      ),
                    ),
                    DataCell(
                      SelectableText(
                        dash(peer.virtualIp),
                        style: _cellMonoStyle,
                      ),
                    ),
                    DataCell(Text(dash(peer.state), style: _cellStyle)),
                    DataCell(_PathBadge(peer: peer)),
                    DataCell(
                      Text(dash(peer.connectionType), style: _cellStyle),
                    ),
                    DataCell(
                      Text(_routeLabel(strings, peer), style: _cellStyle),
                    ),
                    DataCell(
                      Text(
                        formatLatency(peer.latencyMs),
                        style: _cellMonoStyle,
                      ),
                    ),
                    DataCell(
                      SelectableText(
                        dash(peer.endpoint ?? peer.relayServer),
                        style: _cellMonoStyle,
                      ),
                    ),
                  ],
                ),
            ],
          ),
        ),
      ),
    );
  }

  static const _columnHeaderStyle = TextStyle(
    fontSize: 12,
    fontWeight: FontWeight.w700,
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

class _PeerList extends StatelessWidget {
  const _PeerList({required this.peers});

  final List<PeerSnapshot> peers;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return Column(
      children: [
        for (final peer in peers) ...[
          AppPanel(
            title: peer.displayName,
            trailing: _PathBadge(peer: peer),
            child: Wrap(
              spacing: 20,
              runSpacing: 4,
              children: [
                MetricTile(label: strings.peerId, value: shortId(peer.nodeId)),
                MetricTile(
                  label: strings.virtualIp,
                  value: dash(peer.virtualIp),
                ),
                MetricTile(label: strings.state, value: dash(peer.state)),
                MetricTile(
                  label: strings.path,
                  value: strings.pathLabel(peer.path),
                ),
                MetricTile(
                  label: strings.connectionType,
                  value: dash(peer.connectionType),
                ),
                MetricTile(
                  label: strings.route,
                  value: _routeLabel(strings, peer),
                ),
                MetricTile(
                  label: strings.latency,
                  value: formatLatency(peer.latencyMs),
                ),
                MetricTile(
                  label: strings.endpoint,
                  value: dash(peer.endpoint ?? peer.relayServer),
                ),
                if (peer.lastError != null)
                  MetricTile(label: strings.lastError, value: peer.lastError!),
              ],
            ),
          ),
          const SizedBox(height: 10),
        ],
      ],
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
