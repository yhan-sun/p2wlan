import 'package:flutter/material.dart';

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
    return AnimatedBuilder(
      animation: statusStore,
      builder: (context, _) {
        final snapshot = statusStore.snapshot;
        final peers = snapshot?.peers ?? const <PeerSnapshot>[];
        return PageScaffold(
          title: 'Nodes',
          subtitle: 'Read-only peer list from the daemon status snapshot.',
          children: [
            _PeerSummary(snapshot: snapshot, peerCount: peers.length),
            const SizedBox(height: 16),
            if (peers.isEmpty)
              const InfoCard(
                title: 'Peers',
                child: Text(
                  'No peers are present in the current daemon snapshot.',
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
    final stats = snapshot?.stats;
    return InfoCard(
      title: 'Peer summary',
      child: Wrap(
        spacing: 24,
        runSpacing: 8,
        children: [
          MetricTile(label: 'Peer count', value: formatInt(peerCount)),
          MetricTile(
            label: 'Direct paths',
            value: stats == null ? '—' : formatInt(stats.directConnections),
          ),
          MetricTile(
            label: 'Relay paths',
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
    return InfoCard(
      title: 'Peers',
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: DataTable(
          columnSpacing: 28,
          columns: const [
            DataColumn(label: Text('Device')),
            DataColumn(label: Text('Peer ID')),
            DataColumn(label: Text('Virtual IP')),
            DataColumn(label: Text('State')),
            DataColumn(label: Text('Path')),
            DataColumn(label: Text('Connection type')),
            DataColumn(label: Text('Route')),
            DataColumn(label: Text('Latency')),
            DataColumn(label: Text('Endpoint')),
          ],
          rows: [
            for (final peer in peers)
              DataRow(
                cells: [
                  DataCell(Text(dash(peer.displayName))),
                  DataCell(SelectableText(shortId(peer.nodeId))),
                  DataCell(SelectableText(dash(peer.virtualIp))),
                  DataCell(Text(dash(peer.state))),
                  DataCell(_PathBadge(peer: peer)),
                  DataCell(Text(dash(peer.connectionType))),
                  DataCell(Text(_routeLabel(peer))),
                  DataCell(Text(formatLatency(peer.latencyMs))),
                  DataCell(
                    SelectableText(dash(peer.endpoint ?? peer.relayServer)),
                  ),
                ],
              ),
          ],
        ),
      ),
    );
  }
}

class _PeerList extends StatelessWidget {
  const _PeerList({required this.peers});

  final List<PeerSnapshot> peers;

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        for (final peer in peers) ...[
          InfoCard(
            title: peer.displayName,
            trailing: _PathBadge(peer: peer),
            child: Wrap(
              spacing: 20,
              runSpacing: 8,
              children: [
                MetricTile(label: 'Peer ID', value: shortId(peer.nodeId)),
                MetricTile(label: 'Virtual IP', value: dash(peer.virtualIp)),
                MetricTile(label: 'State', value: dash(peer.state)),
                MetricTile(label: 'Path', value: pathLabel(peer.path)),
                MetricTile(
                  label: 'Connection type',
                  value: dash(peer.connectionType),
                ),
                MetricTile(label: 'Route', value: _routeLabel(peer)),
                MetricTile(
                  label: 'Latency',
                  value: formatLatency(peer.latencyMs),
                ),
                MetricTile(
                  label: 'Endpoint',
                  value: dash(peer.endpoint ?? peer.relayServer),
                ),
                if (peer.lastError != null)
                  MetricTile(label: 'Last error', value: peer.lastError!),
              ],
            ),
          ),
          const SizedBox(height: 12),
        ],
      ],
    );
  }
}

String _routeLabel(PeerSnapshot peer) {
  if (peer.path == 'direct') return 'Direct';
  if (peer.path == 'relay' || peer.isRelay) return 'Relay';
  return '—';
}

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
    return StatusBadge(label: pathLabel(peer.path), tone: tone);
  }
}
