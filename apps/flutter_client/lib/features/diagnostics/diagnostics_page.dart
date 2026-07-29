import 'package:flutter/material.dart';

import '../../core/models/daemon_models.dart';
import '../../core/state/status_store.dart';
import '../../shared/formatters.dart';
import '../../shared/widgets/info_card.dart';
import '../../shared/widgets/page_scaffold.dart';
import '../../shared/widgets/status_badge.dart';

class DiagnosticsPage extends StatelessWidget {
  const DiagnosticsPage({super.key, required this.statusStore});

  final StatusStore statusStore;

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: statusStore,
      builder: (context, _) {
        final snapshot = statusStore.snapshot;
        return PageScaffold(
          title: 'Diagnostics',
          subtitle: 'Summary plus raw JSON from daemon GET /status.',
          children: [
            _Summary(statusStore: statusStore, snapshot: snapshot),
            const SizedBox(height: 16),
            _RawJson(snapshot: snapshot),
          ],
        );
      },
    );
  }
}

class _Summary extends StatelessWidget {
  const _Summary({required this.statusStore, required this.snapshot});

  final StatusStore statusStore;
  final DaemonSnapshot? snapshot;

  @override
  Widget build(BuildContext context) {
    final health = snapshot?.health;
    return InfoCard(
      title: 'Summary',
      trailing: StatusBadge(
        label: statusStore.online ? 'Status loaded' : 'No snapshot',
        tone: statusStore.online ? StatusTone.good : StatusTone.bad,
      ),
      child: Wrap(
        spacing: 24,
        runSpacing: 8,
        children: [
          MetricTile(
            label: 'Health endpoint',
            value: statusStore.healthReachable ? 'reachable' : 'offline',
          ),
          MetricTile(label: 'Daemon health', value: health?.status ?? '-'),
          MetricTile(
            label: 'Control connected',
            value: formatBool(health?.controlConnected ?? false),
          ),
          MetricTile(
            label: 'Reauth required',
            value: formatBool(health?.reauthRequired ?? false),
          ),
          MetricTile(
            label: 'UDP sockets',
            value: formatInt(snapshot?.udpSocketCount ?? 0),
          ),
          MetricTile(
            label: 'Socket pool active',
            value: formatBool(snapshot?.udpSocketPoolActive ?? false),
          ),
          MetricTile(
            label: 'Relay connected',
            value: formatBool(snapshot?.relayConnected ?? false),
          ),
          MetricTile(
            label: 'Peer count',
            value: formatInt(snapshot?.stats.totalPeers ?? 0),
          ),
          if (statusStore.lastError != null)
            MetricTile(label: 'Last error', value: statusStore.lastError!),
          if (health?.reason != null)
            MetricTile(label: 'Health reason', value: health!.reason!),
        ],
      ),
    );
  }
}

class _RawJson extends StatelessWidget {
  const _RawJson({required this.snapshot});

  final DaemonSnapshot? snapshot;

  @override
  Widget build(BuildContext context) {
    final raw = snapshot?.prettyJson ?? '{\n  "status": "offline"\n}';
    return InfoCard(
      title: 'Raw /status JSON',
      child: Container(
        width: double.infinity,
        constraints: const BoxConstraints(minHeight: 260),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: const Color(0xFF0F172A),
          borderRadius: BorderRadius.circular(8),
        ),
        child: SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          child: SelectableText(
            raw,
            style: const TextStyle(
              color: Color(0xFFE2E8F0),
              fontFamily: 'monospace',
              fontSize: 12.5,
              height: 1.35,
            ),
          ),
        ),
      ),
    );
  }
}
