import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

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
            _RawJson(statusStore: statusStore, snapshot: snapshot),
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
            label: 'GET /health',
            value: statusStore.healthReachable ? 'reachable' : 'offline',
            detail: statusStore.lastHealthError,
          ),
          MetricTile(
            label: 'GET /status',
            value: statusStore.statusReachable
                ? 'loaded'
                : statusStore.healthReachable
                ? 'error'
                : 'skipped',
            detail: statusStore.lastStatusError,
          ),
          MetricTile(label: 'Daemon health', value: dash(health?.status)),
          MetricTile(
            label: 'Control connected',
            value: formatOptionalBool(health?.controlConnected),
          ),
          MetricTile(
            label: 'Reauth required',
            value: formatOptionalBool(health?.reauthRequired),
          ),
          MetricTile(
            label: 'UDP sockets',
            value: snapshot == null ? '—' : formatInt(snapshot!.udpSocketCount),
          ),
          MetricTile(
            label: 'Socket pool active',
            value: formatOptionalBool(snapshot?.udpSocketPoolActive),
          ),
          MetricTile(
            label: 'Relay connected',
            value: formatOptionalBool(snapshot?.relayConnected),
          ),
          MetricTile(
            label: 'Peer count',
            value: snapshot == null
                ? '—'
                : formatInt(snapshot!.stats.totalPeers),
          ),
          MetricTile(
            label: 'Last refresh',
            value: formatDateTime(statusStore.lastFetchedAt),
          ),
          MetricTile(
            label: 'Request duration',
            value: formatDuration(statusStore.lastRequestDuration),
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
  const _RawJson({required this.statusStore, required this.snapshot});

  final StatusStore statusStore;
  final DaemonSnapshot? snapshot;

  @override
  Widget build(BuildContext context) {
    final raw = snapshot?.prettyJson ?? _readableErrorJson();
    return InfoCard(
      title: 'Raw /status JSON',
      trailing: OutlinedButton.icon(
        onPressed: () => _copy(context, raw),
        icon: const Icon(Icons.copy_all_outlined),
        label: const Text('Copy'),
      ),
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

  String _readableErrorJson() {
    const encoder = JsonEncoder.withIndent('  ');
    return encoder.convert({
      'status': statusStore.healthReachable ? 'status_unavailable' : 'offline',
      'health_endpoint': statusStore.healthReachable ? 'reachable' : 'offline',
      'status_endpoint': statusStore.statusReachable
          ? 'loaded'
          : statusStore.healthReachable
          ? 'error'
          : 'skipped',
      if (statusStore.lastError != null) 'error': statusStore.lastError,
      if (statusStore.lastFetchedAt != null)
        'last_refresh': statusStore.lastFetchedAt!.toIso8601String(),
      if (statusStore.lastRequestDuration != null)
        'request_duration_ms': statusStore.lastRequestDuration!.inMilliseconds,
    });
  }

  Future<void> _copy(BuildContext context, String raw) async {
    await Clipboard.setData(ClipboardData(text: raw));
    if (!context.mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(const SnackBar(content: Text('Diagnostics JSON copied')));
  }
}
