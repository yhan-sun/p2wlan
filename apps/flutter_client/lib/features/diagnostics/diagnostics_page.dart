import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../app/app_tokens.dart';
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
            const SizedBox(height: 14),
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
    return AppPanel(
      title: 'Summary',
      trailing: StatusBadge(
        label: statusStore.online ? 'Status loaded' : 'No snapshot',
        tone: statusStore.online ? StatusTone.good : StatusTone.bad,
      ),
      child: Wrap(
        spacing: 24,
        runSpacing: 4,
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

class _RawJson extends StatefulWidget {
  const _RawJson({required this.statusStore, required this.snapshot});

  final StatusStore statusStore;
  final DaemonSnapshot? snapshot;

  @override
  State<_RawJson> createState() => _RawJsonState();
}

class _RawJsonState extends State<_RawJson> {
  var _copied = false;

  @override
  Widget build(BuildContext context) {
    final raw = widget.snapshot?.prettyJson ?? _readableErrorJson();
    return AppPanel(
      title: 'Raw /status JSON',
      trailing: OutlinedButton.icon(
        onPressed: () => _copy(raw),
        icon: Icon(
          _copied ? Icons.check_circle_outline : Icons.copy_all_outlined,
          size: 16,
        ),
        label: Text(_copied ? 'Copied' : 'Copy'),
      ),
      child: Container(
        width: double.infinity,
        constraints: const BoxConstraints(minHeight: 240),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: AppTokens.colorConsoleBg,
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          border: Border.all(color: AppTokens.colorConsoleBorder),
        ),
        child: SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          child: SelectableText(
            raw,
            style: const TextStyle(
              color: AppTokens.colorConsoleText,
              fontFamily: 'monospace',
              fontSize: 12.5,
              height: 1.4,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          ),
        ),
      ),
    );
  }

  String _readableErrorJson() {
    const encoder = JsonEncoder.withIndent('  ');
    return encoder.convert({
      'status': widget.statusStore.healthReachable
          ? 'status_unavailable'
          : 'offline',
      'health_endpoint': widget.statusStore.healthReachable
          ? 'reachable'
          : 'offline',
      'status_endpoint': widget.statusStore.statusReachable
          ? 'loaded'
          : widget.statusStore.healthReachable
          ? 'error'
          : 'skipped',
      if (widget.statusStore.lastError != null)
        'error': widget.statusStore.lastError,
      if (widget.statusStore.lastFetchedAt != null)
        'last_refresh': widget.statusStore.lastFetchedAt!.toIso8601String(),
      if (widget.statusStore.lastRequestDuration != null)
        'request_duration_ms':
            widget.statusStore.lastRequestDuration!.inMilliseconds,
    });
  }

  Future<void> _copy(String raw) async {
    await Clipboard.setData(ClipboardData(text: raw));
    if (!mounted) return;
    setState(() => _copied = true);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Diagnostics JSON copied to clipboard'),
        duration: Duration(seconds: 2),
      ),
    );
    await Future<void>.delayed(const Duration(seconds: 2));
    if (mounted) {
      setState(() => _copied = false);
    }
  }
}
