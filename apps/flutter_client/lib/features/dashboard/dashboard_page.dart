import 'package:flutter/material.dart';

import '../../core/models/daemon_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/formatters.dart';
import '../../shared/widgets/info_card.dart';
import '../../shared/widgets/page_scaffold.dart';
import '../../shared/widgets/status_badge.dart';

class DashboardPage extends StatelessWidget {
  const DashboardPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: Listenable.merge([settingsStore, statusStore]),
      builder: (context, _) {
        final snapshot = statusStore.snapshot;
        return PageScaffold(
          title: 'Dashboard',
          subtitle:
              'Read-only view of the local P2WLAN daemon diagnostics endpoint.',
          children: [
            _ConnectionBanner(
              url: settingsStore.settings.diagnosticsUrl,
              online: statusStore.online,
              healthReachable: statusStore.healthReachable,
              error: statusStore.lastError,
              lastFetchedAt: statusStore.lastFetchedAt,
            ),
            const SizedBox(height: 16),
            if (snapshot == null)
              const _OfflineSummary()
            else ...[
              _StatusGrid(snapshot: snapshot),
              const SizedBox(height: 16),
              _PeerPathSummary(snapshot: snapshot),
            ],
          ],
        );
      },
    );
  }
}

class _ConnectionBanner extends StatelessWidget {
  const _ConnectionBanner({
    required this.url,
    required this.online,
    required this.healthReachable,
    required this.error,
    required this.lastFetchedAt,
  });

  final String url;
  final bool online;
  final bool healthReachable;
  final String? error;
  final DateTime? lastFetchedAt;

  @override
  Widget build(BuildContext context) {
    final tone = online
        ? StatusTone.good
        : healthReachable
        ? StatusTone.warn
        : StatusTone.bad;
    return InfoCard(
      title: 'Local daemon',
      trailing: StatusBadge(label: online ? 'Online' : 'Offline', tone: tone),
      child: Wrap(
        spacing: 28,
        runSpacing: 8,
        children: [
          MetricTile(label: 'Diagnostics URL', value: url),
          MetricTile(
            label: 'Health endpoint',
            value: healthReachable ? 'reachable' : 'offline',
          ),
          MetricTile(
            label: 'Last refresh',
            value: formatDateTime(lastFetchedAt),
          ),
          if (error != null) MetricTile(label: 'Last error', value: error!),
        ],
      ),
    );
  }
}

class _OfflineSummary extends StatelessWidget {
  const _OfflineSummary();

  @override
  Widget build(BuildContext context) {
    return const InfoCard(
      title: 'Snapshot',
      child: Text(
        'No daemon snapshot is available. Start an existing p2pnet-daemon manually and keep this P1 prototype in read-only mode.',
      ),
    );
  }
}

class _StatusGrid extends StatelessWidget {
  const _StatusGrid({required this.snapshot});

  final DaemonSnapshot snapshot;

  @override
  Widget build(BuildContext context) {
    final relay = snapshot.relaySelection;
    return InfoCard(
      title: 'Runtime snapshot',
      trailing: StatusBadge(
        label: snapshot.health.status,
        tone: _healthTone(snapshot.health.status),
      ),
      child: Wrap(
        spacing: 12,
        runSpacing: 4,
        children: [
          MetricTile(
            label: 'Node ID',
            value: shortId(snapshot.nodeId),
            detail: snapshot.nodeId,
          ),
          MetricTile(label: 'Virtual IP', value: dash(snapshot.virtualIp)),
          MetricTile(label: 'Network ID', value: dash(snapshot.networkId)),
          MetricTile(
            label: 'Daemon health',
            value: snapshot.health.status,
            detail: snapshot.health.reason,
          ),
          MetricTile(
            label: 'UDP local addr',
            value: dash(snapshot.udpLocalAddr),
          ),
          MetricTile(
            label: 'Relay',
            value: snapshot.relayConnected ? 'connected' : 'not connected',
            detail: dash(relay.selectedEndpoint ?? relay.lastError),
          ),
          MetricTile(label: 'Relay region', value: dash(relay.selectedRegion)),
          MetricTile(
            label: 'Peers',
            value: formatInt(snapshot.stats.totalPeers),
          ),
        ],
      ),
    );
  }

  StatusTone _healthTone(String status) {
    return switch (status) {
      'healthy' => StatusTone.good,
      'degraded' => StatusTone.warn,
      'unhealthy' || 'shutting_down' => StatusTone.bad,
      _ => StatusTone.neutral,
    };
  }
}

class _PeerPathSummary extends StatelessWidget {
  const _PeerPathSummary({required this.snapshot});

  final DaemonSnapshot snapshot;

  @override
  Widget build(BuildContext context) {
    return InfoCard(
      title: 'Peer paths',
      child: Wrap(
        spacing: 28,
        runSpacing: 8,
        children: [
          MetricTile(
            label: 'Total peers',
            value: formatInt(snapshot.stats.totalPeers),
          ),
          MetricTile(
            label: 'Direct paths',
            value: formatInt(snapshot.stats.directConnections),
          ),
          MetricTile(
            label: 'Relay paths',
            value: formatInt(snapshot.stats.relayConnections),
          ),
          MetricTile(
            label: 'Bytes sent',
            value: formatBytes(snapshot.stats.totalBytesSent),
          ),
          MetricTile(
            label: 'Bytes received',
            value: formatBytes(snapshot.stats.totalBytesReceived),
          ),
        ],
      ),
    );
  }
}
