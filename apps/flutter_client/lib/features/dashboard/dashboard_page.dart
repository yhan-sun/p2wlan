import 'package:flutter/material.dart';

import '../../app/app_tokens.dart';
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
              snapshot: snapshot,
              online: statusStore.online,
              healthReachable: statusStore.healthReachable,
              statusReachable: statusStore.statusReachable,
              refreshing: statusStore.refreshing,
              autoRefreshEnabled: statusStore.autoRefreshEnabled,
              error: statusStore.lastError,
              healthError: statusStore.lastHealthError,
              statusError: statusStore.lastStatusError,
              lastFetchedAt: statusStore.lastFetchedAt,
              requestDuration: statusStore.lastRequestDuration,
              onRefresh: statusStore.refresh,
              onAutoRefreshChanged: (value) => statusStore.setAutoRefresh(
                enabled: value,
                refreshImmediately: value,
              ),
            ),
            const SizedBox(height: 14),
            if (snapshot == null)
              const _OfflineSummary()
            else ...[
              _StatusGrid(snapshot: snapshot),
              const SizedBox(height: 14),
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
    required this.snapshot,
    required this.online,
    required this.healthReachable,
    required this.statusReachable,
    required this.refreshing,
    required this.autoRefreshEnabled,
    required this.error,
    required this.healthError,
    required this.statusError,
    required this.lastFetchedAt,
    required this.requestDuration,
    required this.onRefresh,
    required this.onAutoRefreshChanged,
  });

  final String url;
  final DaemonSnapshot? snapshot;
  final bool online;
  final bool healthReachable;
  final bool statusReachable;
  final bool refreshing;
  final bool autoRefreshEnabled;
  final String? error;
  final String? healthError;
  final String? statusError;
  final DateTime? lastFetchedAt;
  final Duration? requestDuration;
  final Future<void> Function() onRefresh;
  final ValueChanged<bool> onAutoRefreshChanged;

  @override
  Widget build(BuildContext context) {
    final overallLabel = _overallLabel();
    final tone = _overallTone(overallLabel);
    return AppPanel(
      title: 'Local daemon',
      trailing: StatusBadge(label: overallLabel, tone: tone),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Wrap(
            spacing: 24,
            runSpacing: 4,
            children: [
              MetricTile(label: 'Diagnostics URL', value: url),
              MetricTile(label: 'Daemon state', value: overallLabel),
              MetricTile(
                label: 'GET /health',
                value: healthReachable ? 'reachable' : 'offline',
                detail: healthError,
              ),
              MetricTile(
                label: 'GET /status',
                value: _statusEndpointLabel(),
                detail: statusError,
              ),
              MetricTile(
                label: 'Last refresh',
                value: formatDateTime(lastFetchedAt),
              ),
              MetricTile(
                label: 'Request duration',
                value: formatDuration(requestDuration),
              ),
              if (error != null) MetricTile(label: 'Last error', value: error!),
            ],
          ),
          const SizedBox(height: 8),
          const Divider(),
          const SizedBox(height: 12),
          Wrap(
            spacing: 16,
            runSpacing: 8,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              FilledButton.icon(
                key: const Key('dashboard-refresh-button'),
                onPressed: refreshing ? null : onRefresh,
                icon: refreshing
                    ? const SizedBox.square(
                        dimension: 14,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          valueColor: AlwaysStoppedAnimation<Color>(
                            Colors.white,
                          ),
                        ),
                      )
                    : const Icon(Icons.refresh, size: 18),
                label: Text(refreshing ? 'Refreshing...' : 'Refresh now'),
              ),
              InkWell(
                onTap: () => onAutoRefreshChanged(!autoRefreshEnabled),
                borderRadius: BorderRadius.circular(AppTokens.radiusSm),
                child: Padding(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 4,
                    vertical: 2,
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      SizedBox(
                        width: 44,
                        height: 44,
                        child: Center(
                          child: SizedBox(
                            width: 36,
                            height: 22,
                            child: Switch(
                              key: const Key('auto-refresh-switch'),
                              value: autoRefreshEnabled,
                              onChanged: onAutoRefreshChanged,
                              activeTrackColor: AppTokens.colorAccent,
                              materialTapTargetSize:
                                  MaterialTapTargetSize.shrinkWrap,
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(width: 4),
                      Text(
                        'Auto refresh (${StatusStore.defaultAutoRefreshInterval.inSeconds}s)',
                        style: const TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w500,
                          color: AppTokens.colorTextSecondary,
                        ),
                      ),
                      const SizedBox(width: 8),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  String _overallLabel() {
    if (!healthReachable) return 'Offline';
    if (!statusReachable) return 'Degraded';
    final status = snapshot?.health.status.toLowerCase();
    return switch (status) {
      'healthy' => 'Healthy',
      'degraded' => 'Degraded',
      'unhealthy' => 'Unhealthy',
      'shutting_down' => 'Unavailable',
      _ => 'Online',
    };
  }

  String _statusEndpointLabel() {
    if (statusReachable) return 'loaded';
    if (healthReachable) return 'error';
    return 'skipped';
  }

  StatusTone _overallTone(String label) {
    return switch (label) {
      'Healthy' || 'Online' => StatusTone.good,
      'Degraded' => StatusTone.warn,
      _ => StatusTone.bad,
    };
  }
}

class _OfflineSummary extends StatelessWidget {
  const _OfflineSummary();

  @override
  Widget build(BuildContext context) {
    return const AppPanel(
      title: 'Snapshot',
      child: Text(
        'No daemon snapshot is available. Run local p2pnet-daemon outside this app; this client operates in read-only diagnostics mode.',
        style: TextStyle(fontSize: 13, color: AppTokens.colorTextSecondary),
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
    return AppPanel(
      title: 'Runtime snapshot',
      trailing: StatusBadge(
        label: snapshot.health.status,
        tone: _healthTone(snapshot.health.status),
      ),
      child: Wrap(
        spacing: 24,
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
    return AppPanel(
      title: 'Peer paths',
      child: Wrap(
        spacing: 24,
        runSpacing: 4,
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
