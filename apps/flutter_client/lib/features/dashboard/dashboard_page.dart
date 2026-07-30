import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
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
    final strings = AppStringsScope.of(context);
    return AnimatedBuilder(
      animation: Listenable.merge([settingsStore, statusStore]),
      builder: (context, _) {
        final snapshot = statusStore.snapshot;
        return PageScaffold(
          title: strings.dashboard,
          subtitle: strings.dashboardSubtitle,
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
    final strings = AppStringsScope.of(context);
    final overallLabel = _overallLabel(strings);
    final tone = _overallTone();
    return AppPanel(
      title: strings.localDaemon,
      trailing: StatusBadge(label: overallLabel, tone: tone),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Wrap(
            spacing: 24,
            runSpacing: 4,
            children: [
              MetricTile(label: strings.diagnosticsUrl, value: url),
              MetricTile(label: strings.daemonState, value: overallLabel),
              MetricTile(
                label: 'GET /health',
                value: healthReachable ? strings.reachable : strings.offline,
                detail: strings.statusMessage(healthError),
              ),
              MetricTile(
                label: 'GET /status',
                value: strings.endpointStatusLabel(
                  statusReachable: statusReachable,
                  healthReachable: healthReachable,
                ),
                detail: strings.statusMessage(statusError),
              ),
              MetricTile(
                label: strings.lastRefresh,
                value: formatDateTime(lastFetchedAt),
              ),
              MetricTile(
                label: strings.requestDuration,
                value: formatDuration(requestDuration),
              ),
              if (error != null)
                MetricTile(
                  label: strings.lastError,
                  value: strings.statusMessage(error) ?? error!,
                ),
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
                label: Text(
                  refreshing ? strings.refreshing : strings.refreshNow,
                ),
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
                        strings.autoRefresh(
                          StatusStore.defaultAutoRefreshInterval.inSeconds,
                        ),
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

  String _overallLabel(AppStrings strings) {
    if (!healthReachable) return strings.offline;
    if (!statusReachable) return strings.degraded;
    final status = snapshot?.health.status.toLowerCase();
    return switch (status) {
      'healthy' => strings.healthy,
      'degraded' => strings.degraded,
      'unhealthy' => strings.unhealthy,
      'shutting_down' => strings.unavailable,
      _ => strings.online,
    };
  }

  StatusTone _overallTone() {
    if (!healthReachable) return StatusTone.bad;
    if (!statusReachable) return StatusTone.warn;
    return switch (snapshot?.health.status.toLowerCase()) {
      'healthy' => StatusTone.good,
      'degraded' => StatusTone.warn,
      _ => StatusTone.bad,
    };
  }
}

class _OfflineSummary extends StatelessWidget {
  const _OfflineSummary();

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AppPanel(
      title: strings.snapshot,
      child: Text(
        strings.offlineSnapshotMessage,
        style: const TextStyle(
          fontSize: 13,
          color: AppTokens.colorTextSecondary,
        ),
      ),
    );
  }
}

class _StatusGrid extends StatelessWidget {
  const _StatusGrid({required this.snapshot});

  final DaemonSnapshot snapshot;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final relay = snapshot.relaySelection;
    return AppPanel(
      title: strings.runtimeSnapshot,
      trailing: StatusBadge(
        label: strings.daemonHealthStatus(snapshot.health.status),
        tone: _healthTone(snapshot.health.status),
      ),
      child: Wrap(
        spacing: 24,
        runSpacing: 4,
        children: [
          MetricTile(
            label: strings.nodeId,
            value: shortId(snapshot.nodeId),
            detail: snapshot.nodeId,
          ),
          MetricTile(label: strings.virtualIp, value: dash(snapshot.virtualIp)),
          MetricTile(label: strings.networkId, value: dash(snapshot.networkId)),
          MetricTile(
            label: strings.daemonHealth,
            value: strings.daemonHealthStatus(snapshot.health.status),
            detail: snapshot.health.reason,
          ),
          MetricTile(
            label: strings.udpLocalAddr,
            value: dash(snapshot.udpLocalAddr),
          ),
          MetricTile(
            label: strings.relay,
            value: snapshot.relayConnected
                ? strings.connected
                : strings.notConnected,
            detail: dash(relay.selectedEndpoint ?? relay.lastError),
          ),
          MetricTile(
            label: strings.relayRegion,
            value: dash(relay.selectedRegion),
          ),
          MetricTile(
            label: strings.peers,
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
    final strings = AppStringsScope.of(context);
    return AppPanel(
      title: strings.peerPaths,
      child: Wrap(
        spacing: 24,
        runSpacing: 4,
        children: [
          MetricTile(
            label: strings.totalPeers,
            value: formatInt(snapshot.stats.totalPeers),
          ),
          MetricTile(
            label: strings.directPaths,
            value: formatInt(snapshot.stats.directConnections),
          ),
          MetricTile(
            label: strings.relayPaths,
            value: formatInt(snapshot.stats.relayConnections),
          ),
          MetricTile(
            label: strings.bytesSent,
            value: formatBytes(snapshot.stats.totalBytesSent),
          ),
          MetricTile(
            label: strings.bytesReceived,
            value: formatBytes(snapshot.stats.totalBytesReceived),
          ),
        ],
      ),
    );
  }
}
