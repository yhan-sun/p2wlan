import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../../app/app_constants.dart';
import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/capabilities/platform_capabilities.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/formatters.dart';
import '../../shared/layout/app_breakpoints.dart';
import '../../shared/widgets/info_card.dart';
import '../../shared/widgets/page_scaffold.dart';
import '../../shared/widgets/status_badge.dart';

part 'dashboard/helpers.dart';
part 'dashboard/surface.dart';
part 'dashboard/hero.dart';
part 'dashboard/peer_overview.dart';
part 'dashboard/connection_map.dart';
part 'dashboard/network_environment.dart';
part 'dashboard/issues.dart';
part 'dashboard/actions.dart';

class DashboardPage extends StatelessWidget {
  const DashboardPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.showHeader = true,
    this.capabilities,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final bool showHeader;

  /// Platform capability override (primarily for tests); defaults to the
  /// current runtime platform.
  final PlatformCapabilities? capabilities;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final capabilities = this.capabilities ?? PlatformCapabilities.current();
    return AnimatedBuilder(
      animation: Listenable.merge([settingsStore, statusStore]),
      builder: (context, _) {
        final snapshot = statusStore.snapshot;
        final status = _networkStatus(
          snapshot,
          snapshotStale: statusStore.snapshotStale,
          healthReachable: statusStore.healthReachable,
        );
        final daemonAvailable =
            statusStore.daemonReachable || statusStore.statusReachable;
        final peers = snapshot?.peers ?? const <PeerSnapshot>[];
        final counts = _countPeers(peers);
        final overviewPeers = _topOverviewPeers(peers);
        final issueMessage = _dashboardIssueMessage(
          strings: strings,
          daemonAvailable: daemonAvailable,
          snapshotStale: statusStore.snapshotStale,
          statusReachable: statusStore.statusReachable,
          statusError: statusStore.lastStatusError,
          healthReachable: statusStore.healthReachable,
          healthError: statusStore.lastHealthError,
          error: statusStore.lastError,
          snapshot: snapshot,
        );
        final manualCommand = settingsStore.settings.authToken.trim().isEmpty
            ? statusStore.lastDaemonManualCommand
            : null;
        return PageScaffold(
          title: strings.dashboard,
          subtitle: strings.dashboardSubtitle,
          showHeader: showHeader,
          maxWidth: dashboardPageMaxWidth,
          children: [
            _NetworkHero(
              snapshot: snapshot,
              status: status,
              counts: counts,
              daemonAvailable: daemonAvailable,
              canControlLocalDaemon: capabilities.canControlLocalDaemon,
              daemonBusy: statusStore.daemonBusy,
              refreshing: statusStore.refreshing,
              onStartDaemon: statusStore.startDaemon,
              onStopDaemon: statusStore.stopDaemon,
              onRefresh: statusStore.refresh,
            ),
            if (snapshot != null) ...[
              const SizedBox(height: 16),
              LayoutBuilder(
                builder: (context, constraints) {
                  if (constraints.maxWidth >= AppBreakpoints.expandedMinWidth) {
                    return Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(
                          flex: 2,
                          child: _PeerOverview(
                            peers: overviewPeers,
                            totalPeers: peers.length,
                            showMap:
                                daemonAvailable && overviewPeers.isNotEmpty,
                          ),
                        ),
                        const SizedBox(width: 14),
                        Expanded(
                          flex: 1,
                          child: _NetworkEnvironment(
                            snapshot: snapshot,
                            lastFetchedAt: statusStore.lastSuccessfulStatusAt,
                            requestDuration: statusStore.lastRequestDuration,
                            snapshotStale: statusStore.snapshotStale,
                          ),
                        ),
                      ],
                    );
                  }
                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      _PeerOverview(
                        peers: overviewPeers,
                        totalPeers: peers.length,
                        showMap: false,
                      ),
                      const SizedBox(height: 16),
                      _NetworkEnvironment(
                        snapshot: snapshot,
                        lastFetchedAt: statusStore.lastSuccessfulStatusAt,
                        requestDuration: statusStore.lastRequestDuration,
                        snapshotStale: statusStore.snapshotStale,
                      ),
                    ],
                  );
                },
              ),
            ],
            if (issueMessage != null && daemonAvailable) ...[
              const SizedBox(height: 16),
              _DashboardIssues(
                message: issueMessage,
                tone:
                    !statusStore.healthReachable &&
                        statusStore.lastHealthError != null
                    ? StatusTone.bad
                    : StatusTone.warn,
              ),
            ],
            if (manualCommand != null) ...[
              const SizedBox(height: 16),
              _ManualDaemonCommand(command: manualCommand),
            ],
          ],
        );
      },
    );
  }
}
