import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../app/app_constants.dart';
import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/capabilities/platform_capabilities.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/formatters.dart';
import '../../shared/layout/app_breakpoints.dart';
import '../../shared/widgets/page_scaffold.dart';
import '../../shared/widgets/status_badge.dart';

part 'dashboard/actions.dart';
part 'dashboard/components.dart';
part 'dashboard/devices.dart';
part 'dashboard/helpers.dart';
part 'dashboard/hero.dart';
part 'dashboard/issues.dart';
part 'dashboard/surface.dart';

/// Network Home: tells the user how the network is doing right now — status,
/// Virtual IP, key metrics, a short device preview, and plain-language
/// component state. Technical details live in Diagnostics / Troubleshooting.
class DashboardPage extends StatelessWidget {
  const DashboardPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.showHeader = true,
    this.capabilities,
    this.onOpenDevices,
    this.onOpenTroubleshooting,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final bool showHeader;

  /// Platform capability override (primarily for tests); defaults to the
  /// current runtime platform.
  final PlatformCapabilities? capabilities;

  /// Opens the Devices section (supplied by the shell).
  final VoidCallback? onOpenDevices;

  /// Opens Troubleshooting for a reported issue (supplied by the shell).
  final VoidCallback? onOpenTroubleshooting;

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
        final loading =
            snapshot == null &&
            !daemonAvailable &&
            (statusStore.refreshing || statusStore.daemonBusy);
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
          title: strings.home,
          subtitle: strings.homePageSubtitle,
          showHeader: showHeader,
          maxWidth: dashboardPageMaxWidth,
          children: [
            _NetworkHero(
              snapshot: snapshot,
              status: status,
              loading: loading,
              counts: counts,
              daemonAvailable: daemonAvailable,
              canControlLocalDaemon: capabilities.canControlLocalDaemon,
              daemonBusy: statusStore.daemonBusy,
              refreshing: statusStore.refreshing,
              onStartDaemon: statusStore.startDaemon,
              onStopDaemon: statusStore.stopDaemon,
              onRefresh: statusStore.refresh,
            ),
            if (issueMessage != null && daemonAvailable) ...[
              const SizedBox(height: AppTokens.space12),
              _HomeIssueBanner(
                message: issueMessage,
                tone:
                    !statusStore.healthReachable &&
                        statusStore.lastHealthError != null
                    ? StatusTone.bad
                    : StatusTone.warn,
                onOpenTroubleshooting: onOpenTroubleshooting,
              ),
            ],
            if (snapshot != null) ...[
              const SizedBox(height: AppTokens.space20),
              LayoutBuilder(
                builder: (context, constraints) {
                  if (constraints.maxWidth >= AppBreakpoints.expandedMinWidth) {
                    return Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(
                          flex: 2,
                          child: _OnlineDevicesSection(
                            peers: overviewPeers,
                            onOpenDevices: onOpenDevices,
                          ),
                        ),
                        const SizedBox(width: AppTokens.space16),
                        Expanded(
                          flex: 1,
                          child: _NetworkComponentsSection(
                            snapshot: snapshot,
                            counts: counts,
                          ),
                        ),
                      ],
                    );
                  }
                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      _OnlineDevicesSection(
                        peers: overviewPeers,
                        onOpenDevices: onOpenDevices,
                      ),
                      const SizedBox(height: AppTokens.space20),
                      _NetworkComponentsSection(
                        snapshot: snapshot,
                        counts: counts,
                      ),
                    ],
                  );
                },
              ),
            ],
            if (manualCommand != null) ...[
              const SizedBox(height: AppTokens.space12),
              _ManualCommandCard(command: manualCommand),
            ],
          ],
        );
      },
    );
  }
}
