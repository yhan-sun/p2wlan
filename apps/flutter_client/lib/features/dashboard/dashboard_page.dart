import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../app/app_constants.dart';
import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/capabilities/platform_capabilities.dart';
import '../../core/daemon/daemon_controller.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/presentation/network_overview.dart';
import '../../core/presentation/traffic_statistics.dart';
import '../../core/rooms/room_profiles.dart';
import '../../shared/network_overview_presentation.dart';
import '../../shared/widgets/network_scope_picker.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/formatters.dart';
import '../../shared/permission_copy.dart';
import '../../shared/widgets/app_motion.dart';
import '../../shared/widgets/app_notice.dart';
import '../../shared/widgets/traffic_totals.dart';
import '../../shared/widgets/traffic_history_scope.dart';
import '../../shared/widgets/traffic_history_section.dart';
import '../../shared/widgets/page_scaffold.dart';
import '../../shared/widgets/status_badge.dart';
import '../../shared/widgets/device_type_icon.dart';

part 'dashboard/actions.dart';
part 'dashboard/components.dart';
part 'dashboard/devices.dart';
part 'dashboard/helpers.dart';
part 'dashboard/hero.dart';
part 'dashboard/issues.dart';
part 'dashboard/surface.dart';
part 'dashboard/room_overview.dart';
part 'dashboard/traffic.dart';

/// Network Home: tells the user how the network is doing right now — status,
/// Virtual IP, key metrics, a short device preview, and plain-language
/// component state. Technical details live in Diagnostics / Troubleshooting.
class DashboardPage extends StatefulWidget {
  const DashboardPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.showHeader = true,
    this.capabilities,
    this.onOpenDevices,
    this.onOpenPeer,
    this.onOpenTroubleshooting,
    this.onOpenRooms,
    this.onOpenRoom,
    this.onReauthenticate,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final bool showHeader;

  /// Platform capability override (primarily for tests); defaults to the
  /// current runtime platform.
  final PlatformCapabilities? capabilities;

  /// Opens the Devices section (supplied by the shell).
  final VoidCallback? onOpenDevices;

  /// Requests the Devices section to open one peer through its canonical
  /// list/detail flow.
  final ValueChanged<PeerSnapshot>? onOpenPeer;

  /// Opens Troubleshooting for a reported issue (supplied by the shell).
  final VoidCallback? onOpenTroubleshooting;

  final VoidCallback? onOpenRooms;
  final ValueChanged<String>? onOpenRoom;
  final VoidCallback? onReauthenticate;

  @override
  State<DashboardPage> createState() => _DashboardPageState();
}

class _DashboardPageState extends State<DashboardPage> {
  String? _selectedScopeId;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final capabilities = widget.capabilities ?? PlatformCapabilities.current();
    return AnimatedBuilder(
      animation: Listenable.merge([
        widget.settingsStore,
        widget.statusStore,
        widget.statusStore.parallelRooms,
      ]),
      builder: (context, _) {
        final overview = NetworkOverview.read(widget.statusStore);
        final selectedId = overview.selected(_selectedScopeId).isEmpty
            ? null
            : _selectedScopeId;
        final showRoomOverview =
            overview.hasRooms && selectedId != NetworkOverview.primaryScopeId;
        final snapshot = widget.statusStore.snapshot;
        final primaryStale = overview.scopes.any(
          (scope) =>
              scope.isPrimary && scope.state == NetworkDisplayState.stale,
        );
        final status = _networkStatus(
          snapshot,
          snapshotStale: primaryStale,
          healthReachable: widget.statusStore.healthReachable,
        );
        final daemonAvailable =
            widget.statusStore.daemonReachable ||
            widget.statusStore.statusReachable;
        final initialProbePending =
            widget.statusStore.daemonStarting ||
            (snapshot == null && widget.statusStore.startupCatalogSettling) ||
            (widget.statusStore.lastFetchedAt == null &&
                widget.statusStore.refreshing);
        final startupFailure =
            !widget.statusStore.daemonBusy &&
                widget.statusStore.lastDaemonFailureCode != null
            ? daemonStartupFailurePresentation(
                strings,
                DaemonCommandResult(
                  ok: false,
                  message: '',
                  failureCode: widget.statusStore.lastDaemonFailureCode,
                ),
              )
            : !widget.statusStore.daemonBusy &&
                  widget.statusStore.lastError == 'daemon_operation_failed'
            ? strings.daemonOperationFailed
            : null;
        final peers = snapshot?.peers ?? const <PeerSnapshot>[];
        final counts = _countPeers(peers);
        final overviewPeers = _topOverviewPeers(
          widget.statusStore.stablePeerOrder(peers),
        );
        final peerTransferRates = primaryStale
            ? const <String, int>{}
            : widget.statusStore.peerTransferRatesBytesPerSecond;
        final issueMessage =
            startupFailure ??
            _dashboardIssueMessage(
              strings: strings,
              daemonAvailable: daemonAvailable,
              snapshotStale: primaryStale,
              statusReachable: widget.statusStore.statusReachable,
              statusError: widget.statusStore.lastStatusError,
              healthReachable: widget.statusStore.healthReachable,
              healthError: widget.statusStore.lastHealthError,
              error: widget.statusStore.lastError,
              snapshot: snapshot,
              startupCatalogSettling:
                  widget.statusStore.startupCatalogSettling ||
                  widget.statusStore.daemonStarting,
            );
        final manualCommand =
            widget.settingsStore.settings.authToken.trim().isEmpty
            ? widget.statusStore.lastDaemonManualCommand
            : null;
        return PageScaffold(
          title: strings.isZh ? '网络概览' : 'Network overview',
          subtitle: strings.homePageSubtitle,
          showHeader: widget.showHeader,
          maxWidth: dashboardPageMaxWidth,
          children: [
            if (capabilities.canActAsLocalVpnNode && overview.hasRooms) ...[
              NetworkScopePicker(
                overview: overview,
                selectedId: selectedId,
                onChanged: (id) => setState(() => _selectedScopeId = id),
              ),
              const SizedBox(height: AppTokens.space8),
            ],
            if (capabilities.canActAsLocalVpnNode && showRoomOverview)
              _RoomHomeOverview(
                overview: overview,
                selectedId: selectedId,
                trafficSection: _TrafficOverviewSection(
                  statusStore: widget.statusStore,
                  selectedId: selectedId,
                ),
                onOpenDevices: widget.onOpenDevices,
                onOpenRooms: widget.onOpenRooms,
                onOpenRoom: widget.onOpenRoom,
                onOpenPeer: widget.onOpenPeer,
              )
            else if (capabilities.canActAsLocalVpnNode)
              _NetworkHero(
                snapshot: snapshot,
                status: status,
                counts: counts,
                canControlLocalDaemon: capabilities.canControlLocalDaemon,
                daemonBusy: widget.statusStore.daemonBusy,
                initialProbePending: initialProbePending,
                configuredRoom: isRoomNetwork(
                  widget.settingsStore.settings.networkId,
                ),
                onOpenRooms: widget.onOpenRooms,
                onStartDaemon: widget.statusStore.startDaemon,
                onStopDaemon: widget.statusStore.stopPrimaryDaemon,
              )
            else
              _RemoteOnlyHero(
                onOpenDevices: widget.onOpenRooms ?? widget.onOpenDevices,
              ),
            if (capabilities.canActAsLocalVpnNode &&
                !showRoomOverview &&
                issueMessage != null &&
                (daemonAvailable || startupFailure != null)) ...[
              const SizedBox(height: AppTokens.space12),
              _HomeIssueBanner(
                message: issueMessage,
                tone:
                    startupFailure != null ||
                        (!widget.statusStore.healthReachable &&
                            widget.statusStore.lastHealthError != null)
                    ? StatusTone.bad
                    : StatusTone.warn,
                onOpenTroubleshooting: widget.onOpenTroubleshooting,
                onReauthenticate: snapshot?.health.reauthRequired == true
                    ? widget.onReauthenticate
                    : null,
              ),
            ],
            if (capabilities.canActAsLocalVpnNode &&
                !showRoomOverview &&
                snapshot == null &&
                !(capabilities.canControlLocalDaemon &&
                    status == _NetworkStatus.stopped) &&
                widget.onOpenRooms != null) ...[
              const SizedBox(height: AppTokens.space12),
              _RoomEntryAction(onOpenRooms: widget.onOpenRooms!),
            ],
            if (capabilities.canActAsLocalVpnNode &&
                !showRoomOverview &&
                manualCommand != null) ...[
              const SizedBox(height: AppTokens.space12),
              _ManualCommandCard(command: manualCommand),
            ],
            if (capabilities.canActAsLocalVpnNode && !showRoomOverview) ...[
              const SizedBox(height: AppTokens.space16),
              _TrafficOverviewSection(
                statusStore: widget.statusStore,
                selectedId: selectedId,
              ),
            ],
            if (capabilities.canActAsLocalVpnNode &&
                !showRoomOverview &&
                snapshot != null) ...[
              const SizedBox(height: AppTokens.space16),
              _DashboardSectionSurface(
                child: _OnlineDevicesSection(
                  peers: overviewPeers,
                  current: !primaryStale,
                  peerTransferRates: peerTransferRates,
                  onOpenDevices: widget.onOpenDevices,
                  onOpenPeer: widget.onOpenPeer,
                  onOpenRooms: widget.onOpenRooms,
                ),
              ),
              if (!primaryStale) ...[
                const SizedBox(height: AppTokens.space12),
                _ConnectionDetails(snapshot: snapshot, counts: counts),
              ],
            ],
          ],
        );
      },
    );
  }
}
