import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../app/app_constants.dart';
import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/capabilities/permission_preflight.dart';
import '../../core/capabilities/platform_capabilities.dart';
import '../../core/daemon/diagnostics_auth.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/security/redactor.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/formatters.dart';
import '../../shared/permission_copy.dart';
import '../../shared/log_tail.dart';
import '../../shared/widgets/info_card.dart';
import '../../shared/widgets/page_scaffold.dart';
import '../../shared/widgets/status_badge.dart';
import 'diagnostics_model.dart';

part 'diagnostics/actions.dart';
part 'diagnostics/advanced.dart';
part 'diagnostics/checks.dart';
part 'diagnostics/overview.dart';
part 'diagnostics/issues.dart';
part 'diagnostics/network.dart';
part 'diagnostics/platform_panel.dart';
part 'diagnostics/status_panels.dart';
part 'diagnostics/raw_json.dart';
part 'diagnostics/recent_logs.dart';
part 'diagnostics/helpers.dart';

class DiagnosticsPage extends StatefulWidget {
  const DiagnosticsPage({
    super.key,
    required this.statusStore,
    this.settingsStore,
    this.showHeader = true,
    this.capabilities,
    this.permissionCheck,
    this.logPreviewLoader,
    this.openLogs,
    this.onOpenDevices,
    this.onOpenSettings,
  });

  final StatusStore statusStore;

  /// Provides the diagnostics URL / TUN / MTU settings used by the network
  /// diagnostics (route verify, repair, daemon restart) inside Advanced.
  final SettingsStore? settingsStore;

  final bool showHeader;

  /// Platform capability override (primarily for tests); defaults to the
  /// current runtime platform.
  final PlatformCapabilities? capabilities;

  /// Test seam: replaces the real platform permission preflight. When null the
  /// real preflight runs (and only runs once the advanced section is expanded).
  final Future<PermissionPreflight> Function()? permissionCheck;

  /// Test seam: replaces the bounded log-tail loader. When null the real
  /// loader runs (and only runs once the advanced section is expanded).
  final Future<DiagnosticsLogPreview> Function()? logPreviewLoader;

  /// Test seam: replaces the "open logs directory" action. When null the
  /// platform launcher (open/explorer/xdg-open) runs, with errors surfaced as
  /// a localized message instead of an uncaught exception.
  final Future<void> Function()? openLogs;

  /// Shell callback for the "view devices" issue action.
  final VoidCallback? onOpenDevices;

  /// Shell callback for the "open settings" (reauth) issue action.
  final VoidCallback? onOpenSettings;

  @override
  State<DiagnosticsPage> createState() => _DiagnosticsPageState();
}

class _DiagnosticsPageState extends State<DiagnosticsPage> {
  late final PlatformCapabilities _capabilities;
  var _advancedExpanded = false;

  @override
  void initState() {
    super.initState();
    _capabilities = widget.capabilities ?? PlatformCapabilities.current();
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AnimatedBuilder(
      animation: Listenable.merge([widget.statusStore, widget.settingsStore]),
      builder: (context, _) {
        final statusStore = widget.statusStore;
        final snapshot = statusStore.snapshot;
        final model = buildDiagnosticsModel(
          strings: strings,
          healthReachable: statusStore.healthReachable,
          statusReachable: statusStore.statusReachable,
          snapshotStale: statusStore.snapshotStale,
          snapshot: snapshot,
        );
        final canLocal =
            _capabilities.canActAsLocalVpnNode &&
            _capabilities.canControlLocalDaemon;
        final refreshing = statusStore.refreshing;
        return PageScaffold(
          title: strings.troubleshooting,
          subtitle: strings.diagnosticsSubtitle,
          showHeader: widget.showHeader,
          maxWidth: diagnosticsPageMaxWidth,
          children: [
            _SystemStatusCard(
              model: model,
              refreshing: refreshing,
              onRecheck: refreshing ? null : statusStore.refresh,
            ),
            // Issues only appear when there is something to do; a healthy page
            // never shows a redundant "no issues" card (the status card above
            // already says everything is fine).
            if (model.issues.isNotEmpty) ...[
              const SizedBox(height: AppTokens.space14),
              _IssuesPanel(
                issues: model.issues,
                refreshing: refreshing,
                onRecheck: statusStore.refresh,
                onOpenDevices: widget.onOpenDevices,
                onOpenSettings: widget.onOpenSettings,
              ),
            ],
            if (model.checks.isNotEmpty) ...[
              const SizedBox(height: AppTokens.space14),
              _ChecksPanel(checks: model.checks),
            ],
            const SizedBox(height: AppTokens.space14),
            _AdvancedDisclosure(
              open: _advancedExpanded,
              onToggle: () =>
                  setState(() => _advancedExpanded = !_advancedExpanded),
              children: _buildAdvancedChildren(
                statusStore: statusStore,
                snapshot: snapshot,
                canLocal: canLocal,
              ),
            ),
          ],
        );
      },
    );
  }

  /// Lazy advanced section: nothing below is constructed (or run) until the
  /// user expands the disclosure. Network route verification, permission
  /// preflight, log tail reads, and the raw JSON builder are all skipped while
  /// collapsed.
  List<Widget> _buildAdvancedChildren({
    required StatusStore statusStore,
    required DiagnosticsSnapshot? snapshot,
    required bool canLocal,
  }) {
    if (!_advancedExpanded) return const [];
    final children = <Widget>[];

    // 1. Network & routes first: this is where the former Tunnels page lives.
    //    Only constructed when the advanced section is open, so route verify
    //    never fires on page load.
    final settingsStore = widget.settingsStore;
    if (settingsStore != null && _capabilities.canActAsLocalVpnNode) {
      children.add(
        _NetworkDiagnosticsSection(
          settingsStore: settingsStore,
          statusStore: statusStore,
          capabilities: _capabilities,
        ),
      );
      children.add(const SizedBox(height: AppTokens.space14));
    }

    // 2. Technical runtime.
    children.add(
      _RuntimeDetailsPanel(statusStore: statusStore, snapshot: snapshot),
    );

    // 3. Platform permissions (local only).
    if (canLocal) {
      children.add(const SizedBox(height: AppTokens.space14));
      children.add(_PlatformPanel(permissionCheck: widget.permissionCheck));
    }

    // 4. Protocol / MTU + critical tasks (require a snapshot).
    if (snapshot != null) {
      children.add(const SizedBox(height: AppTokens.space14));
      children.add(_ProtocolMtuPanel(snapshot: snapshot));
      children.add(const SizedBox(height: AppTokens.space14));
      children.add(_TaskPanel(snapshot: snapshot));
    }

    // 5. Logs (local only).
    if (_capabilities.canOpenLocalLogs) {
      children.add(const SizedBox(height: AppTokens.space14));
      children.add(
        _RecentLogsPanel(
          logPreviewLoader: widget.logPreviewLoader,
          openLogs: widget.openLogs,
        ),
      );
    }

    // 6. Support tools: copy diagnostics summary (kept, but demoted here).
    children.add(const SizedBox(height: AppTokens.space14));
    children.add(_SupportTools(statusStore: statusStore));

    // 7. Raw JSON stays the lowest-level disclosure.
    children.add(const SizedBox(height: AppTokens.space14));
    children.add(_RawJson(statusStore: statusStore, snapshot: snapshot));
    return children;
  }
}
