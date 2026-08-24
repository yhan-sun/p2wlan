part of '../diagnostics_page.dart';

/// Network & route diagnostics — the home of the former Tunnels page inside
/// Troubleshooting → Advanced.
///
/// Keeps every Tunnels capability while removing the standalone page:
///   - virtual adapter data (TUN interface, overlay CIDR, virtual IP, MTU,
///     UDP bind, UDP socket count);
///   - authoritative route verification (state comes only from the daemon
///     verify API, never inferred from "daemon running + virtual IP");
///   - in-place route repair and daemon restart, both capability-gated;
///   - loading / busy states and localized success / failure messages.
///
/// Lazy by construction: the whole section is only mounted once the Advanced
/// disclosure is expanded, so route verification never fires on page load.
class _NetworkDiagnosticsSection extends StatefulWidget {
  const _NetworkDiagnosticsSection({
    required this.settingsStore,
    required this.statusStore,
    required this.capabilities,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final PlatformCapabilities capabilities;

  @override
  State<_NetworkDiagnosticsSection> createState() =>
      _NetworkDiagnosticsSectionState();
}

class _NetworkDiagnosticsSectionState
    extends State<_NetworkDiagnosticsSection> {
  /// Authoritative overlay-route state fetched from the daemon. `null` = not
  /// yet verified; we never guess a healthy route from other facts.
  Map<String, dynamic>? _routeState;
  var _verifying = false;
  var _repairing = false;
  var _rebuilding = false;
  String? _message;
  var _messageIsError = false;

  @override
  void initState() {
    super.initState();
    // One-shot authoritative check on first mount (Advanced expanded only).
    if (widget.capabilities.canVerifyRoutes &&
        widget.statusStore.daemonReachable) {
      _verifyRoutes();
    }
  }

  Future<void> _verifyRoutes() async {
    if (!widget.capabilities.canVerifyRoutes) return;
    final url = widget.settingsStore.settings.diagnosticsUrl;
    if (!widget.statusStore.daemonReachable) return;
    setState(() {
      _verifying = true;
    });
    try {
      final result = await widget.statusStore.diagnosticsApi.verifyRoutes(url);
      if (!mounted) return;
      setState(() => _routeState = result.toJson());
    } catch (_) {
      // Daemon may not expose /routes/verify yet; leave state unknown.
    } finally {
      if (mounted) setState(() => _verifying = false);
    }
  }

  Future<void> _repairRoutes() async {
    if (!widget.capabilities.canRepairRoutes) return;
    final strings = AppStringsScope.of(context);
    final url = widget.settingsStore.settings.diagnosticsUrl;
    setState(() {
      _repairing = true;
      _message = null;
      _messageIsError = false;
    });
    try {
      final result = await widget.statusStore.diagnosticsApi.repairRoutes(url);
      final changed = result.changed;
      final after = result.after;
      if (!mounted) return;
      // Refresh the authoritative route state from the verify API instead of
      // trusting the repair response to carry the full route table.
      final routeState = await _fetchAuthoritativeState();
      if (!mounted) return;
      setState(() {
        _routeState = routeState;
        _message = changed
            ? strings.tunnelRouteRepaired(after)
            : strings.tunnelRouteAlreadyInstalled;
      });
    } catch (_) {
      if (mounted) {
        setState(() {
          _message = strings.tunnelRouteRepairFailed;
          _messageIsError = true;
        });
      }
    } finally {
      if (mounted) setState(() => _repairing = false);
    }
  }

  /// Fetches the authoritative route table from the daemon verify API, or null
  /// when the endpoint is unavailable (state stays "unknown" in the UI).
  Future<Map<String, dynamic>?> _fetchAuthoritativeState() async {
    try {
      final url = widget.settingsStore.settings.diagnosticsUrl;
      final result = await widget.statusStore.diagnosticsApi.verifyRoutes(url);
      return result.toJson();
    } catch (_) {
      return null;
    }
  }

  /// Restart network service — deliberately heavier than check/repair and kept
  /// at the bottom of the section as a low-weight text action.
  Future<void> _restartNetworkService() async {
    if (!widget.capabilities.canControlLocalDaemon) return;
    final strings = AppStringsScope.of(context);
    setState(() {
      _rebuilding = true;
      _message = null;
      _messageIsError = false;
    });
    try {
      final stop = await widget.statusStore.stopDaemon();
      if (!mounted) return;
      if (!stop.ok) {
        setState(() {
          _message = strings.tunnelRestartFailed;
          _messageIsError = true;
        });
        return;
      }
      final start = await widget.statusStore.startDaemon();
      if (!mounted) return;
      setState(() {
        final ok = start.ok;
        _message = ok
            ? strings.daemonRestartedReinstall
            : strings.tunnelRestartFailed;
        _messageIsError = !ok;
      });
    } finally {
      if (mounted) setState(() => _rebuilding = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final settings = widget.settingsStore.settings;
    final snapshot = widget.statusStore.snapshot;
    final running = widget.statusStore.daemonReachable && snapshot != null;
    final busy = _verifying || _repairing || _rebuilding;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _AdvancedSectionHeader(title: strings.networkAndRoutes),
        const SizedBox(height: AppTokens.space10),
        _AdvancedSubsection(
          title: strings.virtualNetwork,
          trailing: StatusBadge(
            label: running
                ? strings.virtualNetworkUp
                : strings.virtualNetworkDown,
            tone: running ? StatusTone.good : StatusTone.neutral,
          ),
          rows: [
            _KvRow(
              label: strings.virtualAdapter,
              value: settings.effectiveTunInterface,
            ),
            _KvRow(label: strings.virtualIp, value: _dash(snapshot?.virtualIp)),
            _KvRow(label: strings.overlayCidr, value: settings.overlayCidr),
            _KvRow(label: strings.mtu, value: settings.mtu.toString()),
            _KvRow(
              label: strings.udpLocalAddr,
              value: _dash(snapshot?.udpLocalAddr ?? settings.udpBind),
            ),
            _KvRow(
              label: strings.udpSockets,
              value: (snapshot?.udpSocketCount ?? 0).toString(),
            ),
          ],
        ),
        const SizedBox(height: AppTokens.space10),
        _buildRoutePanel(strings: strings, running: running, busy: busy),
        if (_message != null) ...[
          const SizedBox(height: AppTokens.space10),
          _NetworkMessage(message: _message!, isError: _messageIsError),
        ],
      ],
    );
  }

  Widget _buildRoutePanel({
    required AppStrings strings,
    required bool running,
    required bool busy,
  }) {
    final state =
        _routeState?['entries'] is List &&
            (_routeState?['entries'] as List).isNotEmpty
        ? ((_routeState?['entries']) as List).first as Map<String, dynamic>
        : null;
    final routeOk = state?['state'] == 'installed';
    final routeConflict = state?['state'] == 'conflict';
    final actual = state?['actual_interface']?.toString();
    final expected = state?['expected_interface']?.toString();

    final String badgeLabel;
    final StatusTone badgeTone;
    if (!running) {
      badgeLabel = strings.offline;
      badgeTone = StatusTone.neutral;
    } else if (state == null) {
      badgeLabel = strings.routeUnknown;
      badgeTone = StatusTone.warn;
    } else if (routeOk) {
      badgeLabel = strings.routeInstalled;
      badgeTone = StatusTone.good;
    } else if (routeConflict) {
      badgeLabel = strings.routeConflict;
      badgeTone = StatusTone.bad;
    } else {
      badgeLabel = strings.routeMissing;
      badgeTone = StatusTone.bad;
    }

    final canVerify = widget.capabilities.canVerifyRoutes;
    final canRepair = widget.capabilities.canRepairRoutes;
    final canRestart = widget.capabilities.canControlLocalDaemon;

    return _AdvancedSubsection(
      title: strings.componentOverlayRoute,
      trailing: StatusBadge(label: badgeLabel, tone: badgeTone),
      rows: [
        _KvRow(label: strings.routeDestination, value: settingsOverlayCidr()),
        _KvRow(
          label: strings.routeExpectedInterface,
          value:
              expected ?? widget.settingsStore.settings.effectiveTunInterface,
        ),
        if (actual != null)
          _KvRow(label: strings.routeActualInterface, value: actual),
        _KvRow(
          label: strings.routeDetail,
          value: state == null
              ? strings.routeNotRead
              : strings.routeAuthoritative(
                  _routeState?['state'] ?? state['state'],
                ),
        ),
      ],
      footer: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (canVerify || canRepair) ...[
            LayoutBuilder(
              builder: (context, constraints) {
                final verifyButton = OutlinedButton.icon(
                  onPressed: running && !busy ? _verifyRoutes : null,
                  icon: _verifying
                      ? const SizedBox.square(
                          dimension: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.check_circle_outline_rounded),
                  label: Text(strings.checkRoutes),
                );
                final repairButton = _routeRepairButton(
                  strings: strings,
                  running: running,
                  busy: busy,
                  routeOk: routeOk,
                );

                // Two expanded buttons become hard to read (and can overflow
                // with large accessibility text) on a phone. Keep the
                // desktop/tablet pair compact, but give each action a full
                // width touch target on narrow layouts.
                if (constraints.maxWidth < 520) {
                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      if (canVerify)
                        SizedBox(width: double.infinity, child: verifyButton),
                      if (canVerify && canRepair)
                        const SizedBox(height: AppTokens.space8),
                      if (canRepair)
                        SizedBox(width: double.infinity, child: repairButton),
                    ],
                  );
                }

                return Row(
                  children: [
                    if (canVerify) Expanded(child: verifyButton),
                    if (canVerify && canRepair)
                      const SizedBox(width: AppTokens.space10),
                    if (canRepair) Expanded(child: repairButton),
                  ],
                );
              },
            ),
            // Repair is never highlighted when the route is already installed.
            if (canRepair && routeOk) ...[
              const SizedBox(height: AppTokens.space6),
              Align(
                alignment: Alignment.centerRight,
                child: Text(
                  strings.noFixNeeded,
                  style: TextStyle(
                    fontSize: 12,
                    color: P2WlanColors.of(context).textSecondary,
                  ),
                ),
              ),
            ],
          ],
          if (canRestart) ...[
            const SizedBox(height: AppTokens.space8),
            // Restarting the network service interrupts the connection; it is
            // a clearly-labelled secondary action, never a primary one.
            Align(
              alignment: Alignment.centerRight,
              child: TextButton.icon(
                onPressed: running && !busy ? _restartNetworkService : null,
                icon: _rebuilding
                    ? const SizedBox.square(
                        dimension: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.restart_alt_rounded, size: 16),
                label: Text(strings.restartNetworkService),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _routeRepairButton({
    required AppStrings strings,
    required bool running,
    required bool busy,
    required bool routeOk,
  }) {
    final onPressed = running && !busy ? _repairRoutes : null;
    if (routeOk) {
      // Installed: low-weight text action only ("无需修复" hint is shown next).
      return TextButton.icon(
        onPressed: onPressed,
        icon: _repairing
            ? const SizedBox.square(
                dimension: 16,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
            : const Icon(Icons.build_rounded, size: 16),
        label: Text(strings.repairRoutes),
      );
    }
    return OutlinedButton.icon(
      onPressed: onPressed,
      icon: _repairing
          ? const SizedBox.square(
              dimension: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : const Icon(Icons.build_rounded),
      label: Text(strings.repairRoutes),
    );
  }

  String settingsOverlayCidr() => widget.settingsStore.settings.overlayCidr;
}

/// A compact, bordered subsection used across Advanced. Avoids the old
/// three-card Tunnels layout — a single quiet surface with rows + footer.
class _AdvancedSubsection extends StatelessWidget {
  const _AdvancedSubsection({
    this.title,
    required this.rows,
    this.trailing,
    this.footer,
  });

  final String? title;
  final Widget? trailing;
  final List<Widget> rows;
  final Widget? footer;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final header = title;
    return Container(
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Padding(
        padding: const EdgeInsets.all(AppTokens.space14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (header != null) ...[
              _AdvancedSubsectionHeader(title: header, trailing: trailing),
              const SizedBox(height: AppTokens.space6),
            ],
            for (final row in rows) row,
            if (footer != null) ...[
              const SizedBox(height: AppTokens.space10),
              footer!,
            ],
          ],
        ),
      ),
    );
  }
}

class _AdvancedSubsectionHeader extends StatelessWidget {
  const _AdvancedSubsectionHeader({required this.title, this.trailing});

  final String title;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final titleWidget = Text(
      title,
      style: TextStyle(
        fontSize: 13,
        fontWeight: FontWeight.w700,
        color: theme.colorScheme.onSurface,
      ),
    );
    final trailingWidget = trailing;
    if (trailingWidget == null) return titleWidget;
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Expanded(child: titleWidget),
        const SizedBox(width: AppTokens.space12),
        trailingWidget,
      ],
    );
  }
}
