import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import '../app/app_strings.dart';
import '../app/navigation_model.dart';
import '../app/p2wlan_colors.dart';
import '../core/capabilities/platform_capabilities.dart';
import '../core/state/settings_store.dart';
import '../core/state/status_store.dart';
import '../features/dashboard/dashboard_page.dart';
import '../features/diagnostics/diagnostics_page.dart';
import '../features/nodes/nodes_page.dart';
import '../features/settings/settings_page.dart';
import '../shared/layout/app_breakpoints.dart';
import '../shared/widgets/app_nav_rail.dart';
import '../shared/widgets/desktop_sidebar.dart';
import '../shared/widgets/status_badge.dart';

class P2WlanShell extends StatefulWidget {
  const P2WlanShell({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.onLogout,
    this.capabilities,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final VoidCallback? onLogout;

  /// Platform capability override (primarily for tests); defaults to the
  /// current runtime platform.
  final PlatformCapabilities? capabilities;

  @override
  State<P2WlanShell> createState() => _P2WlanShellState();
}

class _P2WlanShellState extends State<P2WlanShell> {
  static const _sectionFadeDuration = Duration(milliseconds: 150);

  var _section = P2WlanSection.home;

  /// Last primary (bottom-bar) section, kept so the mobile bar keeps a valid
  /// selection while a secondary section (troubleshooting) is open — no fake
  /// fourth destination, never an out-of-range index.
  var _lastPrimarySection = P2WlanSection.home;

  /// Whether the Settings page currently has unsaved drafts across any
  /// category. Set by the SettingsPage via [onDirtyChanged]; when true,
  /// navigating away from Settings prompts a discard confirmation.
  var _settingsDirty = false;
  late final SettingsPageController _settingsController;

  @override
  void initState() {
    super.initState();
    _settingsController = SettingsPageController();
    widget.settingsStore.addListener(_handleSettingsChanged);
  }

  @override
  void didUpdateWidget(covariant P2WlanShell oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.settingsStore != widget.settingsStore) {
      oldWidget.settingsStore.removeListener(_handleSettingsChanged);
      widget.settingsStore.addListener(_handleSettingsChanged);
    }
  }

  @override
  void dispose() {
    widget.settingsStore.removeListener(_handleSettingsChanged);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStrings.fromCode(
      widget.settingsStore.settings.languageCode,
    );
    return LayoutBuilder(
      builder: (context, constraints) {
        final breakpoint = AppBreakpoints.of(constraints.maxWidth);
        // Desktop navigation is platform-aware: an 860px desktop window is
        // still a desktop sidebar, while a 700px desktop window gets the
        // compact icon-only sidebar. Non-desktop tablets keep the labeled rail
        // until the regular expanded content breakpoint.
        final useDesktopSidebar =
            breakpoint == AppBreakpoint.expanded ||
            (_isDesktopShell &&
                constraints.maxWidth >= AppBreakpoints.desktopSidebarMinWidth);
        // Phones get the three-item bottom bar; desktop windows keep desktop
        // interaction even when squeezed below the compact width.
        final useBottomNav =
            breakpoint == AppBreakpoint.compact && !_isDesktopShell;

        return PopScope<Object?>(
          canPop: _section == P2WlanSection.home,
          onPopInvokedWithResult: (didPop, result) {
            if (!didPop) _handleSystemBack();
          },
          child: Scaffold(
            appBar: _buildTopBar(strings, useBottomNav, useDesktopSidebar),
            body: useBottomNav
                ? _buildBody(showPageHeader: false)
                : Row(
                    children: [
                      _buildNavigation(strings, useDesktopSidebar),
                      const VerticalDivider(width: 1),
                      Expanded(child: _buildBody(showPageHeader: true)),
                    ],
                  ),
            bottomNavigationBar: useBottomNav ? _buildBottomNav(strings) : null,
          ),
        );
      },
    );
  }

  void _handleSettingsChanged() {
    if (mounted) {
      setState(() {});
    }
  }

  Widget _buildNavigation(AppStrings strings, bool useDesktopSidebar) {
    final selected = P2WlanSection.primary.contains(_section) ? _section : null;
    if (useDesktopSidebar) {
      return DesktopSidebar(
        selected: selected,
        strings: strings,
        statusStore: widget.statusStore,
        onSelect: _select,
        onFooterTap: () => _select(P2WlanSection.troubleshooting),
      );
    }
    return AppNavRail(
      selected: selected,
      // Desktop compact windows use an icon-only sidebar. Non-desktop medium
      // layouts keep labels, but the rail renders them horizontally.
      iconOnly: _isDesktopShell,
      strings: strings,
      statusStore: widget.statusStore,
      onSelect: _select,
      onFooterTap: () => _select(P2WlanSection.troubleshooting),
    );
  }

  PreferredSizeWidget _buildTopBar(
    AppStrings strings,
    bool isMobileLayout,
    bool hasSidebarFooter,
  ) {
    // Expanded desktop: the sidebar footer already carries the network status.
    // Home: the hero itself is the strong status expression, so the top bar
    // adds no duplicate badge there either. Other sections (Devices,
    // Troubleshooting, Settings) keep the global badge on medium and compact
    // desktop because they have no footer.
    final showStatusBadge = !hasSidebarFooter && _section != P2WlanSection.home;
    return AppBar(
      leading: _usesMacosChrome ? const SizedBox.shrink() : null,
      leadingWidth: _usesMacosChrome ? 76 : null,
      title: isMobileLayout ? Text(_appBarTitle(strings)) : null,
      centerTitle: false,
      flexibleSpace: _canDragWindowFromAppBar
          ? const DragToMoveArea(child: SizedBox.expand())
          : null,
      actions: isMobileLayout
          ? [
              _MobileShellMenu(
                statusStore: widget.statusStore,
                onOpenTroubleshooting: () =>
                    _select(P2WlanSection.troubleshooting),
              ),
            ]
          : [
              _ShellStatusActions(
                statusStore: widget.statusStore,
                showStatusBadge: showStatusBadge,
                showTroubleshootingAction: !hasSidebarFooter,
                onOpenTroubleshooting: () =>
                    _select(P2WlanSection.troubleshooting),
              ),
              const SizedBox(width: 8),
            ],
    );
  }

  Widget _buildBody({required bool showPageHeader}) {
    final page = switch (_section) {
      P2WlanSection.home => DashboardPage(
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
        showHeader: false,
        capabilities: widget.capabilities,
        onOpenDevices: () => _select(P2WlanSection.devices),
        onOpenPeer: (peer) => showPeerDetailsSurface(context, peer),
        onOpenTroubleshooting: () => _select(P2WlanSection.troubleshooting),
      ),
      P2WlanSection.devices => NodesPage(
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
        showHeader: showPageHeader,
        capabilities: widget.capabilities,
      ),
      P2WlanSection.troubleshooting => DiagnosticsPage(
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
        capabilities: widget.capabilities,
        showHeader: showPageHeader,
        onOpenDevices: () => _select(P2WlanSection.devices),
        onOpenSettings: () => _select(P2WlanSection.settings),
      ),
      P2WlanSection.settings => SettingsPage(
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
        controller: _settingsController,
        capabilities: widget.capabilities,
        onLogout: widget.onLogout,
        onDirtyChanged: (dirty) => _settingsDirty = dirty,
        showHeader: showPageHeader,
      ),
    };
    return AnimatedSwitcher(
      duration: MediaQuery.disableAnimationsOf(context)
          ? Duration.zero
          : _sectionFadeDuration,
      switchInCurve: Curves.easeOut,
      switchOutCurve: Curves.easeIn,
      child: KeyedSubtree(key: ValueKey(_section), child: page),
    );
  }

  String _appBarTitle(AppStrings strings) {
    return strings.sectionLabel(_section.name);
  }

  void _select(P2WlanSection section) {
    // Leave guard: if Settings has unsaved drafts and the user is navigating
    // to a different section, confirm before discarding.
    if (_section == P2WlanSection.settings &&
        section != P2WlanSection.settings &&
        _settingsDirty) {
      _showDiscardGuard(section);
      return;
    }
    _doSelect(section);
  }

  void _doSelect(P2WlanSection section) {
    setState(() {
      _section = section;
      if (P2WlanSection.mobilePrimary.contains(section)) {
        _lastPrimarySection = section;
      }
    });
  }

  void _handleSystemBack() {
    // Settings categories are in-place details, so they unwind before the
    // shell moves between primary sections.
    if (_section == P2WlanSection.settings &&
        _settingsController.maybeGoBack()) {
      return;
    }

    // Contextual troubleshooting returns to the primary section that opened
    // it. Primary destinations return Home; only a second back on Home leaves
    // the app, matching Android's expected task behavior.
    if (_section == P2WlanSection.troubleshooting) {
      _select(_lastPrimarySection);
    } else if (_section != P2WlanSection.home) {
      _select(P2WlanSection.home);
    }
  }

  void _showDiscardGuard(P2WlanSection targetSection) {
    final strings = AppStrings.fromCode(
      widget.settingsStore.settings.languageCode,
    );
    showDialog<void>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(strings.discardSettingsTitle),
        content: Text(strings.discardSettingsBody),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text(strings.continueEditing),
          ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(context).colorScheme.error,
            ),
            onPressed: () {
              Navigator.of(context).pop();
              _settingsDirty = false;
              _doSelect(targetSection);
            },
            child: Text(strings.discardChanges),
          ),
        ],
      ),
    );
  }

  int _bottomNavIndex() {
    final index = P2WlanSection.mobilePrimary.indexOf(_section);
    if (index != -1) return index;
    // Secondary sections keep the last primary selection highlighted.
    final last = P2WlanSection.mobilePrimary.indexOf(_lastPrimarySection);
    return last == -1 ? 0 : last;
  }

  Widget _buildBottomNav(AppStrings strings) {
    return NavigationBar(
      selectedIndex: _bottomNavIndex(),
      onDestinationSelected: (index) =>
          _select(P2WlanSection.mobilePrimary[index]),
      destinations: [
        for (final item in P2WlanSection.mobilePrimary)
          NavigationDestination(
            icon: MouseRegion(
              cursor: SystemMouseCursors.click,
              child: Icon(item.icon),
            ),
            label: strings.sectionLabel(item.name),
          ),
      ],
    );
  }
}

bool get _isDesktopShell =>
    !kIsWeb &&
    (defaultTargetPlatform == TargetPlatform.macOS ||
        defaultTargetPlatform == TargetPlatform.windows ||
        defaultTargetPlatform == TargetPlatform.linux);

bool get _usesMacosChrome => !kIsWeb && Platform.isMacOS;

bool get _canDragWindowFromAppBar {
  return !kIsWeb && (Platform.isMacOS || Platform.isWindows);
}

/// Compact mobile only: low-weight overflow menu in the top bar. Keeps the
/// shell quiet — the bottom bar stays at exactly three destinations and
/// troubleshooting is entered from here and from Home's issue banner.
class _MobileShellMenu extends StatelessWidget {
  const _MobileShellMenu({
    required this.statusStore,
    required this.onOpenTroubleshooting,
  });

  final StatusStore statusStore;
  final VoidCallback onOpenTroubleshooting;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    return PopupMenuButton<_MobileMenuAction>(
      icon: const Icon(Icons.more_horiz_rounded),
      tooltip: strings.menu,
      onSelected: (action) => switch (action) {
        _MobileMenuAction.troubleshooting => onOpenTroubleshooting(),
        _MobileMenuAction.refresh => statusStore.refresh(),
      },
      itemBuilder: (context) => [
        PopupMenuItem(
          value: _MobileMenuAction.troubleshooting,
          height: 44,
          child: Row(
            children: [
              Icon(
                P2WlanSection.troubleshooting.icon,
                size: 18,
                color: theme.colorScheme.onSurfaceVariant,
              ),
              const SizedBox(width: 12),
              Text(strings.troubleshooting),
            ],
          ),
        ),
        const PopupMenuDivider(),
        PopupMenuItem(
          value: _MobileMenuAction.refresh,
          height: 44,
          enabled: !statusStore.refreshing,
          child: Row(
            children: [
              Icon(
                Icons.refresh,
                size: 18,
                color: theme.colorScheme.onSurfaceVariant,
              ),
              const SizedBox(width: 12),
              Text(strings.refresh),
            ],
          ),
        ),
      ],
    );
  }
}

enum _MobileMenuAction { troubleshooting, refresh }

class _ShellStatusActions extends StatelessWidget {
  const _ShellStatusActions({
    required this.statusStore,
    this.showStatusBadge = true,
    this.showTroubleshootingAction = false,
    this.onOpenTroubleshooting,
  });

  final StatusStore statusStore;
  final bool showStatusBadge;
  final bool showTroubleshootingAction;
  final VoidCallback? onOpenTroubleshooting;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AnimatedBuilder(
      animation: statusStore,
      builder: (context, _) {
        final label = _statusLabel(strings);
        final tone = _statusTone();
        return Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (showStatusBadge)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 8),
                child: Center(
                  child: StatusBadge(label: label, tone: tone),
                ),
              ),
            if (showTroubleshootingAction && onOpenTroubleshooting != null)
              IconButton(
                key: const Key('shell-open-troubleshooting'),
                tooltip: strings.openTroubleshooting,
                onPressed: onOpenTroubleshooting,
                icon: Icon(P2WlanSection.troubleshooting.icon),
              ),
            IconButton(
              tooltip: strings.refresh,
              onPressed: statusStore.refreshing ? null : statusStore.refresh,
              icon: statusStore.refreshing
                  ? SizedBox.square(
                      dimension: 16,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        valueColor: AlwaysStoppedAnimation<Color>(
                          P2WlanColors.of(context).textMuted,
                        ),
                      ),
                    )
                  : const Icon(Icons.refresh),
            ),
          ],
        );
      },
    );
  }

  String _statusLabel(AppStrings strings) {
    if (statusStore.daemonBusy) return strings.daemonWorking;
    if (statusStore.snapshotStale) return strings.stale;
    if (!statusStore.daemonReachable) return strings.offline;
    final health = statusStore.snapshot?.health.status;
    if (health == null || health.isEmpty) return strings.degraded;
    return strings.healthStatusLabel(health);
  }

  StatusTone _statusTone() {
    if (statusStore.snapshotStale) return StatusTone.warn;
    if (!statusStore.daemonReachable) return StatusTone.neutral;
    return switch (statusStore.snapshot?.health.status.toLowerCase()) {
      'healthy' => StatusTone.good,
      'degraded' => StatusTone.warn,
      _ => StatusTone.warn,
    };
  }
}
