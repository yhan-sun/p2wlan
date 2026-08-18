import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import '../app/app_constants.dart';
import '../app/app_strings.dart';
import '../app/app_tokens.dart';
import '../app/p2wlan_colors.dart';
import '../core/capabilities/platform_capabilities.dart';
import '../core/state/settings_store.dart';
import '../core/state/status_store.dart';
import '../features/dashboard/dashboard_page.dart';
import '../features/diagnostics/diagnostics_page.dart';
import '../features/nodes/nodes_page.dart';
import '../features/settings/settings_page.dart';
import '../features/tunnels/tunnels_page.dart';
import '../shared/layout/app_breakpoints.dart';
import '../shared/widgets/status_badge.dart';

enum P2WlanSection {
  dashboard(Icons.dashboard_outlined),
  nodes(Icons.hub_outlined),
  tunnels(Icons.cable_outlined),
  diagnostics(Icons.monitor_heart_outlined),
  settings(Icons.settings_outlined);

  const P2WlanSection(this.icon);

  final IconData icon;
}

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
  var _section = P2WlanSection.dashboard;

  /// Compact phones: "More" is a hub listing diagnostics/settings instead of
  /// a fifth bottom tab. Rail layouts never open the hub.
  var _showMoreHub = false;

  @override
  void initState() {
    super.initState();
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
        // Phones get a four-item bottom bar; tablets and desktop (even when
        // squeezed below the compact width) keep a rail so the navigation
        // never suddenly morphs into a phone layout.
        final useBottomNav =
            breakpoint == AppBreakpoint.compact && !_isDesktopShell;
        // The More hub is meaningful only while the bottom bar is actually
        // shown. If the viewport grows to a rail layout, derive it away so
        // the current business section renders instead — no setState needed
        // on viewport change.
        final showMoreHub = useBottomNav && _showMoreHub;
        final body = _buildBody(showMoreHub);
        final dragWindowFromAppBar = _canDragWindowFromAppBar;
        final macosChrome = _usesMacosChrome;
        final windowsChrome = _usesWindowsChrome;

        return Scaffold(
          appBar: AppBar(
            leading: macosChrome ? const SizedBox.shrink() : null,
            leadingWidth: macosChrome ? 76 : null,
            title: Text(_appBarTitle(strings, showMoreHub)),
            centerTitle: true,
            flexibleSpace: dragWindowFromAppBar
                ? const DragToMoveArea(child: SizedBox.expand())
                : null,
            actions: [
              _ShellStatusActions(statusStore: widget.statusStore),
              if (_showsInAppCloseButton) const _WindowsCloseButton(),
              SizedBox(width: windowsChrome ? 148 : 8),
            ],
          ),
          body: useBottomNav
              ? body
              : Row(
                  children: [
                    _buildRail(breakpoint, strings),
                    const VerticalDivider(width: 1),
                    Expanded(child: body),
                  ],
                ),
          bottomNavigationBar: useBottomNav
              ? _buildBottomNav(strings, showMoreHub)
              : null,
        );
      },
    );
  }

  void _handleSettingsChanged() {
    if (mounted) {
      setState(() {});
    }
  }

  Widget _buildBody(bool showMoreHub) {
    if (showMoreHub) {
      return _MoreHub(onOpenSection: _openFromMoreHub);
    }
    return switch (_section) {
      P2WlanSection.dashboard => DashboardPage(
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
        showHeader: false,
      ),
      P2WlanSection.nodes => NodesPage(
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
        showHeader: false,
      ),
      P2WlanSection.tunnels => TunnelsPage(
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
        showHeader: false,
      ),
      P2WlanSection.diagnostics => DiagnosticsPage(
        statusStore: widget.statusStore,
        capabilities: widget.capabilities,
        showHeader: false,
      ),
      P2WlanSection.settings => SettingsPage(
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
        onLogout: widget.onLogout,
        showHeader: false,
      ),
    };
  }

  String _appBarTitle(AppStrings strings, bool showMoreHub) {
    if (showMoreHub) return strings.more;
    return strings.sectionLabel(_section.name);
  }

  void _select(P2WlanSection section) {
    if (_section != section || _showMoreHub) {
      setState(() {
        _section = section;
        _showMoreHub = false;
      });
    }
  }

  void _openFromMoreHub(P2WlanSection section) {
    setState(() {
      _section = section;
      _showMoreHub = false;
    });
  }

  int _bottomNavIndex(bool showMoreHub) {
    if (showMoreHub) return 3;
    return switch (_section) {
      P2WlanSection.dashboard => 0,
      P2WlanSection.nodes => 1,
      P2WlanSection.tunnels => 2,
      P2WlanSection.diagnostics => 3,
      P2WlanSection.settings => 3,
    };
  }

  void _onBottomNavSelected(int index) {
    if (index == 3) {
      if (!_showMoreHub) setState(() => _showMoreHub = true);
      return;
    }
    _select(P2WlanSection.values[index]);
  }

  Widget _buildRail(AppBreakpoint breakpoint, AppStrings strings) {
    if (breakpoint == AppBreakpoint.expanded) {
      return _GroupedNavRail(
        selected: _section,
        strings: strings,
        onSelect: _select,
      );
    }
    // Medium, or desktop windows squeezed below the compact width: a plain
    // rail. Narrow desktop windows get an icon-only rail instead of the
    // phone bottom bar.
    final iconOnly = breakpoint == AppBreakpoint.compact;
    return NavigationRail(
      selectedIndex: _section.index,
      onDestinationSelected: (index) => _select(P2WlanSection.values[index]),
      labelType: iconOnly
          ? NavigationRailLabelType.none
          : NavigationRailLabelType.all,
      minWidth: iconOnly ? 64 : 88,
      destinations: [
        for (final item in P2WlanSection.values)
          NavigationRailDestination(
            icon: MouseRegion(
              cursor: SystemMouseCursors.click,
              child: Icon(item.icon),
            ),
            label: Text(strings.sectionLabel(item.name)),
          ),
      ],
    );
  }

  Widget _buildBottomNav(AppStrings strings, bool showMoreHub) {
    return NavigationBar(
      selectedIndex: _bottomNavIndex(showMoreHub),
      onDestinationSelected: _onBottomNavSelected,
      destinations: [
        _bottomDestination(strings.dashboard, P2WlanSection.dashboard.icon),
        _bottomDestination(strings.nodes, P2WlanSection.nodes.icon),
        _bottomDestination(strings.tunnels, P2WlanSection.tunnels.icon),
        NavigationDestination(
          icon: MouseRegion(
            cursor: SystemMouseCursors.click,
            child: const Icon(Icons.more_horiz_rounded),
          ),
          label: strings.more,
        ),
      ],
    );
  }

  NavigationDestination _bottomDestination(String label, IconData icon) {
    return NavigationDestination(
      icon: MouseRegion(cursor: SystemMouseCursors.click, child: Icon(icon)),
      label: label,
    );
  }
}

bool get _isDesktopShell =>
    !kIsWeb &&
    (defaultTargetPlatform == TargetPlatform.macOS ||
        defaultTargetPlatform == TargetPlatform.windows ||
        defaultTargetPlatform == TargetPlatform.linux);

bool get _usesMacosChrome => !kIsWeb && Platform.isMacOS;

bool get _usesWindowsChrome => false;

bool get _canDragWindowFromAppBar {
  return !kIsWeb && (Platform.isMacOS || Platform.isWindows);
}

bool get _showsInAppCloseButton => !kIsWeb && Platform.isWindows;

/// Compact phones only: a hub for low-frequency sections (diagnostics,
/// settings) instead of a crowded five-item bottom bar.
class _MoreHub extends StatelessWidget {
  const _MoreHub({required this.onOpenSection});

  final ValueChanged<P2WlanSection> onOpenSection;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    return SafeArea(
      child: ListView(
        padding: const EdgeInsets.only(top: 10, bottom: 16),
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(18, 4, 18, 10),
            child: Text(
              strings.moreDescription,
              style: TextStyle(
                fontSize: 13,
                height: 1.4,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
          _MoreEntry(
            icon: P2WlanSection.diagnostics.icon,
            title: strings.diagnostics,
            subtitle: strings.diagnosticsSubtitle,
            onTap: () => onOpenSection(P2WlanSection.diagnostics),
          ),
          const Divider(height: 1, indent: 18, endIndent: 18),
          _MoreEntry(
            icon: P2WlanSection.settings.icon,
            title: strings.settings,
            subtitle: strings.settingsSubtitle,
            onTap: () => onOpenSection(P2WlanSection.settings),
          ),
        ],
      ),
    );
  }
}

class _MoreEntry extends StatelessWidget {
  const _MoreEntry({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ListTile(
      onTap: onTap,
      leading: Icon(icon, color: theme.colorScheme.onSurfaceVariant),
      title: Text(
        title,
        style: TextStyle(
          fontSize: 14,
          fontWeight: FontWeight.w600,
          color: theme.colorScheme.onSurface,
        ),
      ),
      subtitle: Text(
        subtitle,
        style: TextStyle(
          fontSize: 12,
          height: 1.3,
          color: theme.colorScheme.onSurfaceVariant,
        ),
      ),
      trailing: Icon(
        Icons.chevron_right_rounded,
        size: 20,
        color: theme.colorScheme.onSurfaceVariant,
      ),
      contentPadding: const EdgeInsets.symmetric(horizontal: 18),
    );
  }
}

/// Expanded desktop: a real side navigation with brand header and visual
/// grouping. Secondary (tool) sections are visually separated instead of
/// flattened into one five-item list.
class _GroupedNavRail extends StatelessWidget {
  const _GroupedNavRail({
    required this.selected,
    required this.strings,
    required this.onSelect,
  });

  final P2WlanSection selected;
  final AppStrings strings;
  final ValueChanged<P2WlanSection> onSelect;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final railColor =
        theme.navigationRailTheme.backgroundColor ?? theme.colorScheme.surface;
    return Container(
      width: 208,
      color: railColor,
      child: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const _RailBrandHeader(),
            Divider(height: 1),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.symmetric(vertical: 8),
                children: [
                  _RailGroupLabel(strings.navGroupOverview),
                  _RailItem(
                    icon: P2WlanSection.dashboard.icon,
                    label: strings.dashboard,
                    selected: selected == P2WlanSection.dashboard,
                    onTap: () => onSelect(P2WlanSection.dashboard),
                  ),
                  _RailItem(
                    icon: P2WlanSection.nodes.icon,
                    label: strings.nodes,
                    selected: selected == P2WlanSection.nodes,
                    onTap: () => onSelect(P2WlanSection.nodes),
                  ),
                  _RailGroupLabel(strings.navGroupNetwork),
                  _RailItem(
                    icon: P2WlanSection.tunnels.icon,
                    label: strings.tunnels,
                    selected: selected == P2WlanSection.tunnels,
                    onTap: () => onSelect(P2WlanSection.tunnels),
                  ),
                  _RailGroupLabel(strings.navGroupTools),
                  _RailItem(
                    icon: P2WlanSection.diagnostics.icon,
                    label: strings.diagnostics,
                    selected: selected == P2WlanSection.diagnostics,
                    onTap: () => onSelect(P2WlanSection.diagnostics),
                  ),
                  _RailItem(
                    icon: P2WlanSection.settings.icon,
                    label: strings.settings,
                    selected: selected == P2WlanSection.settings,
                    onTap: () => onSelect(P2WlanSection.settings),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _RailBrandHeader extends StatelessWidget {
  const _RailBrandHeader();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 12),
      child: Row(
        children: [
          Container(
            width: 28,
            height: 28,
            decoration: BoxDecoration(
              color: theme.colorScheme.primary,
              borderRadius: BorderRadius.circular(AppTokens.radiusSm + 1),
            ),
            child: Icon(
              Icons.hub_outlined,
              size: 17,
              color: theme.colorScheme.onPrimary,
            ),
          ),
          const SizedBox(width: AppTokens.space10),
          Text(
            p2wlanAppName,
            style: TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.w700,
              letterSpacing: 0,
              color: theme.colorScheme.onSurface,
            ),
          ),
        ],
      ),
    );
  }
}

class _RailGroupLabel extends StatelessWidget {
  const _RailGroupLabel(this.label);

  final String label;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(20, 14, 20, 6),
      child: Text(
        label,
        style: TextStyle(
          fontSize: 11,
          fontWeight: FontWeight.w600,
          letterSpacing: 0.4,
          color: Theme.of(context).colorScheme.onSurfaceVariant,
        ),
      ),
    );
  }
}

class _RailItem extends StatelessWidget {
  const _RailItem({
    required this.icon,
    required this.label,
    required this.selected,
    required this.onTap,
  });

  final IconData icon;
  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final foreground = selected
        ? theme.colorScheme.primary
        : theme.colorScheme.onSurfaceVariant;
    final indicatorColor =
        theme.navigationRailTheme.indicatorColor ?? theme.colorScheme.surface;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 1.5),
      child: Material(
        color: selected ? indicatorColor : Colors.transparent,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(AppTokens.radiusMd),
          hoverColor: selected ? null : P2WlanColors.of(context).hoverSurface,
          child: Padding(
            padding: const EdgeInsets.symmetric(
              horizontal: AppTokens.space10,
              vertical: AppTokens.space8,
            ),
            child: Row(
              children: [
                Icon(icon, size: 20, color: foreground),
                const SizedBox(width: AppTokens.space10),
                Expanded(
                  child: Text(
                    label,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      fontSize: 13,
                      fontWeight: selected ? FontWeight.w600 : FontWeight.w500,
                      color: foreground,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _WindowsCloseButton extends StatelessWidget {
  const _WindowsCloseButton();

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return IconButton(
      tooltip: strings.closeWindow,
      onPressed: () => unawaited(_destroyWindow()),
      icon: const Icon(Icons.close_rounded),
    );
  }
}

Future<void> _destroyWindow() async {
  await windowManager.setPreventClose(false);
  await windowManager.destroy();
}

class _ShellStatusActions extends StatelessWidget {
  const _ShellStatusActions({required this.statusStore});

  final StatusStore statusStore;

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
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8),
              child: Center(
                child: StatusBadge(label: label, tone: tone),
              ),
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
