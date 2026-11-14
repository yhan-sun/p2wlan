import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:window_manager/window_manager.dart';

import '../app/app_strings.dart';
import '../app/app_tokens.dart';
import '../app/navigation_model.dart';
import 'session_ui_state.dart';
import '../app/p2wlan_colors.dart';
import '../core/capabilities/platform_capabilities.dart';
import '../core/models/diagnostics_models.dart';
import '../core/presentation/network_overview.dart';
import '../core/state/settings_store.dart';
import '../core/state/status_store.dart';
import '../core/update/update_models.dart';
import '../core/update/update_service.dart';
import '../features/dashboard/dashboard_page.dart';
import '../features/diagnostics/diagnostics_page.dart';
import '../features/nodes/nodes_page.dart';
import '../features/rooms/rooms_page.dart';
import '../features/settings/settings_page.dart';
import '../features/update/update_banner.dart';
import '../shared/layout/app_breakpoints.dart';
import '../shared/network_overview_presentation.dart';
import '../shared/widgets/app_nav_rail.dart';
import '../shared/widgets/app_motion.dart';
import '../shared/widgets/desktop_sidebar.dart';
import '../shared/widgets/status_badge.dart';
import '../shared/widgets/windows_window_controls.dart';

class P2WlanShell extends StatefulWidget {
  const P2WlanShell({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.onLogout,
    this.onReauthenticate,
    this.roomInvitation,
    this.onRoomInvitationHandled,
    this.capabilities,
    this.updateService,
    this.updateResult,
    this.onOpenUpdate,
    this.onDismissUpdate,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final VoidCallback? onLogout;
  final VoidCallback? onReauthenticate;
  final Uri? roomInvitation;
  final VoidCallback? onRoomInvitationHandled;

  /// Platform capability override (primarily for tests); defaults to the
  /// current runtime platform.
  final PlatformCapabilities? capabilities;
  final UpdateService? updateService;
  final UpdateCheckResult? updateResult;
  final VoidCallback? onOpenUpdate;
  final VoidCallback? onDismissUpdate;

  @override
  State<P2WlanShell> createState() => _P2WlanShellState();
}

class _P2WlanShellState extends State<P2WlanShell> {
  var _section = P2WlanSection.home;

  /// Home previews hand the selected peer to the Devices page. Keeping only
  /// the id avoids passing a stale snapshot while the list is mounting; the
  /// list resolves the newest peer and opens its own full detail surface.
  String? _pendingPeerId;
  String? _selectedRoomId;
  String? _pendingRoomDeviceId;
  P2WlanSection? _roomDeviceReturnSection;
  final _uiState = SessionUiState();

  /// Home opens a peer through the canonical Devices detail flow. Remember
  /// the originating section so dismissing that detail returns to Home rather
  /// than leaving the shell on the intermediate Devices section.
  P2WlanSection? _peerDetailsReturnSection;

  /// Last primary (bottom-bar) section, kept so the mobile bar keeps a valid
  /// selection while a secondary section (troubleshooting) is open — no fake
  /// extra destination, never an out-of-range index.
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
    _uiState.synchronize(
      widget.statusStore.sessionRevision,
      owner: widget.statusStore,
    );
    if (widget.roomInvitation != null) _section = P2WlanSection.interconnect;
    widget.settingsStore.addListener(_handleSettingsChanged);
    widget.statusStore.addListener(_handleSessionChanged);
  }

  @override
  void didUpdateWidget(covariant P2WlanShell oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.roomInvitation != null &&
        widget.roomInvitation != oldWidget.roomInvitation) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) _select(P2WlanSection.interconnect);
      });
    }
    if (oldWidget.settingsStore != widget.settingsStore) {
      oldWidget.settingsStore.removeListener(_handleSettingsChanged);
      widget.settingsStore.addListener(_handleSettingsChanged);
    }
    if (oldWidget.statusStore != widget.statusStore) {
      oldWidget.statusStore.removeListener(_handleSessionChanged);
      widget.statusStore.addListener(_handleSessionChanged);
      _handleSessionChanged();
    }
  }

  @override
  void dispose() {
    widget.settingsStore.removeListener(_handleSettingsChanged);
    widget.statusStore.removeListener(_handleSessionChanged);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    _uiState.synchronize(
      widget.statusStore.sessionRevision,
      owner: widget.statusStore,
    );
    final strings = AppStrings.fromCode(
      widget.settingsStore.settings.languageCode,
    );
    return LayoutBuilder(
      builder: (context, constraints) {
        final breakpoint = AppBreakpoints.of(constraints.maxWidth);
        // Desktop navigation is platform-aware: the smallest supported
        // desktop window still keeps the labeled sidebar, while a narrower
        // development/test surface gets the compact icon-only sidebar.
        // Non-desktop tablets keep the labeled rail until the regular expanded
        // content breakpoint.
        final useDesktopSidebar =
            breakpoint == AppBreakpoint.expanded ||
            (_isDesktopShell &&
                constraints.maxWidth >= AppBreakpoints.desktopSidebarMinWidth);
        // Phones get the four-item bottom bar; desktop windows keep desktop
        // interaction even when squeezed below the compact width.
        final useBottomNav =
            breakpoint == AppBreakpoint.compact && !_isDesktopShell;

        final shellBody = useBottomNav
            ? _buildBody(showPageHeader: false)
            : Row(
                children: [
                  _buildNavigation(strings, useDesktopSidebar),
                  const VerticalDivider(width: 1),
                  Expanded(child: _buildBody(showPageHeader: true)),
                ],
              );
        return PopScope<Object?>(
          canPop: _section == P2WlanSection.home,
          onPopInvokedWithResult: (didPop, result) {
            if (!didPop) _handleSystemBack();
          },
          child: CallbackShortcuts(
            bindings: _isDesktopShell ? _desktopBindings : const {},
            child: Focus(
              autofocus: _isDesktopShell,
              skipTraversal: true,
              child: Scaffold(
                appBar: _isDesktopShell
                    ? _buildDesktopToolbar(strings, useDesktopSidebar)
                    : _buildTopBar(strings, useBottomNav, useDesktopSidebar),
                body: Column(
                  children: [
                    if (widget.updateResult != null &&
                        (widget.capabilities ?? PlatformCapabilities.current())
                            .canOpenExternalUrls &&
                        widget.onOpenUpdate != null &&
                        widget.onDismissUpdate != null)
                      UpdateBanner(
                        result: widget.updateResult!,
                        onOpen: widget.onOpenUpdate!,
                        onDismiss: widget.onDismissUpdate!,
                      ),
                    Expanded(child: shellBody),
                  ],
                ),
                bottomNavigationBar: useBottomNav
                    ? _buildBottomNav(strings)
                    : null,
              ),
            ),
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

  void _handleSessionChanged() {
    if (!mounted ||
        !_uiState.synchronize(
          widget.statusStore.sessionRevision,
          owner: widget.statusStore,
        )) {
      return;
    }
    setState(() {
      _pendingPeerId = null;
      _pendingRoomDeviceId = null;
      _roomDeviceReturnSection = null;
      _selectedRoomId = null;
      _peerDetailsReturnSection = null;
      _settingsDirty = false;
    });
  }

  SingleActivator _desktopShortcut(LogicalKeyboardKey key) => SingleActivator(
    key,
    meta: defaultTargetPlatform == TargetPlatform.macOS,
    control: defaultTargetPlatform != TargetPlatform.macOS,
    includeRepeats: false,
  );

  static const _navigationKeys = [
    LogicalKeyboardKey.digit1,
    LogicalKeyboardKey.digit2,
    LogicalKeyboardKey.digit3,
    LogicalKeyboardKey.digit4,
  ];

  Map<ShortcutActivator, VoidCallback> get _desktopBindings => {
    for (final (index, section) in P2WlanSection.primary.indexed)
      _desktopShortcut(_navigationKeys[index]): () => _select(section),
    _desktopShortcut(LogicalKeyboardKey.keyR): _refresh,
    const SingleActivator(LogicalKeyboardKey.f5, includeRepeats: false):
        _refresh,
  };

  String _shortcutLabel(String key) =>
      defaultTargetPlatform == TargetPlatform.macOS ? '⌘$key' : 'Ctrl+$key';

  void _refresh() {
    if (!widget.statusStore.refreshActivityVisible) {
      widget.statusStore.refresh();
    }
  }

  PreferredSizeWidget _buildDesktopToolbar(
    AppStrings strings,
    bool hasLabeledSidebar,
  ) {
    final colors = P2WlanColors.of(context);
    final theme = Theme.of(context);
    return PreferredSize(
      preferredSize: const Size.fromHeight(AppTokens.desktopToolbarHeight),
      child: Material(
        color: colors.surfaceMuted,
        child: DecoratedBox(
          decoration: BoxDecoration(
            border: Border(bottom: BorderSide(color: colors.border)),
          ),
          child: Padding(
            padding: EdgeInsets.only(
              left: _usesMacosChrome ? 88 : AppTokens.space16,
              right: _usesWindowsChrome
                  ? WindowsWindowControls.width + AppTokens.space8
                  : AppTokens.space12,
            ),
            child: Row(
              children: [
                Expanded(
                  child: _DesktopTitleRegion(
                    child: hasLabeledSidebar
                        ? const SizedBox.expand()
                        : Align(
                            alignment: AlignmentDirectional.centerStart,
                            child: Text(
                              strings.appName,
                              style: theme.textTheme.labelMedium?.copyWith(
                                color: colors.textSecondary,
                              ),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                  ),
                ),
                _ShellRefresh(
                  statusStore: widget.statusStore,
                  tooltip: '${strings.refresh}  ${_shortcutLabel('R')}',
                  showSampleTime: true,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildNavigation(AppStrings strings, bool useDesktopSidebar) {
    final selected = P2WlanSection.primary.contains(_section) ? _section : null;
    final shortcuts = <P2WlanSection, String>{
      if (_isDesktopShell)
        for (final (index, section) in P2WlanSection.primary.indexed)
          section: _shortcutLabel('${index + 1}'),
    };
    if (useDesktopSidebar) {
      return DesktopSidebar(
        selected: selected,
        strings: strings,
        statusStore: widget.statusStore,
        shortcuts: shortcuts,
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
      shortcuts: shortcuts,
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
      backgroundColor: isMobileLayout
          ? null
          : Theme.of(context).scaffoldBackgroundColor,
      title: isMobileLayout
          ? Text(_appBarTitle(strings))
          : Text(
              strings.appName,
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w500,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
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
        uiState: _uiState.home,
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
        showHeader: showPageHeader,
        capabilities: widget.capabilities,
        onOpenDevices: () => _select(P2WlanSection.devices),
        onOpenPeer: _openPeerFromHome,
        onOpenTroubleshooting: () => _select(P2WlanSection.troubleshooting),
        onOpenRooms: () => _select(P2WlanSection.interconnect),
        onOpenRoom: _openRoom,
        onOpenRoomDevice: _openRoomDevice,
        onReauthenticate: widget.onReauthenticate,
      ),
      P2WlanSection.devices => NodesPage(
        uiState: _uiState.devices,
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
        showHeader: showPageHeader,
        capabilities: widget.capabilities,
        initialPeerId: _pendingPeerId,
        onInitialPeerOpened: _consumePendingPeer,
        onPeerDetailsClosed: _handlePeerDetailsClosed,
        onOpenRooms: () => _select(P2WlanSection.interconnect),
        onOpenRoom: _openRoom,
        onOpenRoomDevice: _openRoomDevice,
      ),
      P2WlanSection.troubleshooting => DiagnosticsPage(
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
        capabilities: widget.capabilities,
        showHeader: showPageHeader,
        onOpenDevices: () => _select(P2WlanSection.devices),
        onOpenSettings: () => _select(P2WlanSection.settings),
        onReauthenticate: widget.onReauthenticate,
        onOpenRooms: () => _select(P2WlanSection.interconnect),
        onOpenRoom: _openRoom,
      ),
      P2WlanSection.interconnect => RoomsPage(
        initialInvitation: widget.roomInvitation,
        initialRoomId: _selectedRoomId,
        initialDeviceId: _pendingRoomDeviceId,
        onInitialDeviceOpened: () => _pendingRoomDeviceId = null,
        onDeviceDetailsClosed: _handleRoomDeviceDetailsClosed,
        onRoomSelected: (id) => _selectedRoomId = id,
        onInvitationHandled: widget.onRoomInvitationHandled,
        onReauthenticate: widget.onReauthenticate,
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
        capabilities: widget.capabilities,
        embedded: true,
        showHeader: showPageHeader,
      ),
      P2WlanSection.settings => SettingsPage(
        settingsStore: widget.settingsStore,
        statusStore: widget.statusStore,
        controller: _settingsController,
        capabilities: widget.capabilities,
        onLogout: widget.onLogout,
        onReauthenticate: widget.onReauthenticate == null
            ? null
            : _requestReauthentication,
        onDirtyChanged: (dirty) => _settingsDirty = dirty,
        updateService: widget.updateService,
        showHeader: showPageHeader,
      ),
    };
    final identity = (
      _section,
      widget.statusStore,
      widget.statusStore.sessionRevision,
    );
    return SizedBox.expand(
      child: AppEntrance(
        key: const Key('shell-page-entrance'),
        identity: identity,
        navigation: _isDesktopShell,
        child: KeyedSubtree(key: ValueKey(identity), child: page),
      ),
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
      if (section != P2WlanSection.devices) {
        _pendingPeerId = null;
        _peerDetailsReturnSection = null;
      }
      _section = section;
      if (section != P2WlanSection.interconnect) {
        _pendingRoomDeviceId = null;
        _roomDeviceReturnSection = null;
      }
      if (P2WlanSection.mobilePrimary.contains(section)) {
        _lastPrimarySection = section;
      }
    });
  }

  void _openPeerFromHome(PeerSnapshot peer) {
    if (!mounted) return;
    setState(() {
      _pendingPeerId = peer.nodeId;
      _peerDetailsReturnSection = P2WlanSection.home;
      _section = P2WlanSection.devices;
      _lastPrimarySection = P2WlanSection.devices;
    });
  }

  void _openRoom(String roomId) {
    _pendingRoomDeviceId = null;
    _roomDeviceReturnSection = null;
    _selectedRoomId = roomId;
    _select(P2WlanSection.interconnect);
  }

  void _openRoomDevice(String roomId, String deviceId) {
    _roomDeviceReturnSection = _section;
    _selectedRoomId = roomId;
    _pendingRoomDeviceId = deviceId;
    _select(P2WlanSection.interconnect);
  }

  void _handleRoomDeviceDetailsClosed() {
    final origin = _roomDeviceReturnSection;
    _roomDeviceReturnSection = null;
    if (mounted && origin != null && _section == P2WlanSection.interconnect) {
      _doSelect(origin);
    }
  }

  Future<void> _requestReauthentication() async {
    final onReauthenticate = widget.onReauthenticate;
    if (onReauthenticate == null) return;
    if (_settingsDirty) {
      final strings = AppStringsScope.of(context);
      final discard = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: Text(strings.discardSettingsTitle),
          content: Text(strings.discardSettingsBody),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: Text(strings.continueEditing),
            ),
            FilledButton(
              onPressed: () => Navigator.of(context).pop(true),
              child: Text(strings.discardChanges),
            ),
          ],
        ),
      );
      if (!mounted || discard != true) return;
    }
    onReauthenticate();
  }

  void _consumePendingPeer() {
    if (!mounted || _pendingPeerId == null) return;
    setState(() => _pendingPeerId = null);
  }

  void _handlePeerDetailsClosed() {
    final returnSection = _peerDetailsReturnSection;
    if (!mounted || returnSection == null) return;

    // A detail dialog/route blocks the underlying shell, but keep this guard
    // so a future non-modal surface cannot unexpectedly change the section
    // after the user has navigated elsewhere.
    if (_section != P2WlanSection.devices) {
      _peerDetailsReturnSection = null;
      return;
    }
    _peerDetailsReturnSection = null;
    _doSelect(returnSection);
  }

  void _handleSystemBack() {
    // Medium-width Settings categories are in-place details, so they unwind
    // before the shell moves between primary sections. Compact mobile
    // categories are real routes and are popped by Navigator first.
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
    !kIsWeb && AppTokens.isDesktopPlatform(defaultTargetPlatform);

bool get _usesMacosChrome => !kIsWeb && Platform.isMacOS;

bool get _usesWindowsChrome => !kIsWeb && Platform.isWindows;

class _DesktopTitleRegion extends StatelessWidget {
  const _DesktopTitleRegion({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) =>
      _usesWindowsChrome ? DragToMoveArea(child: child) : child;
}

/// Compact mobile only: low-weight overflow menu in the top bar. Keeps the
/// shell quiet — the bottom bar stays at exactly four destinations and
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
      color: P2WlanColors.of(context).surfaceElevated,
      surfaceTintColor: Colors.transparent,
      shadowColor: const Color(0x240F172A),
      elevation: 10,
      clipBehavior: Clip.antiAlias,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
        side: BorderSide(color: P2WlanColors.of(context).border),
      ),
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
          enabled: !statusStore.refreshActivityVisible,
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
      animation: Listenable.merge([statusStore, statusStore.parallelRooms]),
      builder: (context, _) {
        final (tone, label, _) = networkOverviewStatus(
          strings,
          NetworkOverview.read(statusStore),
        );
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
            _ShellRefresh(statusStore: statusStore, tooltip: strings.refresh),
          ],
        );
      },
    );
  }
}

class _ShellRefresh extends StatelessWidget {
  const _ShellRefresh({
    required this.statusStore,
    required this.tooltip,
    this.showSampleTime = false,
  });

  final StatusStore statusStore;
  final String tooltip;
  final bool showSampleTime;

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: statusStore,
    builder: (context, _) {
      final refreshing = statusStore.refreshActivityVisible;
      final refresh = IconButton(
        key: const Key('shell-refresh'),
        tooltip: tooltip,
        onPressed: refreshing ? null : statusStore.refresh,
        icon: refreshing
            ? SizedBox.square(
                dimension: AppTokens.iconSm,
                child: MediaQuery.disableAnimationsOf(context)
                    ? Icon(
                        Icons.more_horiz,
                        size: AppTokens.iconSm,
                        color: P2WlanColors.of(context).progress,
                      )
                    : CircularProgressIndicator(
                        strokeWidth: 2,
                        color: P2WlanColors.of(context).progress,
                      ),
              )
            : const Icon(Icons.refresh_rounded, size: AppTokens.iconMd),
      );
      final sampledAt = statusStore.lastSuccessfulStatusAt;
      if (!showSampleTime ||
          sampledAt == null ||
          statusStore.snapshot == null ||
          statusStore.snapshotStale) {
        return refresh;
      }
      final strings = AppStringsScope.of(context);
      final time = MaterialLocalizations.of(context).formatTimeOfDay(
        TimeOfDay.fromDateTime(sampledAt.toLocal()),
        alwaysUse24HourFormat: MediaQuery.alwaysUse24HourFormatOf(context),
      );
      return Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            strings.isZh ? '更新于 $time' : 'Updated $time',
            style: Theme.of(context).textTheme.labelSmall?.copyWith(
              color: P2WlanColors.of(context).textMuted,
              fontFeatures: AppTokens.tabularFontFeatures,
            ),
          ),
          const SizedBox(width: AppTokens.space8),
          refresh,
        ],
      );
    },
  );
}
