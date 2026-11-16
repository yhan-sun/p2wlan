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
import '../shared/widgets/desktop_card.dart';
import '../shared/widgets/desktop_icon.dart';
import '../shared/widgets/status_badge.dart';

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
  var _roomsPageKey = GlobalKey<RoomsPageState>();
  (StatusStore, int)? _roomsOwner;
  DateTime? _roomsSampledAt;
  bool _roomsRefreshRequested = false;

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
    final roomsOwner = (widget.statusStore, widget.statusStore.sessionRevision);
    if (_roomsOwner != roomsOwner) {
      // Scope the refresh handle to the same owner as the page. A GlobalKey
      // reused across shell epochs would reparent the old room state.
      _roomsOwner = roomsOwner;
      _roomsPageKey = GlobalKey<RoomsPageState>();
      _roomsSampledAt = null;
      _roomsRefreshRequested = false;
    }
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

        final shellBody = _isDesktopShell
            ? _buildDesktopWorkspace(
                strings,
                useDesktopSidebar,
                shortWindow: constraints.maxHeight < 540,
              )
            : useBottomNav
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
                    ? null
                    : _buildTopBar(strings, useBottomNav, useDesktopSidebar),
                body: _isDesktopShell
                    ? shellBody
                    : Column(
                        children: [
                          ?_updateBanner(),
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
      _roomsSampledAt = null;
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
    if (_isDesktopShell && _section == P2WlanSection.interconnect) {
      _refreshRooms();
    } else if (!widget.statusStore.refreshActivityVisible) {
      widget.statusStore.refresh();
    }
  }

  Future<void> _refreshRooms() async {
    final pageKey = _roomsPageKey;
    final page = pageKey.currentState;
    if (page == null || _roomsRefreshRequested) return;
    setState(() => _roomsRefreshRequested = true);
    try {
      await page.refreshRooms();
    } finally {
      if (mounted && pageKey == _roomsPageKey) {
        setState(() => _roomsRefreshRequested = false);
      }
    }
  }

  Widget? _updateBanner() {
    final result = widget.updateResult;
    final onOpen = widget.onOpenUpdate;
    final onDismiss = widget.onDismissUpdate;
    if (result == null ||
        onOpen == null ||
        onDismiss == null ||
        !(widget.capabilities ?? PlatformCapabilities.current())
            .canOpenExternalUrls) {
      return null;
    }
    return UpdateBanner(result: result, onOpen: onOpen, onDismiss: onDismiss);
  }

  Widget _buildDesktopWorkspace(
    AppStrings strings,
    bool labeled, {
    required bool shortWindow,
  }) {
    final colors = P2WlanColors.of(context);
    final sidebarWidth = labeled
        ? DesktopSidebar.width
        : _usesMacosChrome
        ? 80.0
        : AppNavRail.compactWidth;
    final update = _updateBanner();
    return Row(
      children: [
        SizedBox(
          width: sidebarWidth,
          child: ColoredBox(
            color: colors.surfaceMuted,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // AppKit draws its real traffic lights over this reserved area.
                if (_usesMacosChrome)
                  const SizedBox(
                    key: Key('desktop-native-chrome-slot'),
                    height: 44,
                  ),
                if (_usesWindowsChrome)
                  const DragToMoveArea(child: SizedBox(height: 28)),
                Expanded(child: _buildNavigation(strings, labeled)),
              ],
            ),
          ),
        ),
        VerticalDivider(width: 1, color: DesktopCard.borderOf(context)),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildDesktopHeader(strings, shortWindow: shortWindow),
              if (update != null) _DesktopHeaderWidth(child: update),
              Expanded(child: _buildBody(showPageHeader: false)),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildDesktopHeader(AppStrings strings, {required bool shortWindow}) {
    final (title, subtitle) = switch (_section) {
      P2WlanSection.home => (
        strings.isZh ? '网络概览' : 'Network overview',
        strings.isZh
            ? '查看虚拟局域网的连接状态、设备与传输活动。'
            : 'View your virtual network, devices, and transfer activity.',
      ),
      P2WlanSection.devices => (
        strings.devices,
        strings.isZh
            ? '查看和管理当前网络中的本机与其他设备。'
            : 'View and manage this device and other devices on the network.',
      ),
      P2WlanSection.interconnect => (
        strings.sectionLabel(_section.name),
        strings.isZh
            ? '管理联机房间，以及本机与每个房间的连接。'
            : 'Manage rooms and this device’s connection to each room.',
      ),
      P2WlanSection.settings => (
        strings.settings,
        strings.isZh
            ? '管理应用偏好、账户与网络配置。'
            : 'Manage app preferences, your account, and network settings.',
      ),
      P2WlanSection.troubleshooting => (
        strings.troubleshooting,
        strings.diagnosticsSubtitle,
      ),
    };
    final colors = P2WlanColors.of(context);
    final theme = Theme.of(context);
    final rooms = _section == P2WlanSection.interconnect;
    return Padding(
      padding: EdgeInsets.only(
        top: !shortWindow
            ? AppTokens.space32
            : _usesWindowsChrome
            ? AppTokens.desktopToolbarHeight
            : AppTokens.space12,
      ),
      child: _DesktopHeaderWidth(
        child: LayoutBuilder(
          builder: (context, constraints) {
            final compact = constraints.maxWidth < 440;
            final largeText = MediaQuery.textScalerOf(context).scale(14) > 18;
            final lines = !shortWindow && (compact || largeText) ? 2 : 1;
            final heading = Padding(
              padding: const EdgeInsets.symmetric(vertical: 2),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Semantics(
                    header: true,
                    child: Text(
                      title,
                      maxLines: lines,
                      overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.headlineSmall?.copyWith(
                        color: colors.textPrimary,
                        fontSize: shortWindow
                            ? 24
                            : compact
                            ? 26
                            : 33,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 0,
                        height: 1.24,
                      ),
                    ),
                  ),
                  if (!shortWindow) ...[
                    const SizedBox(height: AppTokens.space4),
                    Text(
                      subtitle,
                      maxLines: lines,
                      overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.bodyLarge?.copyWith(
                        color: colors.textSecondary,
                      ),
                    ),
                  ],
                ],
              ),
            );
            return ConstrainedBox(
              key: const Key('desktop-page-heading'),
              constraints: BoxConstraints(minHeight: shortWindow ? 42 : 66),
              child: Row(
                children: [
                  Expanded(
                    child: _usesWindowsChrome
                        ? DragToMoveArea(child: heading)
                        : heading,
                  ),
                  const SizedBox(width: AppTokens.space12),
                  _ShellRefresh(
                    statusStore: widget.statusStore,
                    tooltip: '${strings.refresh}  ${_shortcutLabel('R')}',
                    desktop: true,
                    showSampleTime: !compact && !largeText && !shortWindow,
                    onRefresh: _refresh,
                    forRooms: rooms,
                    roomsSampledAt: _roomsSampledAt,
                    roomsRefreshing: _roomsRefreshRequested,
                  ),
                ],
              ),
            );
          },
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
    final roomsKey = _roomsPageKey;
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
        key: roomsKey,
        onRoomRefreshed: (sampledAt) {
          if (!mounted ||
              _section != P2WlanSection.interconnect ||
              roomsKey != _roomsPageKey) {
            return;
          }
          setState(() => _roomsSampledAt = sampledAt);
        },
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
        _roomsSampledAt = null;
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

class _DesktopHeaderWidth extends StatelessWidget {
  const _DesktopHeaderWidth({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) => Padding(
      padding: EdgeInsets.symmetric(
        horizontal: AppTokens.desktopPageGutter(constraints.maxWidth),
      ),
      child: Align(
        alignment: Alignment.topCenter,
        child: ConstrainedBox(
          constraints: const BoxConstraints(
            maxWidth: AppTokens.desktopPageMaxWidth,
          ),
          child: SizedBox(width: double.infinity, child: child),
        ),
      ),
    ),
  );
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
    this.desktop = false,
    this.onRefresh,
    this.forRooms = false,
    this.roomsSampledAt,
    this.roomsRefreshing = false,
  });

  final StatusStore statusStore;
  final String tooltip;
  final bool showSampleTime;
  final bool desktop;
  final VoidCallback? onRefresh;
  final bool forRooms;
  final DateTime? roomsSampledAt;
  final bool roomsRefreshing;

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: statusStore,
    builder: (context, _) {
      final colors = P2WlanColors.of(context);
      final refreshing = forRooms
          ? roomsRefreshing
          : statusStore.refreshActivityVisible;
      final refresh = IconButton(
        key: const Key('shell-refresh'),
        tooltip: tooltip,
        onPressed: refreshing ? null : onRefresh ?? statusStore.refresh,
        style: desktop
            ? IconButton.styleFrom(
                fixedSize: const Size.square(34),
                minimumSize: const Size.square(34),
                padding: EdgeInsets.zero,
                foregroundColor: colors.textPrimary,
                backgroundColor: colors.surfaceElevated,
                side: BorderSide(color: DesktopCard.borderOf(context)),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8),
                ),
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              )
            : null,
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
            : desktop
            ? DesktopIcon('refresh', size: 15, color: colors.textPrimary)
            : const Icon(Icons.refresh_rounded, size: AppTokens.iconMd),
      );
      final sampledAt = forRooms
          ? roomsSampledAt
          : statusStore.snapshot == null || statusStore.snapshotStale
          ? null
          : statusStore.lastSuccessfulStatusAt;
      if (!showSampleTime || sampledAt == null) {
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
