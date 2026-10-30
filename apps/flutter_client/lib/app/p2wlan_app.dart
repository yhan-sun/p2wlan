import 'package:p2wlan_flutter_client/shared/widgets/app_notice.dart';

import 'dart:async';
import 'dart:io' show Platform;
import 'dart:ui' show AppExitResponse;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import '../app/desktop_tray_controller.dart';
import '../app/desktop_window_status_controller.dart';
import '../app/app_strings.dart';
import '../app/app_theme.dart';
import '../app/p2wlan_colors.dart';
import '../core/api/diagnostics_api.dart';
import '../core/capabilities/platform_capabilities.dart';
import '../core/daemon/daemon_controller.dart';
import '../core/platform/windows_startup_registration.dart';
import '../core/state/settings_store.dart';
import '../core/state/status_store.dart';
import '../core/presentation/network_overview.dart';
import '../core/traffic/traffic_history_store.dart';
import '../shared/widgets/traffic_history_scope.dart';
import '../core/update/update_models.dart';
import '../core/update/update_service.dart';
import '../features/auth/login_page.dart';
import '../core/rooms/room_profiles.dart';
import '../features/onboarding/onboarding_page.dart';
import '../shared/widgets/windows_window_controls.dart';
import 'app_constants.dart';
import 'navigation.dart';

class P2WlanApp extends StatefulWidget {
  const P2WlanApp({
    super.key,
    this.initialRefresh = true,
    this.roomLinks,
    this.autoStartPolling = true,
    this.settingsStore,
    this.diagnosticsApi,
    this.daemonController,
    this.trafficHistoryStore,
    this.updateService,
    this.autoCheckForUpdates = true,
    this.enableDesktopTray = false,
    this.enableDesktopTaskbarStatus = false,
    this.connectAfterLoginStartup = false,
  });

  final bool initialRefresh;
  final Stream<Uri>? roomLinks;
  final bool autoStartPolling;
  final SettingsStore? settingsStore;
  final DiagnosticsApi? diagnosticsApi;
  final DaemonController? daemonController;

  /// The executable supplies durable storage. Embedded/test hosts default to
  /// memory-only history, avoiding implicit writes to the user's profile.
  final TrafficHistoryStore? trafficHistoryStore;
  final UpdateService? updateService;
  final bool autoCheckForUpdates;
  final bool enableDesktopTray;
  final bool enableDesktopTaskbarStatus;

  /// True only for a command line created by a P2WLAN desktop login-startup
  /// registration. Manual launches never turn on a network implicitly.
  final bool connectAfterLoginStartup;

  @override
  State<P2WlanApp> createState() => _P2WlanAppState();
}

class _P2WlanAppState extends State<P2WlanApp> with WidgetsBindingObserver {
  late final SettingsStore _settingsStore;
  late final StatusStore _statusStore;
  late final TrafficHistoryStore _trafficHistory;
  DesktopTrayController? _desktopTrayController;
  DesktopWindowStatusController? _desktopWindowStatusController;
  final _navigatorKey = GlobalKey<NavigatorState>();
  StreamSubscription<Uri>? _roomLinkSubscription;
  Uri? _pendingRoomLink;
  bool _openingRoomLink = false;
  var _ready = false;
  var _authenticated = false;
  var _reauthenticating = false;
  late final UpdateService _updateService;
  UpdateCheckResult? _automaticUpdateResult;
  var _automaticUpdateCheckStarted = false;

  @override
  void initState() {
    super.initState();
    _settingsStore = widget.settingsStore ?? SettingsStore();
    _updateService = widget.updateService ?? UpdateService();
    _statusStore = StatusStore(
      settingsStore: _settingsStore,
      diagnosticsApi: widget.diagnosticsApi ?? DiagnosticsApi(),
      daemonController: widget.daemonController,
      enableFreshnessTimer: true,
      autoRefreshInterval: StatusStore.defaultActivePollingInterval,
      startupCatalogRefreshTimeout: Platform.isWindows
          ? StatusStore.defaultWindowsStartupCatalogRefreshTimeout
          : StatusStore.defaultStartupCatalogRefreshTimeout,
      startupCatalogRefreshInterval: Platform.isWindows
          ? StatusStore.defaultWindowsStartupCatalogRefreshInterval
          : StatusStore.defaultStartupCatalogRefreshInterval,
      routeVerificationInterval: Platform.isWindows
          ? StatusStore.defaultWindowsRouteVerificationInterval
          : StatusStore.defaultRouteVerificationInterval,
    );
    _trafficHistory =
        widget.trafficHistoryStore ?? TrafficHistoryStore(persistent: false);
    _statusStore.addListener(_recordTraffic);
    _statusStore.parallelRooms.addListener(_recordTraffic);
    _settingsStore.addListener(_recordTraffic);
    _roomLinkSubscription = widget.roomLinks?.listen((uri) {
      if (uri.scheme != 'p2wlan' ||
          uri.host != 'join' ||
          uri.toString().length > 4096) {
        return;
      }
      _pendingRoomLink = uri;
      _scheduleRoomLink();
    }, onError: (Object _) {});
    WidgetsBinding.instance.addObserver(this);
    _bootstrap();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    _statusStore.updateAppLifecycleState(state);
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached) {
      unawaited(_trafficHistory.flush());
    }
  }

  void _recordTraffic() {
    if (!mounted) return;
    _trafficHistory.observe(
      settings: _settingsStore.settings,
      scopes: NetworkOverview.read(_statusStore).scopes,
    );
  }

  Future<void> _flushTrafficHistory() async {
    _recordTraffic();
    // Disk stalls must not indefinitely hold the native application exit.
    // The existing atomic history file remains intact if this budget expires.
    await _trafficHistory.flush().timeout(
      const Duration(seconds: 3),
      onTimeout: () {},
    );
  }

  @override
  Future<AppExitResponse> didRequestAppExit() async {
    await _flushTrafficHistory();
    return AppExitResponse.exit;
  }

  Future<void> _bootstrap() async {
    writeDesktopTrayLifecycleTrace('bootstrap.begin');
    await _settingsStore.load();
    if (!mounted) return;
    await _trafficHistory.load();
    if (!mounted) return;
    _recordTraffic();
    writeDesktopTrayLifecycleTrace('bootstrap.settings-loaded');
    _authenticated = _settingsStore.settings.hasAuthenticatedConnection;
    if (mounted) {
      setState(() => _ready = true);
    }
    writeDesktopTrayLifecycleTrace('bootstrap.ready');
    _scheduleAutomaticUpdateCheck();
    if (widget.enableDesktopTray && DesktopTrayController.isSupported) {
      writeDesktopTrayLifecycleTrace('bootstrap.tray-controller.begin');
      _desktopTrayController = DesktopTrayController(
        settingsStore: _settingsStore,
        statusStore: _statusStore,
        beforeQuit: _flushTrafficHistory,
      );
      writeDesktopTrayLifecycleTrace('bootstrap.tray-controller.created');
      final trayInitialization = _desktopTrayController!.initialize();
      writeDesktopTrayLifecycleTrace('bootstrap.tray-initialize.started');
      if (_isWindowsTrayNoAdapterExitTest) {
        // This is used only by the Windows release acceptance harness. It
        // enters through the same tray bootstrap and quit path as a real
        // packaged desktop app, while the harness deliberately provides no
        // virtual adapter or running daemon.
        await trayInitialization;
        writeDesktopTrayLifecycleTrace('bootstrap.tray-initialize.completed');
        final tray = _desktopTrayController;
        if (tray != null) {
          writeDesktopTrayLifecycleTrace('bootstrap.tray-quit.begin');
          await tray.quitForLifecycleTest();
          writeDesktopTrayLifecycleTrace('bootstrap.tray-quit.end');
        }
        // Do not start the normal daemon polling loop after the lifecycle
        // probe has entered the real packaged tray quit path.
        return;
      } else {
        unawaited(trayInitialization);
      }
    } else if (widget.enableDesktopTaskbarStatus &&
        DesktopWindowStatusController.isSupported) {
      _desktopWindowStatusController = DesktopWindowStatusController(
        statusStore: _statusStore,
      );
      unawaited(_desktopWindowStatusController!.initialize());
    }
    // Remote-only platforms have no local diagnostics endpoint. Android uses
    // its native VPN bridge and retains local-node polling.
    final canPollLocalDaemon = _capabilities.canActAsLocalVpnNode;
    if (widget.autoStartPolling && _authenticated) {
      await _statusStore.parallelRooms.credentialsChanged();
      unawaited(_statusStore.parallelRooms.recoverJoinedRooms());
    }
    if (widget.autoStartPolling && canPollLocalDaemon) {
      _statusStore.startPolling();
    } else if (widget.initialRefresh && canPollLocalDaemon) {
      unawaited(_statusStore.refreshUntilPeerCatalogSettled(silent: true));
    }
    if (shouldConnectAfterLoginStartup(
      wasLaunchedAtLogin: widget.connectAfterLoginStartup,
      hasValidSession: _settingsStore.settings.hasAuthenticatedConnection,
      onboardingComplete: !_needsOnboarding,
      canActAsLocalVpnNode: canPollLocalDaemon,
    )) {
      unawaited(_statusStore.startDaemon());
    }
  }

  void _scheduleAutomaticUpdateCheck() {
    if (!widget.autoCheckForUpdates || _automaticUpdateCheckStarted) return;
    _automaticUpdateCheckStarted = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) unawaited(_runAutomaticUpdateCheck());
    });
  }

  Future<void> _runAutomaticUpdateCheck() async {
    late final UpdateCheckResult result;
    try {
      result = await _updateService.check();
    } on Object {
      // Update checks are deliberately non-critical. A transport or plugin
      // failure must never escape the startup task or affect the shell.
      return;
    }
    if (!mounted || !result.hasUpdate) return;
    final latestTag = result.update!.version.tag;
    if (_automaticUpdateResult?.update?.version.tag == latestTag) return;
    setState(() => _automaticUpdateResult = result);
  }

  void _dismissAutomaticUpdate() {
    if (!mounted) return;
    setState(() => _automaticUpdateResult = null);
  }

  Future<void> _openAutomaticUpdate() async {
    final result = _automaticUpdateResult;
    final update = result?.update;
    if (update == null) return;
    final opened = await _updateService.openRelease(update);
    if (!mounted) return;
    if (opened) {
      setState(() => _automaticUpdateResult = null);
      return;
    }
    showAppNotice(
      _navigatorKey.currentState?.overlay?.context ?? context,
      content: Text(
        AppStrings.fromCode(_settingsStore.settings.languageCode)
            .updateOpenFailed,
      ),
    );
  }

  bool get _isWindowsTrayNoAdapterExitTest {
    return Platform.isWindows &&
        Platform.environment['P2WLAN_WINDOWS_TRAY_LIFECYCLE_TEST']?.trim() ==
            'no-adapter-exit';
  }

  Uri? _shellRoomLink;

  void _scheduleRoomLink() {
    if (!_ready ||
        !_authenticated ||
        _needsOnboarding ||
        _openingRoomLink ||
        _pendingRoomLink == null) {
      return;
    }
    _openingRoomLink = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      setState(() {
        _shellRoomLink = _pendingRoomLink;
        _pendingRoomLink = null;
      });
    });
  }

  void _roomInvitationHandled() {
    if (!mounted) return;
    setState(() {
      _shellRoomLink = null;
      _openingRoomLink = false;
    });
    _scheduleRoomLink();
  }

  Future<void> _logout() async {
    final settings = _settingsStore.settings;
    try {
      await _settingsStore.updateSettings(
        (isRoomNetwork(settings.networkId)
                ? personalNetworkSettings(settings)
                : settings)
            .copyWith(authToken: '', accountEmail: '', accountUsername: ''),
      );
    } on AccountSessionChangeException catch (error) {
      if (!mounted) return;
      showAppNotice(
        _navigatorKey.currentState!.overlay!.context,
        content: Text(error.message),
      );
      return;
    }
    _pendingRoomLink = null;
    _shellRoomLink = null;
    _openingRoomLink = false;
    _navigatorKey.currentState?.popUntil((route) => route.isFirst);
    if (mounted) {
      setState(() {
        _authenticated = false;
      });
    }
  }

  /// Reuse the authenticated login flow without clearing the current account
  /// first. Its settings update performs the existing session transition;
  /// cancelling the route leaves the user's account and navigation intact.
  Future<void> _reauthenticate() async {
    final navigator = _navigatorKey.currentState;
    if (_reauthenticating || navigator == null || !_authenticated) return;
    _reauthenticating = true;
    try {
      // Settings' compact category routes borrow their page state's drafts.
      // Unwind them before an account transition can replace that state.
      navigator.popUntil((route) => route.isFirst);
      await navigator.push<void>(
        MaterialPageRoute<void>(
          settings: const RouteSettings(name: '/reauthenticate'),
          fullscreenDialog: true,
          builder: (routeContext) => AppStringsScope(
            strings: AppStrings.fromCode(_settingsStore.settings.languageCode),
            child: LoginPage(
              settingsStore: _settingsStore,
              statusStore: _statusStore,
              capabilities: _capabilities,
              isReauthentication: true,
              onCancel: () => Navigator.of(routeContext).pop(),
              onAuthenticated: () => Navigator.of(routeContext).pop(),
            ),
          ),
        ),
      );
    } finally {
      _reauthenticating = false;
    }
  }

  @override
  void dispose() {
    unawaited(_roomLinkSubscription?.cancel());
    WidgetsBinding.instance.removeObserver(this);
    unawaited(_desktopTrayController?.dispose());
    _desktopWindowStatusController?.dispose();
    _statusStore.removeListener(_recordTraffic);
    _statusStore.parallelRooms.removeListener(_recordTraffic);
    _settingsStore.removeListener(_recordTraffic);
    // Normal desktop exit awaits flush in beforeQuit; other hosts still get
    // a final best-effort checkpoint when the widget is removed.
    unawaited(_trafficHistory.flush().whenComplete(_trafficHistory.dispose));
    _statusStore.dispose();
    _settingsStore.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _settingsStore,
      builder: (context, _) {
        final modeCode = _settingsStore.settings.themeMode;
        final themeMode = switch (modeCode) {
          'light' => ThemeMode.light,
          'dark' => ThemeMode.dark,
          _ => ThemeMode.system,
        };
        final strings = AppStrings.fromCode(
          _settingsStore.settings.languageCode,
        );
        _scheduleRoomLink();
        return MaterialApp(
          navigatorKey: _navigatorKey,
          title: p2wlanAppName,
          debugShowCheckedModeBanner: false,
          theme: AppTheme.lightTheme,
          darkTheme: AppTheme.darkTheme,
          themeMode: themeMode,
          builder: (context, child) {
            final content = TrafficHistoryScope(
              store: _trafficHistory,
              settings: _settingsStore.settings,
              onRefresh: _recordTraffic,
              child: child ?? const SizedBox.shrink(),
            );
            if (kIsWeb || !Platform.isWindows) return content;

            // Hidden Windows title bars still need a native resize hit area at
            // the top edge. The package frame preserves that behavior while
            // leaving the entire visible caption to Flutter.
            return Stack(
              fit: StackFit.expand,
              children: [
                VirtualWindowFrame(child: content),
                const Positioned(
                  top: 0,
                  right: 0,
                  child: WindowsWindowControls(),
                ),
              ],
            );
          },
          home: AppStringsScope(
            strings: strings,
            child: !_ready
                ? const _BootScreen()
                : _authenticated
                ? _needsOnboarding
                      ? OnboardingPage(
                          settingsStore: _settingsStore,
                          statusStore: _statusStore,
                          capabilities: _capabilities,
                          onOpenConnectionSettings: _reauthenticate,
                          onReauthenticate: _reauthenticate,
                          onCompleted: () {
                            if (mounted) setState(() {});
                          },
                        )
                      : P2WlanShell(
                          roomInvitation: _shellRoomLink,
                          onRoomInvitationHandled: _roomInvitationHandled,
                          settingsStore: _settingsStore,
                          statusStore: _statusStore,
                          capabilities: _capabilities,
                          onLogout: _logout,
                          onReauthenticate: _reauthenticate,
                          updateService: _updateService,
                          updateResult: _automaticUpdateResult,
                          onOpenUpdate: _openAutomaticUpdate,
                          onDismissUpdate: _dismissAutomaticUpdate,
                        )
                : LoginPage(
                    settingsStore: _settingsStore,
                    statusStore: _statusStore,
                    capabilities: _capabilities,
                    onAuthenticated: () {
                      if (mounted) {
                        setState(() => _authenticated = true);
                      }
                    },
                  ),
          ),
        );
      },
    );
  }

  /// Platform capability, decided once. Pages read this rather than branching
  /// on Platform.isX.
  late final PlatformCapabilities _capabilities =
      PlatformCapabilities.current();

  /// Local-node first-run flow is required when the platform can act as a VPN
  /// node and the device has not finished onboarding yet. Remote-only
  /// platforms (mobile/web) skip straight to the shell.
  bool get _needsOnboarding =>
      _capabilities.canActAsLocalVpnNode &&
      !_settingsStore.settings.onboardingCompleted;
}

class _BootScreen extends StatelessWidget {
  const _BootScreen();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(
        children: [
          if (!kIsWeb && Platform.isWindows)
            const Positioned(
              top: 0,
              left: 0,
              right: WindowsWindowControls.width,
              height: 56,
              child: DragToMoveArea(child: SizedBox.expand()),
            ),
          Center(
            child: SizedBox.square(
              dimension: 24,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                valueColor: AlwaysStoppedAnimation<Color>(
                  P2WlanColors.of(context).textMuted,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
