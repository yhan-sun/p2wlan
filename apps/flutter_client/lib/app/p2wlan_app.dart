import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';

import '../app/desktop_tray_controller.dart';
import '../app/desktop_window_status_controller.dart';
import '../app/app_strings.dart';
import '../app/app_theme.dart';
import '../app/p2wlan_colors.dart';
import '../core/api/diagnostics_api.dart';
import '../core/capabilities/platform_capabilities.dart';
import '../core/daemon/daemon_controller.dart';
import '../core/models/diagnostics_models.dart';
import '../core/state/settings_store.dart';
import '../core/state/status_store.dart';
import '../features/auth/login_page.dart';
import '../features/onboarding/onboarding_page.dart';
import 'app_constants.dart';
import 'navigation.dart';

class P2WlanApp extends StatefulWidget {
  const P2WlanApp({
    super.key,
    this.initialRefresh = true,
    this.autoStartPolling = true,
    this.settingsStore,
    this.diagnosticsApi,
    this.daemonController,
    this.enableDesktopTray = false,
    this.enableDesktopTaskbarStatus = false,
  });

  final bool initialRefresh;
  final bool autoStartPolling;
  final SettingsStore? settingsStore;
  final DiagnosticsApi? diagnosticsApi;
  final DaemonController? daemonController;
  final bool enableDesktopTray;
  final bool enableDesktopTaskbarStatus;

  @override
  State<P2WlanApp> createState() => _P2WlanAppState();
}

class _P2WlanAppState extends State<P2WlanApp> with WidgetsBindingObserver {
  late final SettingsStore _settingsStore;
  late final StatusStore _statusStore;
  DesktopTrayController? _desktopTrayController;
  DesktopWindowStatusController? _desktopWindowStatusController;
  var _ready = false;
  var _authenticated = false;

  @override
  void initState() {
    super.initState();
    _settingsStore = widget.settingsStore ?? SettingsStore();
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
    WidgetsBinding.instance.addObserver(this);
    _bootstrap();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    _statusStore.updateAppLifecycleState(state);
  }

  Future<void> _bootstrap() async {
    await _settingsStore.load();
    final authToken = _settingsStore.settings.authToken.trim();
    _authenticated =
        _settingsStore.settings.manualMode ||
        (authToken.isNotEmpty && !isAuthTokenExpired(authToken));
    if (mounted) {
      setState(() => _ready = true);
    }
    if (widget.enableDesktopTray && DesktopTrayController.isSupported) {
      _desktopTrayController = DesktopTrayController(
        settingsStore: _settingsStore,
        statusStore: _statusStore,
      );
      unawaited(_desktopTrayController!.initialize());
    } else if (widget.enableDesktopTaskbarStatus &&
        DesktopWindowStatusController.isSupported) {
      _desktopWindowStatusController = DesktopWindowStatusController(
        statusStore: _statusStore,
      );
      unawaited(_desktopWindowStatusController!.initialize());
    }
    // Mobile/web builds are remote-management clients. They do not ship a
    // local diagnostics daemon, so polling the desktop default
    // 127.0.0.1:39277 would manufacture a "local service unavailable" state
    // on every Android/iOS launch.
    final canPollLocalDaemon = _capabilities.canActAsLocalVpnNode;
    if (widget.autoStartPolling && canPollLocalDaemon) {
      _statusStore.startPolling();
    } else if (widget.initialRefresh && canPollLocalDaemon) {
      unawaited(_statusStore.refreshUntilPeerCatalogSettled(silent: true));
    }
  }

  Future<void> _logout() async {
    final settings = _settingsStore.settings;
    await _settingsStore.updateSettings(
      settings.copyWith(authToken: '', manualMode: false),
    );
    await _statusStore.refresh();
    if (mounted) {
      setState(() {
        _authenticated = false;
      });
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    unawaited(_desktopTrayController?.dispose());
    _desktopWindowStatusController?.dispose();
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
        return MaterialApp(
          title: p2wlanAppName,
          debugShowCheckedModeBanner: false,
          theme: AppTheme.lightTheme,
          darkTheme: AppTheme.darkTheme,
          themeMode: themeMode,
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
                          onCompleted: () {
                            if (mounted) setState(() {});
                          },
                        )
                      : P2WlanShell(
                          settingsStore: _settingsStore,
                          statusStore: _statusStore,
                          capabilities: _capabilities,
                          onLogout: _logout,
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
      body: Center(
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
    );
  }
}
