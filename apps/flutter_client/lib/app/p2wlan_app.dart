import 'dart:async';

import 'package:flutter/material.dart';

import '../app/desktop_tray_controller.dart';
import '../app/app_strings.dart';
import '../app/app_theme.dart';
import '../app/app_tokens.dart';
import '../core/api/diagnostics_api.dart';
import '../core/daemon/daemon_controller.dart';
import '../core/state/settings_store.dart';
import '../core/state/status_store.dart';
import '../features/auth/login_page.dart';
import 'app_constants.dart';
import 'navigation.dart';

class P2WlanApp extends StatefulWidget {
  const P2WlanApp({
    super.key,
    this.initialRefresh = true,
    this.autoStartPolling = false,
    this.settingsStore,
    this.diagnosticsApi,
    this.daemonController,
    this.enableDesktopTray = false,
  });

  final bool initialRefresh;
  final bool autoStartPolling;
  final SettingsStore? settingsStore;
  final DiagnosticsApi? diagnosticsApi;
  final DaemonController? daemonController;
  final bool enableDesktopTray;

  @override
  State<P2WlanApp> createState() => _P2WlanAppState();
}

class _P2WlanAppState extends State<P2WlanApp> {
  late final SettingsStore _settingsStore;
  late final StatusStore _statusStore;
  DesktopTrayController? _desktopTrayController;
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
    );
    _bootstrap();
  }

  Future<void> _bootstrap() async {
    await _settingsStore.load();
    _authenticated =
        _settingsStore.settings.authToken.trim().isNotEmpty ||
        _settingsStore.settings.manualMode;
    if (widget.enableDesktopTray && DesktopTrayController.isSupported) {
      _desktopTrayController = DesktopTrayController(
        settingsStore: _settingsStore,
        statusStore: _statusStore,
      );
      await _desktopTrayController!.initialize();
    }
    if (widget.initialRefresh) {
      await _statusStore.refresh();
    }
    if (widget.autoStartPolling) {
      _statusStore.startPolling();
    }
    if (mounted) {
      setState(() => _ready = true);
    }
  }

  Future<void> _logout() async {
    final settings = _settingsStore.settings;
    await _settingsStore.updateSettings(
      settings.copyWith(
        authToken: '',
        manualMode: false,
      ),
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
    unawaited(_desktopTrayController?.dispose());
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
                ? P2WlanShell(
                    settingsStore: _settingsStore,
                    statusStore: _statusStore,
                    onLogout: _logout,
                  )
                : LoginPage(
                    settingsStore: _settingsStore,
                    statusStore: _statusStore,
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
}

class _BootScreen extends StatelessWidget {
  const _BootScreen();

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      body: Center(
        child: SizedBox.square(
          dimension: 24,
          child: CircularProgressIndicator(
            strokeWidth: 2,
            valueColor: AlwaysStoppedAnimation<Color>(AppTokens.colorTextMuted),
          ),
        ),
      ),
    );
  }
}
