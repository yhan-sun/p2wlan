import 'package:flutter/material.dart';

import '../app/app_motion.dart';
import '../app/app_strings.dart';
import '../app/app_theme.dart';
import '../app/app_tokens.dart';
import '../core/api/daemon_api.dart';
import '../core/state/settings_store.dart';
import '../core/state/status_store.dart';
import 'app_constants.dart';
import 'navigation.dart';

class P2WlanApp extends StatefulWidget {
  const P2WlanApp({
    super.key,
    this.initialRefresh = true,
    this.autoStartPolling = false,
    this.settingsStore,
    this.daemonApi,
  });

  final bool initialRefresh;
  final bool autoStartPolling;
  final SettingsStore? settingsStore;
  final DaemonApi? daemonApi;

  @override
  State<P2WlanApp> createState() => _P2WlanAppState();
}

class _P2WlanAppState extends State<P2WlanApp> {
  late final SettingsStore _settingsStore;
  late final StatusStore _statusStore;
  var _ready = false;

  @override
  void initState() {
    super.initState();
    _settingsStore = widget.settingsStore ?? SettingsStore();
    _statusStore = StatusStore(
      settingsStore: _settingsStore,
      daemonApi: widget.daemonApi ?? DaemonApi(),
    );
    _bootstrap();
  }

  Future<void> _bootstrap() async {
    await _settingsStore.load();
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

  @override
  void dispose() {
    _statusStore.dispose();
    _settingsStore.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: p2wlanAppName,
      debugShowCheckedModeBanner: false,
      theme: AppTheme.lightTheme,
      home: AnimatedBuilder(
        animation: _settingsStore,
        builder: (context, _) {
          final strings = AppStrings.fromCode(
            _settingsStore.settings.languageCode,
          );
          return AppStringsScope(
            strings: strings,
            child: Builder(
              builder: (context) {
                final duration = AppMotion.duration(
                  context,
                  AppTokens.durationMedium,
                );
                return AnimatedSwitcher(
                  duration: duration,
                  switchInCurve: AppTokens.curveEase,
                  switchOutCurve: AppTokens.curveEase,
                  child: _ready
                      ? P2WlanShell(
                          key: const ValueKey('app-shell'),
                          settingsStore: _settingsStore,
                          statusStore: _statusStore,
                        )
                      : const _BootScreen(key: ValueKey('boot-screen')),
                );
              },
            ),
          );
        },
      ),
    );
  }
}

class _BootScreen extends StatelessWidget {
  const _BootScreen({super.key});

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
