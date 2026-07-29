import 'package:flutter/material.dart';

import '../core/api/daemon_api.dart';
import '../core/state/settings_store.dart';
import '../core/state/status_store.dart';
import 'navigation.dart';

class P2WlanApp extends StatefulWidget {
  const P2WlanApp({
    super.key,
    this.initialRefresh = true,
    this.autoStartPolling = false,
  });

  final bool initialRefresh;
  final bool autoStartPolling;

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
    _settingsStore = SettingsStore();
    _statusStore = StatusStore(
      settingsStore: _settingsStore,
      daemonApi: DaemonApi(),
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
      title: 'P2WLAN',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF176B87),
          brightness: Brightness.light,
        ),
        visualDensity: VisualDensity.compact,
        scaffoldBackgroundColor: const Color(0xFFF6F8FA),
      ),
      home: _ready
          ? P2WlanShell(
              settingsStore: _settingsStore,
              statusStore: _statusStore,
            )
          : const _BootScreen(),
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
          dimension: 32,
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
      ),
    );
  }
}
