part of '../p15_widget_test.dart';

Future<DiagnosticsSnapshot> _loadFixtureSnapshot() async {
  final raw = await File('test/fixtures/status_connected.json').readAsString();
  return DiagnosticsSnapshot.fromJson(jsonDecode(raw) as Map<String, dynamic>);
}

DiagnosticsSnapshot _snapshotWithPeerCount(
  DiagnosticsSnapshot snapshot,
  int peerCount,
) {
  final raw = jsonDecode(jsonEncode(snapshot.raw)) as Map<String, dynamic>;
  raw['peers'] = (raw['peers'] as List<dynamic>).take(peerCount).toList();
  (raw['stats'] as Map<String, dynamic>)['total_peers'] = peerCount;
  return DiagnosticsSnapshot.fromJson(raw);
}

Future<_Stores> _makeStores({
  required DiagnosticsApi api,
  Duration startupCatalogRefreshInterval =
      StatusStore.defaultStartupCatalogRefreshInterval,
  Duration startupCatalogRefreshTimeout =
      StatusStore.defaultStartupCatalogRefreshTimeout,
}) async {
  final tempDir = await Directory.systemTemp.createTemp('p2wlan_flutter_test_');
  final settingsStore = SettingsStore(
    settingsFile: File('${tempDir.path}/settings.json'),
  );
  await settingsStore.load();
  await settingsStore.updateSettings(
    settingsStore.settings.copyWith(languageCode: AppLanguage.english.code),
  );
  final statusStore = StatusStore(
    settingsStore: settingsStore,
    diagnosticsApi: api,
    daemonController: _FakeDaemonController(api),
    autoRefreshInterval: const Duration(minutes: 5),
    startupCatalogRefreshInterval: startupCatalogRefreshInterval,
    startupCatalogRefreshTimeout: startupCatalogRefreshTimeout,
  );
  return _Stores(tempDir, settingsStore, statusStore);
}

class _Stores {
  _Stores(this.tempDir, this.settingsStore, this.statusStore);

  final Directory tempDir;
  final SettingsStore settingsStore;
  final StatusStore statusStore;

  void dispose() {
    statusStore.dispose();
    settingsStore.dispose();
    tempDir.deleteSync(recursive: true);
  }
}

class _FakeDiagnosticsApi implements DiagnosticsApi {
  _FakeDiagnosticsApi({
    required this.health,
    this.snapshot,
    this.snapshots,
    this.statusError,
  });

  final bool health;
  final DiagnosticsSnapshot? snapshot;
  final List<DiagnosticsSnapshot>? snapshots;
  final Object? statusError;
  var statusFetchCount = 0;

  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => health;

  @override
  Future<bool> requestShutdown(String diagnosticsUrl) async => true;

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async {
    statusFetchCount += 1;
    final error = statusError;
    if (error != null) throw error;
    final sequence = snapshots;
    if (sequence != null && sequence.isNotEmpty) {
      final index = statusFetchCount - 1;
      if (index < sequence.length) return sequence[index];
      return sequence.last;
    }
    final value = snapshot;
    if (value == null) {
      throw const DiagnosticsApiException('missing fixture snapshot');
    }
    return value;
  }

  @override
  void close() {}
}

class _FakeDaemonController extends DaemonController {
  _FakeDaemonController(DiagnosticsApi api) : super(diagnosticsApi: api);

  @override
  Future<DaemonCommandResult> start(AppSettings settings) async {
    return const DaemonCommandResult(ok: true, message: 'fake start');
  }

  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) async {
    return const DaemonCommandResult(ok: true, message: 'fake stop');
  }
}

class _TestApp extends StatelessWidget {
  const _TestApp({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: AppStringsScope(
        strings: AppStrings.fromCode(AppLanguage.english.code),
        child: ScaffoldMessenger(child: Scaffold(body: child)),
      ),
    );
  }
}
