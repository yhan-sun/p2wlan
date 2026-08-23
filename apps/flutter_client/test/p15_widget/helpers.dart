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
  bool enableFreshnessTimer = false,
  Duration maxSnapshotAge = StatusStore.defaultMaxSnapshotAge,
  DaemonController? daemonController,
  bool manualMode = false,
  SecureTokenRepository? tokenRepository,
}) async {
  final tempDir = await Directory.systemTemp.createTemp('p2wlan_flutter_test_');
  final repo = tokenRepository ?? InMemorySecureTokenRepository();
  final settingsStore = SettingsStore(
    settingsFile: File('${tempDir.path}/settings.json'),
    tokenRepository: repo,
  );
  await settingsStore.load();
  await settingsStore.updateSettings(
    settingsStore.settings.copyWith(
      languageCode: AppLanguage.english.code,
      manualMode: manualMode,
    ),
  );
  final statusStore = StatusStore(
    settingsStore: settingsStore,
    diagnosticsApi: api,
    daemonController: daemonController ?? _FakeDaemonController(api),
    autoRefreshInterval: const Duration(minutes: 5),
    startupCatalogRefreshInterval: startupCatalogRefreshInterval,
    startupCatalogRefreshTimeout: startupCatalogRefreshTimeout,
    enableFreshnessTimer: enableFreshnessTimer,
    maxSnapshotAge: maxSnapshotAge,
  );
  return _Stores(tempDir, settingsStore, statusStore, repo);
}

class _Stores {
  _Stores(
    this.tempDir,
    this.settingsStore,
    this.statusStore,
    this.tokenRepository,
  );

  final Directory tempDir;
  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final SecureTokenRepository tokenRepository;

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
    this.statusError,
    this.speedTestResult,
    this.speedTestError,
    this.repairRoutesError,
    RoutesResponse? routes,
    this.repairResult,
  }) : routes = routes ?? _fakeRoutes;

  bool health;
  DiagnosticsSnapshot? snapshot;
  final Object? statusError;
  final SpeedTestResult? speedTestResult;
  final Object? speedTestError;
  final Object? repairRoutesError;

  /// Route verification response (default: installed); tests swap this to
  /// exercise missing/conflict/unverified states.
  RoutesResponse routes;
  Object? verifyRoutesError;

  /// Repair response; default performs a successful in-place change.
  RouteRepairResponse? repairResult;
  var statusFetchCount = 0;
  var speedTestCount = 0;
  var verifyRoutesCount = 0;
  var repairRoutesCount = 0;

  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => health;

  @override
  Future<bool> requestShutdown(String diagnosticsUrl) async => true;

  @override
  Future<SpeedTestResult> runSpeedTest(
    String diagnosticsUrl, {
    required String peerVirtualIp,
    Duration duration = const Duration(seconds: 10),
  }) async {
    speedTestCount += 1;
    final error = speedTestError;
    if (error != null) throw error;
    return speedTestResult ??
        SpeedTestResult(
          peerVirtualIp: peerVirtualIp,
          durationMs: duration.inMilliseconds,
          downloadMbps: 123.4,
          uploadMbps: 56.7,
          downloadBytes: 154250000,
          uploadBytes: 70875000,
        );
  }

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async {
    statusFetchCount += 1;
    final error = statusError;
    if (error != null) throw error;
    final value = snapshot;
    if (value == null) {
      throw const DiagnosticsApiException('missing fixture snapshot');
    }
    return value;
  }

  @override
  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) async {
    verifyRoutesCount += 1;
    final error = verifyRoutesError;
    if (error != null) throw error;
    return routes;
  }

  @override
  Future<RouteRepairResponse> repairRoutes(String diagnosticsUrl) async {
    repairRoutesCount += 1;
    final error = repairRoutesError;
    if (error != null) throw error;
    return repairResult ?? _fakeRepair;
  }

  @override
  Future<EventsResponse> fetchEvents(
    String diagnosticsUrl, {
    int since = 0,
    Duration timeout = const Duration(seconds: 30),
  }) async => throw UnimplementedError();

  @override
  Future<PeersPageResponse> fetchPeers(
    String diagnosticsUrl, {
    String? cursor,
    int limit = 100,
  }) async => throw UnimplementedError();

  @override
  Future<String> fetchLogTail(
    String diagnosticsUrl, {
    int lines = 120,
    int maxBytes = 262144,
  }) async => throw UnimplementedError();

  @override
  void close() {}
}

const _fakeRoutes = RoutesResponse(
  contractVersion: 1,
  interfaceName: 'p2wlan0',
  mtu: 1420,
  healthy: true,
  conflictCount: 0,
  entries: [
    RouteEntryResponse(
      cidr: '10.20.0.0/16',
      expectedInterface: 'p2wlan0',
      actualInterface: 'p2wlan0',
      state: 'installed',
      owned: true,
    ),
  ],
);

const _fakeRepair = RouteRepairResponse(
  contractVersion: 1,
  cidr: '10.20.0.0/16',
  changed: true,
  attempted: true,
  before: 'missing',
  after: 'installed',
  reason: 'fixed',
  restartedDaemon: false,
);

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

class _FakeControlApi extends ControlApi {
  _FakeControlApi({this.failDelete = false});

  final bool failDelete;
  var deleteCalls = 0;

  @override
  Future<void> deleteDevice({
    required String controlServer,
    required String authToken,
    required String deviceId,
  }) async {
    deleteCalls += 1;
    if (failDelete) throw const ControlApiException('fake delete failed');
  }
}

class _TestApp extends StatelessWidget {
  const _TestApp({required this.child, this.strings});

  final Widget child;
  final AppStrings? strings;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: AppStringsScope(
        strings: strings ?? AppStrings.fromCode(AppLanguage.english.code),
        child: ScaffoldMessenger(child: Scaffold(body: child)),
      ),
    );
  }
}
