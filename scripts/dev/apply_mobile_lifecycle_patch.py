from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match in {path}, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


store = Path("apps/flutter_client/lib/core/state/status_store.dart")
replace_once(
    store,
    """  void updateAppLifecycleState(AppLifecycleState state) {
    final appInForeground = state == AppLifecycleState.resumed;
    if (_appInForeground == appInForeground) return;
    _appInForeground = appInForeground;
    _schedulePolling();
    if (_autoRefreshEnabled && appInForeground) {
      unawaited(refresh(silent: true));
    }
    notifyListeners();
  }
""",
    """  void updateAppLifecycleState(AppLifecycleState state) {
    final appInForeground = state == AppLifecycleState.resumed;
    if (_appInForeground == appInForeground) return;
    _appInForeground = appInForeground;
    if (!appInForeground) {
      // A long-poll request belongs to the physical network and app epoch in
      // which it started. Invalidate it before Android/iOS suspends sockets so
      // a late Wi-Fi/cellular response cannot mutate the resumed snapshot.
      _eventLoopGeneration += 1;
    }
    _schedulePolling();
    if (_autoRefreshEnabled && appInForeground) {
      unawaited(_refreshAfterResume());
    }
    notifyListeners();
  }

  Future<void> _refreshAfterResume() async {
    // Revalidate process identity, route/path state and the peer catalog before
    // opening a new event long poll. This creates an explicit resume boundary
    // instead of carrying a pre-suspend cursor across a network hand-off.
    await refresh(silent: true);
    if (_disposed || !_autoRefreshEnabled || !_appInForeground) return;
    _ensureEventLoop();
  }
""",
)
replace_once(
    store,
    """  void _ensureEventLoop() {
    if (!enableEventPolling ||
        !_autoRefreshEnabled ||
        _disposed ||
        _snapshot == null ||
        _eventLoopFuture != null) {
""",
    """  void _ensureEventLoop() {
    if (!enableEventPolling ||
        !_autoRefreshEnabled ||
        !_appInForeground ||
        _disposed ||
        _snapshot == null ||
        _eventLoopFuture != null) {
""",
)
replace_once(
    store,
    """          if (!_disposed && _autoRefreshEnabled && _snapshot != null) {
            scheduleMicrotask(_ensureEventLoop);
          }
""",
    """          if (!_disposed &&
              _autoRefreshEnabled &&
              _appInForeground &&
              _snapshot != null) {
            scheduleMicrotask(_ensureEventLoop);
          }
""",
)
replace_once(
    store,
    """    while (!_disposed &&
        _autoRefreshEnabled &&
        generation == _eventLoopGeneration &&
""",
    """    while (!_disposed &&
        _autoRefreshEnabled &&
        _appInForeground &&
        generation == _eventLoopGeneration &&
""",
)

test = Path("apps/flutter_client/test/status_store_test.dart")
replace_once(
    test,
    "import 'package:flutter_test/flutter_test.dart';\n",
    "import 'package:flutter/widgets.dart' show AppLifecycleState;\n"
    "import 'package:flutter_test/flutter_test.dart';\n",
)

marker = """  test(
    'event poll carries process identity and resets on daemon restart',
"""
text = test.read_text(encoding="utf-8")
if text.count(marker) != 1:
    raise SystemExit(f"expected one lifecycle insertion marker, found {text.count(marker)}")
new_test = r'''  test(
    'mobile lifecycle stops background event polling and revalidates on resume',
    () async {
      final fixture = await _loadFixture();
      final api = _LifecycleDiagnosticsApi(snapshot: fixture);
      final stores = await _makeStores(api);
      addTearDown(stores.dispose);

      await stores.statusStore.refresh();
      stores.statusStore.setAutoRefresh(enabled: true);
      await _waitUntil(() => api.eventRequests.length == 1);
      final statusCountBeforePause = api.statusFetchCount;

      stores.statusStore.updateAppLifecycleState(AppLifecycleState.paused);
      expect(stores.statusStore.appInForeground, isFalse);
      api.completeEventRequest(0, fixture);
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(
        api.eventRequests,
        hasLength(1),
        reason: 'a completed pre-suspend long poll must not restart in background',
      );

      stores.statusStore.updateAppLifecycleState(AppLifecycleState.resumed);
      await _waitUntil(() => api.statusFetchCount > statusCountBeforePause);
      await _waitUntil(() => api.eventRequests.length == 2);
      expect(stores.statusStore.appInForeground, isTrue);
      expect(
        api.eventProcessIds.last,
        fixture.processId,
        reason: 'resume must rebuild the event cursor from the refreshed process',
      );

      stores.statusStore.setAutoRefresh(enabled: false);
      api.completeEventRequest(1, fixture);
    },
  );

'''
test.write_text(text.replace(marker, new_test + marker, 1), encoding="utf-8")

text = test.read_text(encoding="utf-8")
class_marker = "class _SwitchingDiagnosticsApi implements DiagnosticsApi {\n"
if text.count(class_marker) != 1:
    raise SystemExit(f"expected one diagnostics class marker, found {text.count(class_marker)}")
helper = r'''class _LifecycleDiagnosticsApi extends _SwitchingDiagnosticsApi {
  _LifecycleDiagnosticsApi({required super.snapshot});

  final eventRequests = <Completer<EventsResponse>>[];

  @override
  Future<EventsResponse> fetchEvents(
    String diagnosticsUrl, {
    int since = 0,
    int? processId,
    Duration timeout = const Duration(seconds: 30),
  }) {
    eventProcessIds.add(processId);
    eventCursors.add(since);
    final request = Completer<EventsResponse>();
    eventRequests.add(request);
    return request.future;
  }

  void completeEventRequest(int index, DiagnosticsSnapshot snapshot) {
    final request = eventRequests[index];
    if (request.isCompleted) return;
    request.complete(
      EventsResponse(
        contractVersion: 1,
        processId: snapshot.processId,
        revision: snapshot.revision,
        oldestSeq: snapshot.revision,
        resetRequired: false,
        events: const [],
      ),
    );
  }
}

'''
test.write_text(text.replace(class_marker, helper + class_marker, 1), encoding="utf-8")
