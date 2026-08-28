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
    """      _eventLoopGeneration += 1;
    }
    _schedulePolling();
""",
    """      _eventLoopGeneration += 1;
      // Detach the slot immediately. The in-flight HTTP future is still
      // bounded by its request timeout, but its completion is generation-
      // fenced and `identical` will be false, so resume can start a fresh poll
      // without waiting for the suspended socket to wake up.
      _eventLoopFuture = null;
    }
    _schedulePolling();
""",
)

test = Path("apps/flutter_client/test/status_store_test.dart")
replace_once(
    test,
    """      stores.statusStore.updateAppLifecycleState(AppLifecycleState.paused);
      expect(stores.statusStore.appInForeground, isFalse);
      api.completeEventRequest(0, fixture);
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(
        api.eventRequests,
        hasLength(1),
        reason:
            'a completed pre-suspend long poll must not restart in background',
      );

      stores.statusStore.updateAppLifecycleState(AppLifecycleState.resumed);
      await _waitUntil(() => api.statusFetchCount > statusCountBeforePause);
      await _waitUntil(() => api.eventRequests.length == 2);
      expect(stores.statusStore.appInForeground, isTrue);
      expect(
        api.eventProcessIds.last,
        fixture.processId,
        reason:
            'resume must rebuild the event cursor from the refreshed process',
      );

      stores.statusStore.setAutoRefresh(enabled: false);
      api.completeEventRequest(1, fixture);
""",
    """      stores.statusStore.updateAppLifecycleState(AppLifecycleState.paused);
      expect(stores.statusStore.appInForeground, isFalse);
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(
        api.eventRequests,
        hasLength(1),
        reason: 'backgrounding must not create another long poll',
      );

      // Resume while the pre-suspend request is still pending. The new event
      // loop must not wait for that stale network future to reach its timeout.
      stores.statusStore.updateAppLifecycleState(AppLifecycleState.resumed);
      await _waitUntil(() => api.statusFetchCount > statusCountBeforePause);
      await _waitUntil(() => api.eventRequests.length == 2);
      expect(stores.statusStore.appInForeground, isTrue);
      expect(
        api.eventProcessIds.last,
        fixture.processId,
        reason:
            'resume must rebuild the event cursor from the refreshed process',
      );

      // A late completion from the suspended network epoch is ignored and
      // must not spawn a third request beside the current resumed loop.
      api.completeEventRequest(0, fixture);
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(api.eventRequests, hasLength(2));

      stores.statusStore.setAutoRefresh(enabled: false);
      api.completeEventRequest(1, fixture);
""",
)
