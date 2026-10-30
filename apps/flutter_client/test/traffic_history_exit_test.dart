import 'dart:async';
import 'dart:ui' show AppExitResponse;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/p2wlan_app.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/traffic/traffic_history_store.dart';
import 'package:p2wlan_flutter_client/features/auth/login_page.dart';

void main() {
  testWidgets('normal exit awaits the pending traffic history flush', (
    tester,
  ) async {
    final history = await _pumpExitApp(tester);
    AppExitResponse? response;

    // This is the observer dispatch used by System.requestAppExit. Calling
    // exitApplication would ask the native test host to exit instead.
    final request = WidgetsBinding.instance.handleRequestAppExit();
    unawaited(request.then((value) => response = value));
    await tester.pump();
    expect(history.flushRequests, 1);
    expect(response, isNull);

    history.finishWriting();
    await tester.pump();
    expect(response, AppExitResponse.exit);
    expect(await request, AppExitResponse.exit);
    await _unmountExitApp(tester, history);
  });

  testWidgets('concurrent exit requests await the same history writer', (
    tester,
  ) async {
    final history = await _pumpExitApp(tester);
    final responses = <AppExitResponse>[];
    final first = WidgetsBinding.instance.handleRequestAppExit();
    unawaited(first.then(responses.add));
    await tester.pump();
    final second = WidgetsBinding.instance.handleRequestAppExit();
    unawaited(second.then(responses.add));
    await tester.pump();

    expect(history.flushRequests, 2);
    expect(responses, isEmpty);
    expect(history.saving, isTrue);
    history.finishWriting();
    await tester.pump();
    expect(responses, [AppExitResponse.exit, AppExitResponse.exit]);
    expect(await first, AppExitResponse.exit);
    expect(await second, AppExitResponse.exit);
    await _unmountExitApp(tester, history);
  });

  testWidgets(
    'a stalled history writer delays exit for at most three seconds',
    (tester) async {
      final history = await _pumpExitApp(tester);
      AppExitResponse? response;
      final request = WidgetsBinding.instance.handleRequestAppExit();
      unawaited(request.then((value) => response = value));
      await tester.pump();

      await tester.pump(const Duration(milliseconds: 2999));
      expect(response, isNull);
      expect(history.saving, isTrue);
      await tester.pump(const Duration(milliseconds: 1));
      expect(response, AppExitResponse.exit);
      expect(await request, AppExitResponse.exit);
      // The exit budget releases the app; it does not cancel or pretend that
      // the underlying atomic writer completed successfully.
      expect(history.saving, isTrue);
      history.finishWriting();
      await tester.pump();
      expect(history.saving, isFalse);
      expect(tester.takeException(), isNull);
      await _unmountExitApp(tester, history);
    },
  );
}

Future<_HeldHistoryStore> _pumpExitApp(WidgetTester tester) async {
  final history = _HeldHistoryStore();
  addTearDown(history.finishWriting);
  await tester.pumpWidget(
    P2WlanApp(
      settingsStore: _MemorySettingsStore(),
      diagnosticsApi: _NoDiagnosticsApi(),
      daemonController: _NoDaemonController(),
      trafficHistoryStore: history,
      initialRefresh: false,
      autoStartPolling: false,
      autoCheckForUpdates: false,
    ),
  );
  await tester.pumpAndSettle();
  expect(find.byType(LoginPage), findsOneWidget);
  expect(history.loaded, isTrue);
  return history;
}

Future<void> _unmountExitApp(
  WidgetTester tester,
  _HeldHistoryStore history,
) async {
  history.finishWriting();
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.pump();
  expect(tester.takeException(), isNull);
}

class _MemorySettingsStore extends SettingsStore {
  _MemorySettingsStore()
    : super(tokenRepository: InMemorySecureTokenRepository());

  @override
  Future<void> load() async {}
}

/// Only the app's await/timeout behavior is under test here. The real store's
/// single-writer behavior is covered by traffic_history_store_test.dart.
class _HeldHistoryStore extends TrafficHistoryStore {
  _HeldHistoryStore() : super(persistent: false);

  final _writeCompletion = Completer<void>();
  var flushRequests = 0;

  @override
  bool get saving => flushRequests > 0 && !_writeCompletion.isCompleted;

  @override
  Future<void> flush() {
    flushRequests++;
    return _writeCompletion.future;
  }

  void finishWriting() {
    if (!_writeCompletion.isCompleted) _writeCompletion.complete();
  }
}

class _NoDiagnosticsApi implements DiagnosticsApi {
  @override
  void cancelSpeedTest() {}

  @override
  void close() {}

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected diagnostics call: ${invocation.memberName}');
}

class _NoDaemonController implements DaemonController {
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected daemon call: ${invocation.memberName}');
}
