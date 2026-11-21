import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/wake_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/features/wake/wake_dialog.dart';
import 'package:p2wlan_flutter_client/features/wake/wake_strings.dart';

const _agentA = WakeAgent('agent-a', 'Agent A');
const _agentB = WakeAgent('agent-b', 'Agent B');
const _target = WakeTarget.device('target', 'Target');
const _strings = WakeStrings(false);

class _Settings extends SettingsStore {
  final remembered = <String, String>{};
  AppSettings current = const AppSettings(
    controlServer: 'https://example.com',
    authToken: 'test-session',
  );

  @override
  AppSettings get settings => current;

  @override
  String? wakeAgent(String targetId) => remembered[targetId];

  @override
  Future<void> rememberWakeAgent(String targetId, String agentId) async {
    remembered[targetId] = agentId;
  }

  void signOut() {
    current = current.copyWith(authToken: '');
    notifyListeners();
  }
}

class _Api implements WakeApi {
  _Api(this.current);

  WakeStatus current;
  WakeJob result = const WakeJob('job', WakeJobState.sent, '');
  final sentTo = <String?>[];
  String? acceptedAgentId;
  bool closed = false;
  int statusCalls = 0;

  @override
  Future<WakeStatus> status(WakeTarget target) async {
    statusCalls++;
    return current;
  }

  @override
  Future<WakeJob> trigger(WakeTarget target, {String? agentId}) async {
    sentTo.add(agentId);
    return WakeJob('job', WakeJobState.queued, '', agentId: acceptedAgentId);
  }

  @override
  Future<WakeJob> job(String id) async => result;

  @override
  void close() => closed = true;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

WakeStatus _status({
  bool online = false,
  bool hasMac = true,
  List<WakeAgent> agents = const [],
}) => WakeStatus(online: online, hasMac: hasMac, agents: agents);

Future<void> _open(
  WidgetTester tester,
  _Settings settings,
  _Api api, {
  WakeStrings strings = _strings,
  WakeTarget target = _target,
}) async {
  await tester.pumpWidget(
    MaterialApp(
      home: WakeDialog(
        settingsStore: settings,
        strings: strings,
        target: target,
        api: api,
      ),
    ),
  );
  await tester.pump();
}

Future<void> _close(WidgetTester tester) => tester.pumpWidget(const SizedBox());

void main() {
  for (final zh in [false, true]) {
    final strings = WakeStrings(zh);
    for (final status in [
      _status(online: true, hasMac: false),
      _status(agents: [_agentA]),
      _status(hasMac: false, agents: [_agentA]),
      _status(),
    ]) {
      testWidgets('shows ${status.availability.name} with zh=$zh', (
        tester,
      ) async {
        final settings = _Settings();
        addTearDown(settings.dispose);
        await _open(tester, settings, _Api(status), strings: strings);
        expect(
          find.text(strings.availability(status.availability)),
          findsOneWidget,
        );
        expect(
          find.text(strings.confirm),
          status.availability == WakeAvailability.ready
              ? findsOneWidget
              : findsNothing,
        );
        await _close(tester);
      });
    }
  }

  testWidgets('multi-agent choice persists and sent waits for online', (
    tester,
  ) async {
    final settings = _Settings();
    addTearDown(settings.dispose);
    final api = _Api(_status(agents: [_agentA, _agentB]));
    await _open(tester, settings, api);
    await tester.tap(find.text(_strings.confirm));
    await tester.pumpAndSettle();
    expect(find.text(_strings.chooseAgent), findsOneWidget);
    expect(find.text(_strings.sameLan), findsWidgets);
    await tester.tap(find.text(_agentB.name));
    await tester.pumpAndSettle();
    expect(api.sentTo, [_agentB.id]);
    expect(settings.remembered[_target.id], _agentB.id);
    await tester.pump(const Duration(seconds: 3));
    expect(find.text(_strings.waitingOnline), findsOneWidget);
    expect(
      find.text(_strings.availability(WakeAvailability.online)),
      findsNothing,
    );
    api.current = _status(online: true);
    await tester.pump(const Duration(seconds: 3));
    expect(
      find.text(_strings.availability(WakeAvailability.online)),
      findsOneWidget,
    );
    await _close(tester);

    final reopened = _Api(_status(agents: [_agentA, _agentB]));
    await _open(tester, settings, reopened);
    await tester.tap(find.text(_strings.confirm));
    await tester.pump();
    expect(reopened.sentTo, [_agentB.id]);
    await _close(tester);
  });

  testWidgets('dedup shows and remembers the assigned agent', (tester) async {
    final settings = _Settings();
    addTearDown(settings.dispose);
    settings.remembered[_target.id] = _agentA.id;
    final api = _Api(_status(agents: [_agentA, _agentB]))
      ..acceptedAgentId = _agentB.id;
    await _open(tester, settings, api);
    await tester.tap(find.text(_strings.confirm));
    await tester.pump();
    expect(api.sentTo, [_agentA.id]);
    expect(find.text(_strings.assignedAgent(_agentB.name)), findsOneWidget);
    expect(find.text(_strings.existingJob), findsOneWidget);
    expect(settings.remembered[_target.id], _agentB.id);
    await _close(tester);
  });

  for (final zh in [false, true]) {
    testWidgets('stops online polling after 120 seconds, zh=$zh', (
      tester,
    ) async {
      final strings = WakeStrings(zh);
      final settings = _Settings();
      addTearDown(settings.dispose);
      final api = _Api(_status(agents: [_agentA]));
      await _open(tester, settings, api, strings: strings);
      await tester.tap(find.text(strings.confirm));
      await tester.pump();
      await tester.pump(const Duration(seconds: 3));
      expect(find.text(strings.waitingOnline), findsOneWidget);
      await tester.pump(const Duration(seconds: 117));
      expect(find.text(strings.timedOut), findsOneWidget);
      final polls = api.statusCalls;
      await tester.pump(const Duration(seconds: 9));
      expect(api.statusCalls, polls);
      await _close(tester);
    });
  }

  testWidgets('manual target reports packet sent and ends polling', (
    tester,
  ) async {
    final settings = _Settings();
    addTearDown(settings.dispose);
    final api = _Api(_status(agents: [_agentA]));
    await _open(
      tester,
      settings,
      api,
      target: const WakeTarget.manual('manual', 'Target', true),
    );
    await tester.tap(find.text(_strings.confirm));
    await tester.pump();
    await tester.pump(const Duration(seconds: 3));
    expect(find.text(_strings.manualSent), findsOneWidget);
    expect(api.statusCalls, 1);
    expect(
      find.text(_strings.availability(WakeAvailability.online)),
      findsNothing,
    );
    await _close(tester);
  });

  testWidgets('sign-out closes the owned API and cancels polling', (
    tester,
  ) async {
    final settings = _Settings();
    addTearDown(settings.dispose);
    final api = _Api(_status(agents: [_agentA]));
    await _open(tester, settings, api);
    await tester.tap(find.text(_strings.confirm));
    await tester.pump();
    settings.signOut();
    await tester.pump(const Duration(seconds: 120));
    expect(api.closed, isTrue);
    expect(api.statusCalls, 1);
    expect(find.text(_strings.error('auth_expired')), findsOneWidget);
    await _close(tester);
  });
}
