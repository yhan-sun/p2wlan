import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/app/app_theme.dart';
import 'package:p2wlan_flutter_client/app/navigation.dart';
import 'package:p2wlan_flutter_client/app/navigation_model.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/capabilities/platform_capabilities.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/features/dashboard/dashboard_page.dart';
import 'package:p2wlan_flutter_client/features/nodes/nodes_page.dart';
import 'package:p2wlan_flutter_client/features/rooms/rooms_page.dart';
import 'package:p2wlan_flutter_client/features/settings/settings_page.dart';
import 'package:p2wlan_flutter_client/shared/widgets/app_motion.dart';
import 'package:p2wlan_flutter_client/shared/widgets/desktop_sidebar.dart';

Widget _motionHost({
  required Object identity,
  required Widget child,
  bool reduceMotion = false,
}) => Directionality(
  textDirection: TextDirection.ltr,
  child: MediaQuery(
    data: MediaQueryData(disableAnimations: reduceMotion),
    child: Align(
      alignment: Alignment.topLeft,
      child: AppEntrance(identity: identity, child: child),
    ),
  ),
);

Opacity _opacity(WidgetTester tester) => tester.widget<Opacity>(
  find
      .descendant(of: find.byType(AppEntrance), matching: find.byType(Opacity))
      .first,
);

double _offset(WidgetTester tester) => tester
    .widget<Transform>(
      find
          .descendant(
            of: find.byType(AppEntrance),
            matching: find.byType(Transform),
          )
          .first,
    )
    .transform
    .storage[13];

class _Status extends StatusStore {
  _Status(SettingsStore settings)
    : super(
        settingsStore: settings,
        diagnosticsApi: DiagnosticsApi(),
        enableEventPolling: false,
      );

  int listeners = 0;
  int revision = 0;
  final _snapshot = DiagnosticsSnapshot.fromJson({
    'network_id': 'demo-network',
    'virtual_ip': '10.20.0.2',
    'health': {'status': 'healthy', 'control_connected': true},
    'peers': [],
  });

  @override
  void addListener(VoidCallback listener) {
    super.addListener(listener);
    listeners++;
  }

  @override
  void removeListener(VoidCallback listener) {
    super.removeListener(listener);
    listeners--;
  }

  @override
  DiagnosticsSnapshot get snapshot => _snapshot;
  @override
  bool get healthReachable => true;
  @override
  bool get daemonReachable => true;
  @override
  int get sessionRevision => revision;
}

class _Harness {
  _Harness(this.directory, this.settings, this.status);
  final Directory directory;
  final SettingsStore settings;
  final _Status status;

  static Future<_Harness> create() async {
    final directory = await Directory.systemTemp.createTemp('shell-motion-');
    final settings = SettingsStore(
      settingsFile: File('${directory.path}/settings.json'),
      tokenRepository: InMemorySecureTokenRepository(),
    );
    await settings.load();
    await settings.updateSettings(
      settings.settings.copyWith(
        controlServer: 'https://control.example.com',
        languageCode: 'en',
        deviceName: 'Demo device',
      ),
    );
    return _Harness(directory, settings, _Status(settings));
  }

  void dispose() {
    status.dispose();
    settings.dispose();
    directory.deleteSync(recursive: true);
  }
}

Widget _shell(_Harness harness, {bool reduceMotion = false}) => MaterialApp(
  theme: AppTheme.lightTheme,
  builder: (context, child) => MediaQuery(
    data: MediaQuery.of(context).copyWith(disableAnimations: reduceMotion),
    child: child!,
  ),
  home: AppStringsScope(
    strings: AppStrings.fromCode('en'),
    child: P2WlanShell(
      settingsStore: harness.settings,
      statusStore: harness.status,
      capabilities: PlatformCapabilities.fromPlatform('android'),
    ),
  ),
);

void _select(WidgetTester tester, P2WlanSection section) => tester
    .widget<DesktopSidebar>(find.byType(DesktopSidebar))
    .onSelect(section);

Future<void> _asDesktop(Future<void> Function() run) async {
  debugDefaultTargetPlatformOverride = TargetPlatform.linux;
  try {
    await run();
  } finally {
    debugDefaultTargetPlatformOverride = null;
  }
}

void main() {
  testWidgets('motion timing and disclosure styles honor reduced motion', (
    tester,
  ) async {
    for (final reduced in [false, true]) {
      late Duration duration;
      late Duration feedback;
      late AnimationStyle expansion;
      await tester.pumpWidget(
        MediaQuery(
          data: MediaQueryData(disableAnimations: reduced),
          child: Builder(
            builder: (context) {
              duration = AppMotion.durationOf(context);
              feedback = AppMotion.feedbackDurationOf(context);
              expansion = AppMotion.expansionStyleOf(context);
              return const SizedBox();
            },
          ),
        ),
      );
      expect(
        duration,
        reduced ? Duration.zero : const Duration(milliseconds: 180),
      );
      expect(
        feedback,
        reduced ? Duration.zero : const Duration(milliseconds: 110),
      );
      expect(expansion.duration, duration);
      expect(expansion.reverseDuration, duration);
      expect(expansion.curve, AppMotion.curve);
      expect(expansion.reverseCurve, AppMotion.curve);
    }
  });

  testWidgets(
    'entrance starts readable and preserves layout throughout its 180ms motion',
    (tester) async {
      Widget scene(String identity) => _motionHost(
        identity: identity,
        child: SizedBox(key: ValueKey(identity), width: 240, height: 80),
      );
      await tester.pumpWidget(scene('first'));
      expect(_opacity(tester).opacity, 1);
      expect(_offset(tester), 0);
      final bounds = tester.getRect(find.byType(AppEntrance));

      await tester.pumpWidget(scene('second'));
      expect(find.byKey(const ValueKey('first')), findsNothing);
      expect(find.byKey(const ValueKey('second')), findsOneWidget);
      expect(_opacity(tester).opacity, closeTo(0.85, 0.001));
      expect(_offset(tester), closeTo(4, 0.001));
      await tester.pump(const Duration(milliseconds: 90));
      expect(_opacity(tester).opacity, greaterThan(0.85));
      expect(_opacity(tester).opacity, lessThan(1));
      expect(_offset(tester), inExclusiveRange(0, 4));
      expect(tester.getRect(find.byType(AppEntrance)), bounds);
      await tester.pump(const Duration(milliseconds: 90));
      expect(_opacity(tester).opacity, 1);
      expect(_offset(tester), 0);
      expect(tester.getRect(find.byType(AppEntrance)), bounds);
    },
  );

  testWidgets('reduced motion finishes an active entrance immediately', (
    tester,
  ) async {
    Widget scene(Object identity, bool reduced) => _motionHost(
      identity: identity,
      reduceMotion: reduced,
      child: const SizedBox(width: 240, height: 80),
    );
    await tester.pumpWidget(scene(0, false));
    await tester.pumpWidget(scene(1, false));
    await tester.pump(const Duration(milliseconds: 40));
    expect(_opacity(tester).opacity, lessThan(1));
    await tester.pumpWidget(scene(1, true));
    expect(_opacity(tester).opacity, 1);
    expect(_offset(tester), 0);
    expect(tester.binding.transientCallbackCount, 0);
    await tester.pumpWidget(scene(2, true));
    expect(_opacity(tester).opacity, 1);
    expect(_offset(tester), 0);
    expect(tester.binding.transientCallbackCount, 0);
  });

  testWidgets(
    'entrance leaves child identity to its caller and fits unbounded content',
    (tester) async {
      Widget scene(Object identity) => Directionality(
        textDirection: TextDirection.ltr,
        child: MediaQuery(
          data: const MediaQueryData(),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              AppEntrance(
                identity: identity,
                child: StatefulBuilder(
                  builder: (context, setState) =>
                      const SizedBox(width: 240, height: 80),
                ),
              ),
            ],
          ),
        ),
      );
      await tester.pumpWidget(scene('first'));
      final childState = tester.state(find.byType(StatefulBuilder));
      expect(tester.getSize(find.byType(AppEntrance)), const Size(240, 80));
      await tester.pumpWidget(scene('second'));
      expect(tester.state(find.byType(StatefulBuilder)), same(childState));
      expect(tester.getSize(find.byType(AppEntrance)), const Size(240, 80));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    },
  );

  group('shell page ownership', () {
    Future<_Harness> mount(WidgetTester tester, {bool reduced = false}) async {
      await tester.binding.setSurfaceSize(const Size(800, 1000));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      final harness = (await tester.runAsync(_Harness.create))!;
      addTearDown(harness.dispose);
      await tester.pumpWidget(_shell(harness, reduceMotion: reduced));
      await tester.pump();
      return harness;
    }

    testWidgets(
      'outgoing page and its listeners leave on the first switch frame',
      (tester) => _asDesktop(() async {
        final harness = await mount(tester);
        expect(find.byType(DashboardPage), findsOneWidget);
        expect(_opacity(tester).opacity, 1);
        final bounds = tester.getRect(find.byType(AppEntrance));
        _select(tester, P2WlanSection.devices);
        await tester.pump();
        expect(find.byType(DashboardPage), findsNothing);
        expect(find.byType(NodesPage), findsOneWidget);
        expect(_opacity(tester).opacity, greaterThan(0));
        final currentListeners = harness.status.listeners;
        await tester.pump(const Duration(milliseconds: 180));
        expect(harness.status.listeners, currentListeners);
        expect(tester.getRect(find.byType(AppEntrance)), bounds);
        expect(_opacity(tester).opacity, 1);
        expect(tester.takeException(), isNull);
      }),
    );

    testWidgets(
      'rapid navigation keeps one page and cannot return focus to old search',
      (tester) => _asDesktop(() async {
        await mount(tester);
        _select(tester, P2WlanSection.devices);
        await tester.pumpAndSettle();
        final search = find.byKey(const Key('nodes-search-field'));
        await tester.tap(search);
        await tester.enterText(search, 'demo');
        final focus = tester.widget<TextField>(search).focusNode!;
        expect(focus.hasFocus, isTrue);
        _select(tester, P2WlanSection.settings);
        await tester.pump();
        expect(find.byType(NodesPage), findsNothing);
        expect(find.byType(SettingsPage), findsOneWidget);
        expect(FocusManager.instance.primaryFocus, isNot(same(focus)));
        await tester.pump(const Duration(milliseconds: 25));
        _select(tester, P2WlanSection.interconnect);
        await tester.pump();
        expect(find.byType(SettingsPage), findsNothing);
        expect(find.byType(RoomsPage), findsOneWidget);
        _select(tester, P2WlanSection.home);
        await tester.pump();
        expect(find.byType(RoomsPage), findsNothing);
        expect(find.byType(DashboardPage), findsOneWidget);
        expect(find.byType(AppEntrance), findsOneWidget);
        await tester.pumpAndSettle();
        expect(FocusManager.instance.primaryFocus, isNot(same(focus)));
        expect(tester.takeException(), isNull);
      }),
    );

    testWidgets(
      'reduced motion and session key replacement preserve one current page',
      (tester) => _asDesktop(() async {
        final harness = await mount(tester, reduced: true);
        _select(tester, P2WlanSection.devices);
        await tester.pump();
        final previous = tester.state(find.byType(NodesPage));
        expect(_opacity(tester).opacity, 1);
        expect(_offset(tester), 0);
        harness.status.revision++;
        await tester.pumpWidget(_shell(harness, reduceMotion: true));
        expect(find.byType(NodesPage), findsOneWidget);
        expect(tester.state(find.byType(NodesPage)), isNot(same(previous)));
        expect(find.byType(DashboardPage), findsNothing);
        expect(_opacity(tester).opacity, 1);
        expect(_offset(tester), 0);
        expect(tester.takeException(), isNull);
      }),
    );
    testWidgets(
      'keyboard navigation retains its navigation focus during the entrance',
      (tester) => _asDesktop(() async {
        await mount(tester);
        final label = find.descendant(
          of: find.byType(DesktopSidebar),
          matching: find.text('Settings'),
        );
        final node = Focus.of(tester.element(label));
        node.requestFocus();
        await tester.pump();
        expect(node.hasFocus, isTrue);
        await tester.sendKeyEvent(LogicalKeyboardKey.enter);
        await tester.pump();
        expect(find.byType(SettingsPage), findsOneWidget);
        expect(find.byType(DashboardPage), findsNothing);
        expect(node.hasFocus, isTrue);
        await tester.pumpAndSettle();
        expect(node.hasFocus, isTrue);
        expect(tester.takeException(), isNull);
      }),
    );
  });
}
