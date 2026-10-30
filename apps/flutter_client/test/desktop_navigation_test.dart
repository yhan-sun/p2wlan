import 'dart:io';
import 'dart:ui' show Tristate;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/app/app_theme.dart';
import 'package:p2wlan_flutter_client/app/navigation_model.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/shared/widgets/app_nav_rail.dart';
import 'package:p2wlan_flutter_client/shared/widgets/desktop_sidebar.dart';

class _NavigationStatusStore extends StatusStore {
  _NavigationStatusStore(SettingsStore settings)
    : super(
        settingsStore: settings,
        diagnosticsApi: DiagnosticsApi(),
        enableFreshnessTimer: false,
        enableEventPolling: false,
      );

  final _snapshot = DiagnosticsSnapshot.fromJson({
    'network_id': 'demo-network',
    'health': {'status': 'degraded'},
  });

  @override
  DiagnosticsSnapshot get snapshot => _snapshot;
  @override
  bool get daemonReachable => true;
  @override
  bool get healthReachable => true;
}

Future<(_NavigationStatusStore, VoidCallback)> _stores(
  WidgetTester tester,
) async {
  final directory = (await tester.runAsync(
    () => Directory.systemTemp.createTemp('p2wlan-navigation-test-'),
  ))!;
  final settings = SettingsStore(
    settingsFile: File('${directory.path}/settings.json'),
    tokenRepository: InMemorySecureTokenRepository(),
  );
  await tester.runAsync(settings.load);
  final status = _NavigationStatusStore(settings);
  return (
    status,
    () {
      status.dispose();
      settings.dispose();
      directory.deleteSync(recursive: true);
    },
  );
}

Widget _host(Widget child, {double textScale = 1}) => MaterialApp(
  theme: AppTheme.lightTheme,
  builder: (context, child) => MediaQuery(
    data: MediaQuery.of(context)
        .copyWith(textScaler: TextScaler.linear(textScale)),
    child: child!,
  ),
  home: Scaffold(
    appBar: AppBar(toolbarHeight: 32),
    body: Row(
      children: [
        child,
        const VerticalDivider(width: 1),
        const Expanded(child: SizedBox()),
      ],
    ),
  ),
);

Future<void> _activateWithKeyboard(WidgetTester tester, Finder target) async {
  final content = find
      .descendant(of: target, matching: find.byType(ExcludeSemantics))
      .last;
  Focus.of(tester.element(content)).requestFocus();
  await tester.pump();
  await tester.sendKeyEvent(LogicalKeyboardKey.enter);
  await tester.pump();
}

void main() {
  for (final surface in ['sidebar', 'rail-labels', 'rail-icons']) {
    testWidgets('$surface announces selection and keeps keyboard navigation', (
      tester,
    ) async {
      final handle = tester.ensureSemantics();
      try {
        final (store, dispose) = await _stores(tester);
        addTearDown(dispose);
        final strings = AppStrings.fromCode('en');
        final selected = <P2WlanSection>[];
        final navigation = surface == 'sidebar'
            ? DesktopSidebar(
                selected: P2WlanSection.devices,
                strings: strings,
                statusStore: store,
                onSelect: selected.add,
                onFooterTap: () {},
              )
            : AppNavRail(
                selected: P2WlanSection.devices,
                iconOnly: surface == 'rail-icons',
                strings: strings,
                statusStore: store,
                onSelect: selected.add,
                onFooterTap: () {},
              );
        await tester.pumpWidget(_host(navigation));
        await tester.pumpAndSettle();
        for (final section in P2WlanSection.primary) {
          final label = strings.sectionLabel(section.name);
          final item = find.bySemanticsLabel(label);
          expect(item, findsOneWidget);
          final data = tester.getSemantics(item).getSemanticsData();
          expect(data.label, label);
          expect(data.flagsCollection.isButton, isTrue);
          expect(
            data.flagsCollection.isSelected,
            section == P2WlanSection.devices
                ? Tristate.isTrue
                : Tristate.isFalse,
          );
          expect(data.hasAction(SemanticsAction.tap), isTrue);
        }
        await _activateWithKeyboard(
          tester,
          find.bySemanticsLabel(strings.settings),
        );
        expect(selected, [P2WlanSection.settings]);
        await tester.tap(find.bySemanticsLabel(strings.devices));
        expect(selected, [P2WlanSection.settings, P2WlanSection.devices]);
        expect(tester.takeException(), isNull);
      } finally {
        handle.dispose();
      }
    });
  }

  testWidgets('800px sidebar footer keeps complete status at 200 percent', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 628);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final handle = tester.ensureSemantics();
    try {
      final (store, dispose) = await _stores(tester);
      addTearDown(dispose);
      final strings = AppStrings.fromCode('en');
      var opened = false;
      Widget sidebar() => DesktopSidebar(
        selected: P2WlanSection.home,
        strings: strings,
        statusStore: store,
        onSelect: (_) {},
        onFooterTap: () => opened = true,
      );
      await tester.pumpWidget(_host(sidebar()));
      final footer = find.byKey(const Key('desktop-sidebar-status'));
      final ordinaryHeight = tester.getSize(footer).height;
      await tester.pumpWidget(_host(sidebar(), textScale: 2));
      await tester.pumpAndSettle();
      for (final label in [
        strings.home,
        strings.devices,
        strings.sectionLabel('interconnect'),
        strings.settings,
      ]) {
        final text = find.text(label);
        await tester.scrollUntilVisible(
          text,
          80,
          scrollable: find
              .descendant(
                of: find.byType(DesktopSidebar),
                matching: find.byType(Scrollable),
              )
              .first,
        );
        final paragraph = tester.renderObject<RenderParagraph>(text);
        expect(paragraph.didExceedMaxLines, isFalse, reason: label);
        expect(tester.getRect(text).right, lessThanOrEqualTo(196));
      }
      final footerRect = tester.getRect(footer);
      expect(tester.getSize(find.byType(DesktopSidebar)).width, 196);
      expect(footerRect.height, greaterThan(ordinaryHeight));
      expect(footerRect.bottom, lessThanOrEqualTo(628));
      final textWidgets = find.descendant(
        of: footer,
        matching: find.byType(Text),
      );
      expect(textWidgets, findsNWidgets(2));
      final values = <String>[];
      for (final element in textWidgets.evaluate()) {
        final text = element.widget as Text;
        values.add(text.data!);
        expect(text.maxLines, isNull);
        final paragraph = element.renderObject! as RenderParagraph;
        expect(paragraph.didExceedMaxLines, isFalse);
        final rect = tester.getRect(find.byWidget(text));
        expect(rect.top, greaterThanOrEqualTo(footerRect.top));
        expect(rect.bottom, lessThanOrEqualTo(footerRect.bottom));
      }
      final tooltip = tester.widget<Tooltip>(
        find.descendant(of: footer, matching: find.byType(Tooltip)),
      );
      expect(
        tooltip.message,
        '${values[0]}\n${values[1]}\n${strings.openTroubleshooting}',
      );
      final footerSemantics = find.bySemanticsLabel(
        '${values[0]}, ${values[1]}',
      );
      expect(footerSemantics, findsOneWidget);
      final data = tester.getSemantics(footerSemantics).getSemanticsData();
      expect(data.flagsCollection.isButton, isTrue);
      expect(data.hint, strings.openTroubleshooting);
      expect(data.hasAction(SemanticsAction.tap), isTrue);
      await _activateWithKeyboard(tester, footerSemantics);
      expect(opened, isTrue);
      expect(tester.takeException(), isNull);
    } finally {
      handle.dispose();
    }
  });
}
