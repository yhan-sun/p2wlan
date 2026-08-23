import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_theme.dart';
import 'package:p2wlan_flutter_client/app/app_tokens.dart';
import 'package:p2wlan_flutter_client/shared/widgets/app_select.dart';

void main() {
  testWidgets('AppSelect opens a branded menu and changes its value', (
    tester,
  ) async {
    var value = 'system';
    await tester.pumpWidget(
      MaterialApp(
        theme: AppTheme.lightTheme,
        home: Scaffold(
          body: StatefulBuilder(
            builder: (context, setState) => Center(
              child: AppSelect<String>(
                key: const ValueKey('theme-select'),
                value: value,
                options: const [
                  AppSelectOption(value: 'system', label: 'System'),
                  AppSelectOption(value: 'dark', label: 'Dark'),
                ],
                onChanged: (next) => setState(() => value = next),
              ),
            ),
          ),
        ),
      ),
    );

    expect(find.byType(DropdownButton<String>), findsNothing);
    await tester.tap(
      find.descendant(
        of: find.byKey(const ValueKey('theme-select')),
        matching: find.byType(OutlinedButton),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('Dark'), findsOneWidget);

    for (final option in ['system', 'dark']) {
      final surface = tester.widget<Material>(
        find.byKey(ValueKey<Object>(('app-select-option-surface', option))),
      );
      final shape = surface.shape! as RoundedRectangleBorder;
      expect(shape.borderRadius, BorderRadius.circular(AppTokens.radiusMd));
      expect(surface.clipBehavior, Clip.antiAlias);
    }

    await tester.tap(
      find.byKey(const ValueKey<Object>(('app-select-option', 'dark'))),
    );
    await tester.pumpAndSettle();

    expect(value, 'dark');
    expect(find.byKey(const ValueKey('theme-select')), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('AppSelect uses a full-width bottom sheet on Android phones', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    var value = 'system';
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    try {
      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.lightTheme,
          darkTheme: AppTheme.darkTheme,
          themeMode: ThemeMode.dark,
          home: Scaffold(
            body: StatefulBuilder(
              builder: (context, setState) => Center(
                child: AppSelect<String>(
                  key: const ValueKey('mobile-theme-select'),
                  menuTitle: 'Theme mode',
                  expanded: true,
                  value: value,
                  options: const [
                    AppSelectOption(value: 'system', label: 'Follow system'),
                    AppSelectOption(value: 'light', label: 'Light'),
                    AppSelectOption(value: 'dark', label: 'Dark'),
                  ],
                  onChanged: (next) => setState(() => value = next),
                ),
              ),
            ),
          ),
        ),
      );

      final trigger = find.descendant(
        of: find.byKey(const ValueKey('mobile-theme-select')),
        matching: find.byType(OutlinedButton),
      );
      final semantics = tester.widget<Semantics>(
        find.ancestor(of: trigger, matching: find.byType(Semantics)).first,
      );
      expect(semantics.properties.label, 'Theme mode');
      expect(semantics.properties.value, 'Follow system');
      expect(semantics.properties.button, isTrue);
      expect(semantics.properties.onTap, isNotNull);
      semantics.properties.onTap!();
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('app-select-mobile-sheet')), findsOneWidget);
      expect(find.text('Theme mode'), findsOneWidget);
      expect(find.byType(PopupMenuItem<String>), findsNothing);

      // Android back dismisses only the transient selector first.
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('app-select-mobile-sheet')), findsNothing);
      expect(find.byKey(const ValueKey('mobile-theme-select')), findsOneWidget);

      await tester.tap(trigger);
      await tester.pumpAndSettle();
      await tester.tap(
        find.byKey(const ValueKey<Object>(('app-select-option', 'dark'))),
      );
      await tester.pumpAndSettle();

      expect(value, 'dark');
      expect(find.byKey(const Key('app-select-mobile-sheet')), findsNothing);

      // A phone remains touch-first after rotating to landscape.
      tester.view.physicalSize = const Size(844, 390);
      await tester.pump();
      await tester.tap(
        find.descendant(
          of: find.byKey(const ValueKey('mobile-theme-select')),
          matching: find.byType(OutlinedButton),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('app-select-mobile-sheet')), findsOneWidget);
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    } finally {
      debugDefaultTargetPlatformOverride = null;
    }
  });
}
