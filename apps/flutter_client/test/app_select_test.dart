import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_theme.dart';
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

    await tester.tap(
      find.byKey(const ValueKey<Object>(('app-select-option', 'dark'))),
    );
    await tester.pumpAndSettle();

    expect(value, 'dark');
    expect(find.byKey(const ValueKey('theme-select')), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
