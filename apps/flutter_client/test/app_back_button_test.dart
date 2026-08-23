import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/shared/widgets/app_back_button.dart';

void main() {
  testWidgets('AppBackButton uses app locale and pops exactly one route', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        builder: (context, child) => AppStringsScope(
          strings: AppStrings.fromCode('zh-Hans'),
          child: child!,
        ),
        home: Scaffold(
          body: Builder(
            builder: (context) => Center(
              child: FilledButton(
                onPressed: () => Navigator.of(context).push<void>(
                  MaterialPageRoute<void>(
                    builder: (_) => Scaffold(
                      appBar: AppBar(
                        leading: const AppBackButton(
                          key: Key('localized-back'),
                        ),
                        title: const Text('二级页面'),
                      ),
                    ),
                  ),
                ),
                child: const Text('打开'),
              ),
            ),
          ),
        ),
      ),
    );

    await tester.tap(find.text('打开'));
    await tester.pumpAndSettle();
    expect(find.byTooltip('返回'), findsOneWidget);

    await tester.tap(find.byKey(const Key('localized-back')));
    await tester.pumpAndSettle();
    expect(find.text('二级页面'), findsNothing);
    expect(find.text('打开'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
