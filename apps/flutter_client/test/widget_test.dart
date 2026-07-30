import 'package:flutter_test/flutter_test.dart';

import 'package:p2wlan_flutter_client/app/p2wlan_app.dart';

void main() {
  testWidgets('renders the read-only console shell', (tester) async {
    await tester.pumpWidget(
      const P2WlanApp(initialRefresh: false, autoStartPolling: false),
    );
    await _waitForBootstrap(tester);

    expect(find.text('P2WLAN Diagnostics'), findsOneWidget);
    expect(find.text('Dashboard'), findsWidgets);
    expect(find.text('Offline'), findsWidgets);
  });

  testWidgets('opens settings and shows diagnostics URL field', (tester) async {
    await tester.pumpWidget(
      const P2WlanApp(initialRefresh: false, autoStartPolling: false),
    );
    await _waitForBootstrap(tester);

    await tester.tap(find.text('Settings').last);
    await tester.pump();

    expect(find.text('Diagnostics URL'), findsWidgets);
    expect(find.text('P1 boundary'), findsOneWidget);
  });
}

Future<void> _waitForBootstrap(WidgetTester tester) async {
  await tester.runAsync(() async {
    await Future<void>.delayed(const Duration(milliseconds: 50));
  });
  await tester.pump();
}
