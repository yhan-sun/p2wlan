import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/core/api/control_api.dart';
import 'package:p2wlan_flutter_client/features/settings/username_settings.dart';

void main() {
  testWidgets('parent rebuild preserves an unsaved username', (tester) async {
    final rebuild = ValueNotifier(0);
    addTearDown(rebuild.dispose);
    final api = _ProfileApi();
    addTearDown(api.close);
    await tester.pumpWidget(
      _testApp(
        ValueListenableBuilder<int>(
          valueListenable: rebuild,
          builder: (context, value, child) => UsernameSettings(
            server: 'https://example.com',
            token: 'demo-token',
            username: 'Original',
            controlApi: api,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'Unsaved draft');
    rebuild.value += 1;
    await tester.pump();
    expect(_text(tester), 'Unsaved draft');
    expect(api.saves, 0);
  });

  testWidgets('shared controller keeps the draft across category remounts', (
    tester,
  ) async {
    final controller = UsernameSettingsController(username: 'Original');
    addTearDown(controller.dispose);
    final api = _ProfileApi();
    addTearDown(api.close);
    Widget editor() => _testApp(
      UsernameSettings(
        server: 'https://example.com',
        token: 'demo-token',
        username: 'Original',
        controller: controller,
        controlApi: api,
      ),
    );
    await tester.pumpWidget(editor());
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'Unsaved draft');
    expect(controller.isDirty, isTrue);
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pumpWidget(editor());
    await tester.pumpAndSettle();
    expect(_text(tester), 'Unsaved draft');
    expect(controller.isDirty, isTrue);
    await tester.tap(find.text('Save username'));
    await tester.pumpAndSettle();
    expect(api.username, 'Unsaved draft');
    expect(controller.isDirty, isFalse);
    expect(api.saves, 1);
  });

  testWidgets('failed username save keeps the draft dirty for retry', (
    tester,
  ) async {
    final controller = UsernameSettingsController(username: 'Original');
    addTearDown(controller.dispose);
    final api = _ProfileApi()
      ..saveError = const ControlApiException('Username is unavailable');
    addTearDown(api.close);
    await tester.pumpWidget(
      _testApp(
        UsernameSettings(
          server: 'https://example.com',
          token: 'demo-token',
          username: 'Original',
          controller: controller,
          controlApi: api,
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'Unsaved draft');
    await tester.tap(find.text('Save username'));
    await tester.pumpAndSettle();
    expect(_text(tester), 'Unsaved draft');
    expect(controller.isDirty, isTrue);
    expect(api.username, 'Original');
    api.saveError = null;
    await tester.tap(find.text('Save username'));
    await tester.pumpAndSettle();
    expect(controller.isDirty, isFalse);
    expect(api.username, 'Unsaved draft');
  });

  testWidgets('new account clears its predecessor draft and ignores old save', (
    tester,
  ) async {
    final controller = UsernameSettingsController(username: 'Original');
    addTearDown(controller.dispose);
    final api = _ProfileApi();
    addTearDown(api.close);
    final savedProfiles = <String>[];
    Widget editor(String token, String username) => _testApp(
      UsernameSettings(
        server: 'https://example.com',
        token: token,
        username: username,
        controller: controller,
        controlApi: api,
        onProfileLoaded: (profile) => savedProfiles.add(profile.username),
      ),
    );
    await tester.pumpWidget(editor('old-account', 'Original'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'Old account draft');
    api.pendingSave = Completer<AccountProfile>();
    await tester.tap(find.text('Save username'));
    await tester.pump();
    api.username = 'Other account';
    await tester.pumpWidget(editor('new-account', 'Other account'));
    await tester.pumpAndSettle();
    expect(_text(tester), 'Other account');
    expect(controller.isDirty, isFalse);
    api.pendingSave!.complete(
      const AccountProfile(email: '', username: 'Old account draft'),
    );
    await tester.pumpAndSettle();
    expect(_text(tester), 'Other account');
    expect(savedProfiles, isNot(contains('Old account draft')));
    expect(controller.isDirty, isFalse);
  });
}

String _text(WidgetTester tester) =>
    tester.widget<TextField>(find.byType(TextField)).controller!.text;

Widget _testApp(Widget child) => MaterialApp(
  home: AppStringsScope(
    strings: AppStrings.fromCode('en'),
    child: Scaffold(body: child),
  ),
);

class _ProfileApi extends ControlApi {
  String username = 'Original';
  Object? saveError;
  Completer<AccountProfile>? pendingSave;
  int saves = 0;

  @override
  Future<AccountProfile> accountProfile({
    required String controlServer,
    required String authToken,
    String? username,
  }) async {
    if (username != null) {
      saves += 1;
      if (saveError != null) throw saveError!;
      if (pendingSave != null) return pendingSave!.future;
      this.username = username.trim();
    }
    return AccountProfile(email: '', username: this.username);
  }
}
