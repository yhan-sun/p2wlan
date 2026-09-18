part of '../p15_widget_test.dart';

void _registerUpdateCheckerTests() {
  testWidgets(
    'Settings shows an available client update and opens its release',
    (tester) async {
      Uri? launched;
      final service = UpdateService(
        currentAppVersion: '0.1.163',
        transport: _WidgetUpdateTransport(_widgetRelease('v0.1.164')),
        launcher: (uri) async {
          launched = uri;
          return true;
        },
      );
      await _pumpSettings(
        tester,
        api: _FakeDiagnosticsApi(health: false),
        updateService: service,
      );

      await _openCategory(tester, 'Diagnostics & About');
      await tester.tap(find.byKey(const Key('settings-check-for-updates')));
      await tester.pumpAndSettle();

      expect(find.text('Current version'), findsOneWidget);
      expect(find.text('0.1.163'), findsAtLeastNWidgets(1));
      expect(find.text('Latest version'), findsOneWidget);
      expect(find.text('v0.1.164'), findsAtLeastNWidgets(1));
      expect(find.byKey(const Key('settings-view-update')), findsOneWidget);

      await tester.tap(find.byKey(const Key('settings-view-update')));
      await tester.pump();
      expect(launched.toString(), _widgetReleaseUrl('v0.1.164'));
    },
  );

  testWidgets('Settings reports a manual update check failure', (tester) async {
    final service = UpdateService(
      currentAppVersion: '0.1.163',
      transport: _WidgetUpdateTransport.throws(
        const UpdateTransportException(
          UpdateTransportErrorCode.timeout,
          'timed out',
        ),
      ),
    );
    await _pumpSettings(
      tester,
      api: _FakeDiagnosticsApi(health: false),
      updateService: service,
    );

    await _openCategory(tester, 'Diagnostics & About');
    await tester.tap(find.byKey(const Key('settings-check-for-updates')));
    await tester.pumpAndSettle();

    expect(find.text('Could not check for updates'), findsAtLeastNWidgets(1));
    expect(find.text('Current version'), findsOneWidget);
    expect(find.byKey(const Key('settings-view-update')), findsNothing);
  });
}

class _WidgetUpdateTransport implements UpdateHttpTransport {
  _WidgetUpdateTransport(this.response) : error = null;

  _WidgetUpdateTransport.throws(this.error) : response = null;

  final UpdateHttpResponse? response;
  final UpdateTransportException? error;

  @override
  Future<UpdateHttpResponse> get(
    Uri uri, {
    required Map<String, String> headers,
    required Duration timeout,
    required int maxResponseBytes,
  }) async {
    final error = this.error;
    if (error != null) throw error;
    return response!;
  }
}

UpdateHttpResponse _widgetRelease(String tag) {
  return UpdateHttpResponse(
    statusCode: 200,
    body: utf8.encode(
      jsonEncode({'tag_name': tag, 'html_url': _widgetReleaseUrl(tag)}),
    ),
  );
}

String _widgetReleaseUrl(String tag) =>
    'https://github.com/yhan-sun/p2wlan/releases/tag/$tag';
