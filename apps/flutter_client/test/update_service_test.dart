import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/update/update_models.dart';
import 'package:p2wlan_flutter_client/core/update/update_service.dart';

void main() {
  group('ClientReleaseVersion', () {
    test('compares numeric components instead of strings', () {
      final older = ClientReleaseVersion.tryParseTag('v0.1.9');
      final newer = ClientReleaseVersion.tryParseTag('v0.1.10');

      expect(older, isNotNull);
      expect(newer, isNotNull);
      expect(newer!.compareTo(older!), greaterThan(0));
    });

    test('accepts only client release tags', () {
      expect(ClientReleaseVersion.tryParseTag('v0.1.164'), isNotNull);
      expect(ClientReleaseVersion.tryParseTag('server-v0.1.163'), isNull);
      expect(ClientReleaseVersion.tryParseTag('release-0.1.164'), isNull);
      expect(ClientReleaseVersion.tryParseTag(' v0.1.164 '), isNull);
    });
  });

  group('UpdateService', () {
    test('reports a newer client release', () async {
      final transport = _FakeTransport(_release('v0.1.164'));
      final result = await _service(transport).check();

      expect(result.status, UpdateCheckStatus.updateAvailable);
      expect(result.currentAppVersion, '0.1.163');
      expect(result.update!.version.tag, 'v0.1.164');
      expect(result.update!.releaseUrl.toString(), _releaseUrl('v0.1.164'));
    });

    test('reports the current release as up to date', () async {
      final result = await _service(_FakeTransport(_release('v0.1.164')))
          .check(appVersion: '0.1.164');

      expect(result.status, UpdateCheckStatus.upToDate);
    });

    test('reports an already newer current release as up to date', () async {
      final result = await _service(_FakeTransport(_release('v0.1.164')))
          .check(appVersion: '0.1.165');

      expect(result.status, UpdateCheckStatus.upToDate);
    });

    test(
      'does not query the network for an unstamped development build',
      () async {
        final transport = _FakeTransport(_release('v0.1.164'));
        final result = await _service(transport).check(appVersion: 'unknown');

        expect(result.status, UpdateCheckStatus.developmentBuild);
        expect(transport.calls, 0);
      },
    );

    test('ignores a server release tag', () async {
      final result = await _service(_FakeTransport(_release('server-v0.1.200')))
          .check();

      expect(result.status, UpdateCheckStatus.invalidRelease);
      expect(result.error!.code, UpdateCheckErrorCode.invalidTag);
      expect(result.update, isNull);
    });

    test('rejects a malformed release tag', () async {
      final result = await _service(_FakeTransport(_release('v0.1.164-beta')))
          .check();

      expect(result.status, UpdateCheckStatus.invalidRelease);
      expect(result.error!.code, UpdateCheckErrorCode.invalidTag);
    });

    test('classifies a timeout as a network error', () async {
      final result = await _service(
        _FakeTransport.throws(
          const UpdateTransportException(
            UpdateTransportErrorCode.timeout,
            'timed out',
          ),
        ),
      ).check();

      expect(result.status, UpdateCheckStatus.networkError);
      expect(result.error!.code, UpdateCheckErrorCode.timeout);
    });

    test('classifies a non-success HTTP status as a network error', () async {
      final result = await _service(
        _FakeTransport(const UpdateHttpResponse(statusCode: 500, body: [])),
      ).check();

      expect(result.status, UpdateCheckStatus.networkError);
      expect(result.error!.code, UpdateCheckErrorCode.httpStatus);
      expect(result.error!.statusCode, 500);
    });

    test('rejects a response over the bounded body limit', () async {
      final result = await _service(
        _FakeTransport(
          UpdateHttpResponse(
            statusCode: 200,
            body: List<int>.filled(UpdateService.maxResponseBytes + 1, 32),
          ),
        ),
      ).check();

      expect(result.status, UpdateCheckStatus.networkError);
      expect(result.error!.code, UpdateCheckErrorCode.responseTooLarge);
    });

    test('rejects an invalid release URL and never opens it', () async {
      final transport = _FakeTransport(
        _release('v0.1.164', htmlUrl: 'https://example.com/releases/v0.1.164'),
      );
      var launched = false;
      final service = _service(
        transport,
        launcher: (_) async {
          launched = true;
          return true;
        },
      );
      final result = await service.check();

      expect(result.status, UpdateCheckStatus.invalidRelease);
      expect(result.error!.code, UpdateCheckErrorCode.invalidUrl);
      expect(result.update, isNull);
      expect(launched, isFalse);
    });

    test('opens only the validated client release URL', () async {
      Uri? launched;
      final service = _service(
        _FakeTransport(_release('v0.1.164')),
        launcher: (uri) async {
          launched = uri;
          return true;
        },
      );
      final result = await service.check();

      expect(await service.openRelease(result.update!), isTrue);
      expect(launched.toString(), _releaseUrl('v0.1.164'));
    });

    test('revalidates a forged release URL before opening', () async {
      var launched = false;
      final service = UpdateService(
        transport: _FakeTransport(_release('v0.1.164')),
        launcher: (_) async {
          launched = true;
          return true;
        },
      );

      final forged = UpdateInfo(
        version: ClientReleaseVersion.tryParseTag('v0.1.164')!,
        releaseUrl: Uri.parse('https://example.com/not-p2wlan'),
      );

      expect(await service.openRelease(forged), isFalse);
      expect(launched, isFalse);
    });

    test('sends only fixed GitHub request headers', () async {
      final transport = _FakeTransport(_release('v0.1.164'));
      await _service(transport).check();

      expect(transport.uri, UpdateService.latestReleaseUri);
      expect(transport.headers, {
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'P2WLAN/0.1.163',
      });
      expect(transport.timeout, UpdateService.requestTimeout);
      expect(transport.maxResponseBytes, UpdateService.maxResponseBytes);
    });
  });
}

UpdateService _service(
  UpdateHttpTransport transport, {
  UpdateUrlLauncher? launcher,
}) {
  return UpdateService(
    transport: transport,
    launcher: launcher,
    currentAppVersion: '0.1.163',
  );
}

UpdateHttpResponse _release(String tag, {String? htmlUrl}) {
  return UpdateHttpResponse(
    statusCode: 200,
    body: utf8.encode(
      jsonEncode({
        'tag_name': tag,
        'html_url': htmlUrl ?? _releaseUrl(tag),
        'name': 'P2WLAN $tag',
        'published_at': '2026-09-18T00:00:00Z',
      }),
    ),
  );
}

String _releaseUrl(String tag) =>
    'https://github.com/yhan-sun/p2wlan/releases/tag/$tag';

class _FakeTransport implements UpdateHttpTransport {
  _FakeTransport(this.response) : error = null;

  _FakeTransport.throws(this.error) : response = null;

  final UpdateHttpResponse? response;
  final UpdateTransportException? error;
  var calls = 0;
  Uri? uri;
  Map<String, String>? headers;
  Duration? timeout;
  int? maxResponseBytes;

  @override
  Future<UpdateHttpResponse> get(
    Uri uri, {
    required Map<String, String> headers,
    required Duration timeout,
    required int maxResponseBytes,
  }) async {
    calls += 1;
    this.uri = uri;
    this.headers = headers;
    this.timeout = timeout;
    this.maxResponseBytes = maxResponseBytes;
    final error = this.error;
    if (error != null) throw error;
    return response!;
  }
}
