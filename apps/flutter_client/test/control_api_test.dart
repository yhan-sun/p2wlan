import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/control_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';

void main() {
  test('default control server matches the desktop client default', () {
    expect(defaultControlServer, 'http://47.109.40.237:18080');
  });

  test('settings load migrates the stale p2wlan.io control host', () async {
    final tempDir = await Directory.systemTemp.createTemp(
      'p2wlan_control_migration_test_',
    );
    addTearDown(() {
      if (tempDir.existsSync()) {
        tempDir.deleteSync(recursive: true);
      }
    });
    final settingsFile = File('${tempDir.path}/settings.json');
    await settingsFile.writeAsString('''
{
  "controlServer": "$legacyControlServer",
  "authToken": "",
  "manualMode": false
}
''');

    final store = SettingsStore(settingsFile: settingsFile);
    await store.load();
    addTearDown(store.dispose);

    expect(store.settings.controlServer, defaultControlServer);
  });

  test('settings load replaces ip-like default device names', () async {
    final tempDir = await Directory.systemTemp.createTemp(
      'p2wlan_device_name_migration_test_',
    );
    addTearDown(() {
      if (tempDir.existsSync()) {
        tempDir.deleteSync(recursive: true);
      }
    });
    final settingsFile = File('${tempDir.path}/settings.json');
    await settingsFile.writeAsString('''
{
  "controlServer": "$defaultControlServer",
  "authToken": "token",
  "deviceName": "192.168.2.16",
  "manualMode": false
}
''');

    final store = SettingsStore(settingsFile: settingsFile);
    await store.load();
    addTearDown(store.dispose);

    expect(store.settings.deviceName, isNot('192.168.2.16'));
    expect(store.settings.deviceName.trim(), isNotEmpty);
  });

  test(
    'authenticate wraps connection failures as user-facing errors',
    () async {
      final serverSocket = await ServerSocket.bind(
        InternetAddress.loopbackIPv4,
        0,
      );
      final port = serverSocket.port;
      await serverSocket.close();
      final api = ControlApi();
      addTearDown(api.close);

      expect(
        () => api.authenticate(
          mode: AuthMode.login,
          controlServer: 'http://127.0.0.1:$port',
          email: 'user@example.com',
          password: 'password',
        ),
        throwsA(
          isA<ControlApiException>().having(
            (error) => error.message,
            'message',
            contains('无法连接控制服务器'),
          ),
        ),
      );
    },
  );

  test('authenticate explains Windows sendto socket failures', () async {
    const socketError = SocketException(
      '由于套接字没有连接并且没有提供地址，发送或接收数据的请求没有被接受。sendto failed',
      osError: OSError('socket is not connected', 10057),
    );
    final api = ControlApi(client: _ThrowingHttpClient(socketError));
    addTearDown(api.close);

    await expectLater(
      () => api.authenticate(
        mode: AuthMode.login,
        controlServer: defaultControlServer,
        email: 'user@example.com',
        password: 'password',
      ),
      throwsA(
        isA<ControlApiException>().having(
          (error) => error.message,
          'message',
          allOf(contains('Windows 无法建立到控制服务器的连接'), contains('/health')),
        ),
      ),
    );
  });

  test('deleteDevice sends a bearer-authenticated DELETE request', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    final api = ControlApi();
    addTearDown(api.close);

    final deleteFuture = api.deleteDevice(
      controlServer: 'http://127.0.0.1:${server.port}',
      authToken: 'token-123',
      deviceId: 'node-a',
    );
    final request = await server.first.timeout(const Duration(seconds: 3));
    expect(request.method, 'DELETE');
    expect(request.uri.path, '/api/v1/devices/node-a');
    expect(
      request.headers.value(HttpHeaders.authorizationHeader),
      'Bearer token-123',
    );
    request.response.headers.contentType = ContentType.json;
    request.response.write('{"success":true}');
    await request.response.close();

    await deleteFuture;
  });

  test('updateDevice sends name and virtual IP in PATCH request', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    final api = ControlApi();
    addTearDown(api.close);

    final updateFuture = api.updateDevice(
      controlServer: 'http://127.0.0.1:${server.port}',
      authToken: 'token-123',
      deviceId: 'node-a',
      deviceName: '  Studio Mac  ',
      virtualIp: ' 10.20.0.88 ',
    );
    final request = await server.first.timeout(const Duration(seconds: 3));
    expect(request.method, 'PATCH');
    expect(request.uri.path, '/api/v1/devices/node-a');
    expect(
      request.headers.value(HttpHeaders.authorizationHeader),
      'Bearer token-123',
    );
    final payload =
        jsonDecode(await utf8.decoder.bind(request).join())
            as Map<String, dynamic>;
    expect(payload['device_name'], 'Studio Mac');
    expect(payload['virtual_ip'], '10.20.0.88');
    request.response.headers.contentType = ContentType.json;
    request.response.write('''
{
  "success": true,
  "device": {
    "device_name": "Studio Mac",
    "virtual_ip": "10.20.0.88"
  }
}
''');
    await request.response.close();

    final result = await updateFuture;
    expect(result.deviceName, 'Studio Mac');
    expect(result.virtualIp, '10.20.0.88');
  });

  test('updateDevice rejects invalid virtual IP before sending', () async {
    final api = ControlApi();
    addTearDown(api.close);

    await expectLater(
      api.updateDevice(
        controlServer: defaultControlServer,
        authToken: 'token-123',
        deviceId: 'node-a',
        virtualIp: 'not-an-ip',
      ),
      throwsA(
        isA<ControlApiException>().having(
          (error) => error.message,
          'message',
          contains('虚拟 IP 格式不正确'),
        ),
      ),
    );
  });

  test(
    'deleteDevice reports expired session instead of login credentials',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      final api = ControlApi();
      addTearDown(api.close);

      final deleteFuture = api.deleteDevice(
        controlServer: 'http://127.0.0.1:${server.port}',
        authToken: 'expired-token',
        deviceId: 'node-a',
      );
      final request = await server.first.timeout(const Duration(seconds: 3));
      request.response.statusCode = HttpStatus.unauthorized;
      request.response.headers.contentType = ContentType.json;
      request.response.write('{"error":"unauthorized"}');
      await request.response.close();

      await expectLater(
        deleteFuture,
        throwsA(
          isA<ControlApiException>()
              .having((error) => error.message, 'message', contains('重新登录'))
              .having(
                (error) => error.message,
                'message',
                isNot(contains('邮箱')),
              ),
        ),
      );
    },
  );
}

class _ThrowingHttpClient implements HttpClient {
  _ThrowingHttpClient(this.error);

  final Object error;

  @override
  Duration? connectionTimeout;

  @override
  void close({bool force = false}) {}

  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) {
    return Future<HttpClientRequest>.error(error);
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}
