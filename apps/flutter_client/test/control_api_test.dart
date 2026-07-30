import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/control_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';

void main() {
  test('default control server matches the desktop client default', () {
    expect(defaultControlServer, 'http://control.example.com:18080');
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
}
