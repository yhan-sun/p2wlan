import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';

void main() {
  late Directory tempDir;

  setUp(() async {
    tempDir = await Directory.systemTemp.createTemp('p2wlan-auth-log-test');
  });

  tearDown(() async {
    try {
      await tempDir.delete(recursive: true);
    } catch (_) {}
  });

  Future<File> writeLog(String contents) async {
    final log = File('${tempDir.path}/p2wlan-daemon.log');
    await log.writeAsString(contents);
    return log;
  }

  test('detects the daemon permanent auth failure markers', () async {
    final log = await writeLog(
      'INFO p2wlan_daemon: starting\n'
      'ERROR p2wlan_daemon::control: Permanent auth failure during polling: '
      'register request returned HTTP 401\n',
    );
    expect(await logTailShowsPermanentAuthFailure(log.path), isTrue);
  });

  test('detects the re-authentication-required marker', () async {
    final log = await writeLog(
      'ERROR p2wlan_daemon::control: Control registration permanent auth '
      'failure — re-authentication required\n',
    );
    expect(await logTailShowsPermanentAuthFailure(log.path), isTrue);
  });

  test('detects 401 markers from the signal poll loop', () async {
    final log = await writeLog(
      'ERROR p2wlan_daemon::control: Permanent auth failure during signal '
      'polling: list signals returned HTTP 401\n',
    );
    expect(await logTailShowsPermanentAuthFailure(log.path), isTrue);
  });

  test('a healthy startup log is not an auth failure', () async {
    final log = await writeLog(
      'INFO p2wlan_daemon: P2WLAN daemon starting...\n'
      'INFO p2wlan_daemon: Connected to relay tcp://control.example.com:18081\n'
      'INFO p2wlan_daemon: diagnostics ready\n',
    );
    expect(await logTailShowsPermanentAuthFailure(log.path), isFalse);
  });

  test('a missing log file is not an auth failure', () async {
    expect(
      await logTailShowsPermanentAuthFailure('${tempDir.path}/missing.log'),
      isFalse,
    );
  });

  test('launch token uses a random name and is deleted explicitly', () async {
    final api = DiagnosticsApi(authTokenReader: () async => null);
    addTearDown(api.close);
    final controller = DaemonController(diagnosticsApi: api);
    final runtime = Directory('${tempDir.path}/runtime');
    final file = await controller.createEphemeralLaunchTokenFile(
      runtime,
      'launch-secret',
    );

    expect(file.uri.pathSegments.last, startsWith('p2wlan-launch-'));
    expect(file.uri.pathSegments.last, endsWith('.token'));
    expect(await file.readAsString(), 'launch-secret');
    if (!Platform.isWindows) {
      expect((await file.stat()).mode & 0x1ff, 0x180);
      expect((await runtime.stat()).mode & 0x1ff, 0x1c0);
    }

    await controller.deleteEphemeralLaunchTokenFile(file);
    expect(await file.exists(), isFalse);
  });

  test(
    'stale launch token cleanup is limited to the controlled name',
    () async {
      final api = DiagnosticsApi(authTokenReader: () async => null);
      addTearDown(api.close);
      final controller = DaemonController(diagnosticsApi: api);
      final runtime = Directory('${tempDir.path}/stale-runtime');
      await runtime.create(recursive: true);
      final stale = File('${runtime.path}/p2wlan-launch-abcdef.token');
      await stale.writeAsString('old');
      await stale.setLastModified(
        DateTime.now().subtract(const Duration(minutes: 11)),
      );
      final unrelated = File('${runtime.path}/keep.txt');
      await unrelated.writeAsString('keep');

      await controller.cleanupStaleLaunchTokenFiles(runtime);

      expect(await stale.exists(), isFalse);
      expect(await unrelated.exists(), isTrue);
    },
  );

  test('an unrelated relay 404 log is not an auth failure', () async {
    final log = await writeLog(
      'WARN p2pnet_daemon::relay: Received relay runtime error: code=404, '
      'error_code=peer_not_found\n',
    );
    expect(await logTailShowsPermanentAuthFailure(log.path), isFalse);
  });
}
