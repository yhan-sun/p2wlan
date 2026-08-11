import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
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

  test('an unrelated relay 404 log is not an auth failure', () async {
    final log = await writeLog(
      'WARN p2pnet_daemon::relay: Received relay runtime error: code=404, '
      'error_code=peer_not_found\n',
    );
    expect(await logTailShowsPermanentAuthFailure(log.path), isFalse);
  });
}
