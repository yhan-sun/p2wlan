import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';

void main() {
  test(
    'successful probe runs a real child and parses build-info JSON',
    () async {
      final root = await _createTempRoot();
      addTearDown(() => _deleteTempRoot(root));

      final probe = await _runControlledProbe(root, 'success');

      expect(probe.error, isNull, reason: probe.error);
      expect(probe.failureCode, isNull);
      expect(probe.identity, isNotNull);
      expect(probe.identity!.isComplete, isTrue);
      expect(probe.identity!.appVersion, '0.1.135');
    },
  );

  test('non-zero probe preserves sanitized stdout and stderr', () async {
    final root = await _createTempRoot();
    addTearDown(() => _deleteTempRoot(root));

    final probe = await _runControlledProbe(root, 'nonzero');

    expect(probe.failureCode, DaemonStartupFailureCode.daemonBinaryLoadFailed);
    expect(probe.error, contains('code 17'));
    expect(probe.error, contains('stdout=probe stdout detail'));
    expect(probe.error, contains('stderr=probe stderr token=<redacted>'));
    expect(probe.error, isNot(contains('should-not-leak')));
  });

  test('timeout kills a non-exiting child process', () async {
    final root = await _createTempRoot();
    addTearDown(() => _deleteTempRoot(root));
    final marker = File(
      '${root.path}${Platform.pathSeparator}timeout-finished.marker',
    );

    final probe = await _runControlledProbe(
      root,
      'timeout',
      marker: marker,
      timeout: const Duration(milliseconds: 250),
    );

    expect(probe.failureCode, DaemonStartupFailureCode.daemonBinaryLoadFailed);
    expect(probe.error, contains('timed out after 250 milliseconds'));
    await Future<void>.delayed(const Duration(seconds: 1));
    expect(marker.existsSync(), isFalse);
  });

  test('missing executable maps to DAEMON_BINARY_LOAD_FAILED', () async {
    final root = await _createTempRoot();
    addTearDown(() => _deleteTempRoot(root));
    final missing = File(
      '${root.path}${Platform.pathSeparator}does-not-exist.exe',
    );

    final probe = await probeDaemonBinary(missing);

    expect(probe.error, isNotNull);
    expect(probe.failureCode, DaemonStartupFailureCode.daemonBinaryLoadFailed);
  });

  test(
    'Windows runs the actual p2wlan-daemon.exe --build-info',
    () async {
      final binaryPath = _resolveWindowsDaemonBinary();
      expect(
        binaryPath,
        isNotNull,
        reason:
            'Set P2WLAN_DAEMON_BIN or build a Windows release daemon before '
            'running this integration test.',
      );

      final probe = await probeDaemonBinary(File(binaryPath!));

      expect(probe.error, isNull, reason: probe.error);
      expect(probe.failureCode, isNull);
      expect(probe.identity, isNotNull);
      expect(probe.identity!.isComplete, isTrue);
    },
    skip: !Platform.isWindows,
  );
}

Future<Directory> _createTempRoot() {
  return Directory.systemTemp.createTemp('p2wlan binary probe ');
}

Future<void> _deleteTempRoot(Directory root) async {
  try {
    await root.delete(recursive: true);
  } catch (_) {}
}

Future<DaemonBinaryProbe> _runControlledProbe(
  Directory root,
  String mode, {
  File? marker,
  Duration timeout = const Duration(seconds: 6),
}) async {
  if (Platform.isWindows) {
    final script = File(
      '${root.path}${Platform.pathSeparator}probe-helper.ps1',
    );
    await script.writeAsString(r'''
param([string]$mode, [string]$markerPath)
$ErrorActionPreference = 'Stop'
switch ($mode) {
  'success' {
    Write-Output '{"app_version":"0.1.135","daemon_version":"0.1.135","git_commit":"integration","build_id":"integration","dirty":false,"diff_hash":"","profile":"release"}'
    exit 0
  }
  'nonzero' {
    Write-Output 'probe stdout detail'
    [Console]::Error.WriteLine('probe stderr token=should-not-leak')
    exit 17
  }
  'timeout' {
    Start-Sleep -Seconds 30
    Set-Content -LiteralPath $markerPath -Value 'finished'
    exit 0
  }
  default {
    exit 2
  }
}
''');
    return probeDaemonBinary(
      File(_windowsPowerShell()),
      arguments: [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        script.path,
        mode,
        marker?.path ?? '',
      ],
      timeout: timeout,
    );
  }

  final script = File('${root.path}${Platform.pathSeparator}probe-helper.sh');
  await script.writeAsString(r'''#!/bin/sh
set -eu
case "$1" in
  success)
    printf '%s\n' '{"app_version":"0.1.135","daemon_version":"0.1.135","git_commit":"integration","build_id":"integration","dirty":false,"diff_hash":"","profile":"release"}'
    ;;
  nonzero)
    printf '%s\n' 'probe stdout detail'
    printf '%s\n' 'probe stderr token=should-not-leak' >&2
    exit 17
    ;;
  timeout)
    sleep 30
    touch "$2"
    ;;
  *)
    exit 2
    ;;
esac
''');
  final chmod = await Process.run('chmod', ['+x', script.path]);
  expect(chmod.exitCode, 0, reason: chmod.stderr.toString());
  return probeDaemonBinary(
    script,
    arguments: [mode, marker?.path ?? ''],
    timeout: timeout,
  );
}

String _windowsPowerShell() {
  final windir = Platform.environment['WINDIR']?.trim();
  if (windir == null || windir.isEmpty) return 'powershell.exe';
  return '$windir\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
}

String? _resolveWindowsDaemonBinary() {
  final configured = Platform.environment['P2WLAN_DAEMON_BIN']?.trim();
  final cwd = Directory.current;
  final candidates = <String>[
    if (configured != null && configured.isNotEmpty) configured,
    '${cwd.path}/build/windows/x64/runner/Release/p2wlan-daemon.exe',
    '${cwd.path}/../../target/release/p2wlan-daemon.exe',
    '${cwd.path}/target/release/p2wlan-daemon.exe',
  ];
  for (final candidate in candidates) {
    if (File(candidate).existsSync()) return File(candidate).absolute.path;
  }
  return null;
}
