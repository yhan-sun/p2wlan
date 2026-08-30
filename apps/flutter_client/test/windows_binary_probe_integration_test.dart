import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
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

  test('Windows runs the actual p2wlan-daemon.exe --build-info', () async {
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
  }, skip: !Platform.isWindows);

  test(
    'Windows helper reads the real current-user SID with a normal child',
    () async {
      final api = DiagnosticsApi(authTokenReader: () async => null);
      addTearDown(api.close);
      final controller = DaemonController(diagnosticsApi: api);

      final result = await controller.runWindowsPowerShellForTesting(
        '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
      );

      expect(result.exitCode, 0, reason: result.stderr.toString());
      expect(
        RegExp(r'^S-\d-\d+(?:-\d+)+$')
            .hasMatch(result.stdout.toString().trim()),
        isTrue,
        reason: result.stdout.toString(),
      );
    },
    skip: !Platform.isWindows,
  );

  test('Windows helper preserves a non-zero child exit code', () async {
    final api = DiagnosticsApi(authTokenReader: () async => null);
    addTearDown(api.close);
    final controller = DaemonController(diagnosticsApi: api);

    final result = await controller.runWindowsPowerShellForTesting(
      r'Write-Output "helper stdout"; $global:LASTEXITCODE = 17',
    );

    expect(result.exitCode, 17, reason: result.stderr.toString());
    expect(result.stdout, contains('helper stdout'));
  }, skip: !Platform.isWindows);

  test('Windows helper kills a timed-out child', () async {
    final root = await _createTempRoot();
    addTearDown(() => _deleteTempRoot(root));
    final marker = File(
      '${root.path}${Platform.pathSeparator}helper-timeout-finished.marker',
    );
    final markerPath = marker.path.replaceAll("'", "''");
    final api = DiagnosticsApi(authTokenReader: () async => null);
    addTearDown(api.close);
    final controller = DaemonController(diagnosticsApi: api);

    final result = await controller.runWindowsPowerShellForTesting(
      "Start-Sleep -Seconds 30; Set-Content -LiteralPath '$markerPath' -Value finished",
      timeout: const Duration(milliseconds: 250),
    );

    expect(result.exitCode, isNot(0));
    expect(result.stderr, contains('timed out after 250 milliseconds'));
    await Future<void>.delayed(const Duration(seconds: 1));
    expect(marker.existsSync(), isFalse);
  }, skip: !Platform.isWindows);

  test(
    'Windows ACL token preparation keeps only the required runtime access',
    () async {
      final root = await _createTempRoot();
      addTearDown(() => _deleteTempRoot(root));
      final api = DiagnosticsApi(authTokenReader: () async => null);
      addTearDown(api.close);
      final controller = DaemonController(diagnosticsApi: api);
      final runtime = Directory('${root.path}${Platform.pathSeparator}runtime');
      await runtime.create(recursive: true);
      final stale = File(
        '${runtime.path}${Platform.pathSeparator}'
        'p2wlan-launch-abcdef0123456789.token',
      );
      await stale.writeAsString('expired');
      await stale.setLastModified(
        DateTime.now().subtract(const Duration(minutes: 11)),
      );

      // This is the production stage-05/06 sequence: protect the directory
      // once, then clean stale files, write the new token, and protect only
      // that token file.
      await controller.protectRuntimeDirectory(runtime);
      final currentSid = await _windowsCurrentUserSid(controller);
      _expectRestrictedWindowsAcl(
        await _readWindowsAcl(controller, runtime.path, directory: true),
        currentSid,
      );

      await controller.cleanupStaleLaunchTokenFiles(runtime);
      expect(await stale.exists(), isFalse);

      final token = await controller.writeEphemeralLaunchTokenFile(
        runtime,
        'integration-launch-token',
      );
      await controller.protectEphemeralLaunchTokenFile(token);
      expect(await token.readAsString(), 'integration-launch-token');
      _expectRestrictedWindowsAcl(
        await _readWindowsAcl(controller, token.path, directory: false),
        currentSid,
      );

      await controller.deleteEphemeralLaunchTokenFile(token);
      expect(await token.exists(), isFalse);
    },
    skip: !Platform.isWindows,
  );

  test('Windows daemon completes three graceful start-stop cycles without force kill', () async {
    final binaryPath = _resolveWindowsDaemonBinary();
    expect(
      binaryPath,
      isNotNull,
      reason:
          'Set P2WLAN_DAEMON_BIN or build a Windows release daemon before '
          'running this integration test.',
    );

    final root = await _createTempRoot();
    addTearDown(() => _deleteTempRoot(root));

    for (var cycle = 0; cycle < 3; cycle++) {
      final cycleDir = Directory(
        '${root.path}${Platform.pathSeparator}cycle-$cycle',
      );
      await cycleDir.create(recursive: true);
      final config = File(
        '${cycleDir.path}${Platform.pathSeparator}p2wlan-config.json',
      );
      final log = File(
        '${cycleDir.path}${Platform.pathSeparator}p2wlan-daemon.log',
      );
      final auth = File(
        '${cycleDir.path}${Platform.pathSeparator}p2wlan-daemon.diag-auth',
      );
      final port = await _reserveTcpPort();
      final diagnosticsUrl = 'http://127.0.0.1:$port/status';

      final process = await Process.start(
        binaryPath!,
        [
          '--config',
          config.path,
          '--control',
          'http://127.0.0.1:9',
          '--network',
          'default',
          '--diagnostics-bind',
          '127.0.0.1:$port',
          '--log-file',
          log.path,
          '--udp-bind',
          '127.0.0.1:0',
          '--interface',
          'p2wlan-lifecycle-$cycle',
          '--manual',
        ],
        environment: {'P2WLAN_DISABLE_TUN': '1', 'RUST_LOG': 'info'},
      );
      var exited = false;
      addTearDown(() async {
        if (!exited) {
          process.kill(ProcessSignal.sigkill);
          try {
            await process.exitCode.timeout(const Duration(seconds: 5));
          } catch (_) {}
        }
      });
      final stdoutFuture = process.stdout.transform(utf8.decoder).join();
      final stderrFuture = process.stderr.transform(utf8.decoder).join();

      await _waitForWindowsDaemonHealth(port);
      await _waitForNonEmptyFile(auth);

      final api = DiagnosticsApi(
        authTokenReader: () async => (await auth.readAsString()).trim(),
      );
      final controller = DaemonController(diagnosticsApi: api);
      final stopped = await controller.stop(diagnosticsUrl);
      api.close();

      expect(stopped.ok, isTrue, reason: stopped.message);
      expect(
        stopped.message,
        isNot(contains('forced process termination')),
        reason: 'normal UI stop must not use taskkill /F',
      );

      final exitCode = await process.exitCode.timeout(
        const Duration(seconds: 15),
      );
      exited = true;
      final stdout = await stdoutFuture;
      final stderr = await stderrFuture;
      expect(exitCode, 0, reason: 'cycle=$cycle stdout=$stdout stderr=$stderr');
      expect(await auth.exists(), isFalse);
      expect(await log.exists(), isTrue);
      expect(await log.readAsString(), contains('Shutdown complete.'));
    }
  }, skip: !Platform.isWindows);
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
  Duration timeout = const Duration(seconds: 30),
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

Future<String> _windowsCurrentUserSid(DaemonController controller) async {
  final result = await controller.runWindowsPowerShellForTesting(
    '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
  );
  expect(result.exitCode, 0, reason: result.stderr.toString());
  final sid = result.stdout.toString().trim();
  expect(
    RegExp(r'^S-\d-\d+(?:-\d+)+$').hasMatch(sid),
    isTrue,
    reason: result.stdout.toString(),
  );
  return sid;
}

Future<_WindowsAclSnapshot> _readWindowsAcl(
  DaemonController controller,
  String path, {
  required bool directory,
}) async {
  final quotedPath = path.replaceAll("'", "''");
  final result = await controller.runWindowsPowerShellForTesting(
    '\$path = \'$quotedPath\'; '
    'if (\'$directory\' -eq \'true\') { '
    '\$acl = [System.IO.Directory]::GetAccessControl(\$path) '
    '} else { '
    '\$acl = [System.IO.File]::GetAccessControl(\$path) }; '
    '\$sids = @(\$acl.Access | ForEach-Object { '
    'try { \$_.IdentityReference.Translate('
    '[System.Security.Principal.SecurityIdentifier]).Value } '
    'catch { \$_.IdentityReference.Value } } | Sort-Object -Unique); '
    '[pscustomobject]@{ '
    'protected = [bool]\$acl.AreAccessRulesProtected; '
    'sids = @(\$sids) '
    '} | ConvertTo-Json -Compress',
    timeout: const Duration(seconds: 30),
  );
  expect(result.exitCode, 0, reason: result.stderr.toString());
  final decoded = jsonDecode(result.stdout.toString().trim());
  expect(
    decoded,
    isA<Map<String, dynamic>>(),
    reason: result.stdout.toString(),
  );
  final json = decoded! as Map<String, dynamic>;
  final rawSids = json['sids'];
  final values = rawSids is List<Object?> ? rawSids : <Object?>[rawSids];
  return _WindowsAclSnapshot(
    isProtected: json['protected'] == true,
    sids: values.whereType<String>().toSet(),
  );
}

void _expectRestrictedWindowsAcl(_WindowsAclSnapshot acl, String currentSid) {
  expect(acl.isProtected, isTrue);
  expect(acl.sids, contains(currentSid));
  expect(acl.sids, contains('S-1-5-32-544'));
  expect(acl.sids, contains('S-1-5-18'));
  expect(acl.sids, isNot(contains('S-1-1-0')));
  expect(acl.sids, isNot(contains('S-1-5-32-545')));
}

class _WindowsAclSnapshot {
  const _WindowsAclSnapshot({required this.isProtected, required this.sids});

  final bool isProtected;
  final Set<String> sids;
}

Future<int> _reserveTcpPort() async {
  final socket = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = socket.port;
  await socket.close();
  return port;
}

Future<void> _waitForWindowsDaemonHealth(int port) async {
  final client = HttpClient()
    ..connectionTimeout = const Duration(milliseconds: 500)
    ..findProxy = null;
  final deadline = DateTime.now().add(const Duration(seconds: 20));
  try {
    while (DateTime.now().isBefore(deadline)) {
      try {
        final request = await client
            .getUrl(Uri.parse('http://127.0.0.1:$port/health'))
            .timeout(const Duration(milliseconds: 500));
        final response = await request.close().timeout(
          const Duration(milliseconds: 500),
        );
        await response.drain<void>();
        if (response.statusCode == HttpStatus.ok) return;
      } catch (_) {}
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
  } finally {
    client.close(force: true);
  }
  throw StateError('daemon health endpoint did not become ready on port $port');
}

Future<void> _waitForNonEmptyFile(File file) async {
  final deadline = DateTime.now().add(const Duration(seconds: 10));
  while (DateTime.now().isBefore(deadline)) {
    try {
      if (await file.exists() && (await file.length()) > 0) return;
    } catch (_) {}
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
  throw StateError('file did not become ready: ${file.path}');
}
