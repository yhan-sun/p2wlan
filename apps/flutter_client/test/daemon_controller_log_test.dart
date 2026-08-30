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

  test('detects a missing Wintun runtime marker', () async {
    final log = await writeLog(
      'ERROR p2pnet_tun::windows: wintun.dll not found or not loadable. '
      'Tried: C:\\Program Files\\P2WLAN\\wintun.dll\n',
    );
    expect(await logTailShowsWintunMissing(log.path), isTrue);
  });

  test('detects the current Wintun missing marker', () async {
    final log = await writeLog(
      'ERROR [tun] Wintun load failed: dynamic library not found: '
      'wintun.dll not found. Tried: C:\\Program Files\\P2WLAN\\wintun.dll\n',
    );
    final failure = await logTailClassifyStartupFailure(log.path);
    expect(failure?.code, DaemonStartupFailureCode.wintunDllMissing);
  });

  test(
    'a healthy Windows runtime log is not a missing Wintun marker',
    () async {
      final log = await writeLog(
        'INFO p2pnet_tun::windows: Loaded Wintun runtime from wintun.dll\n',
      );
      expect(await logTailShowsWintunMissing(log.path), isFalse);
    },
  );

  test('a missing log file is not an auth failure', () async {
    expect(
      await logTailShowsPermanentAuthFailure('${tempDir.path}/missing.log'),
      isFalse,
    );
  });

  test('rotates daemon logs and keeps only the previous startup', () async {
    final current = File('${tempDir.path}/p2wlan-daemon.log');
    final previous = File('${current.path}.1');
    await current.writeAsString('current startup');
    await previous.writeAsString('older startup');

    await rotateP2wlanLogFiles(current);

    expect(await current.exists(), isFalse);
    expect(await previous.readAsString(), 'current startup');
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

  test(
    'Windows token failures distinguish ACL errors and redact diagnostics',
    () {
      final aclError = WindowsAclProtectionException(
        directory: false,
        exitCode: 5,
        stdout: 'token=should-not-leak',
        stderr: 'secret=also-should-not-leak',
      );

      expect(
        windowsLaunchTokenFailureCodeForError(aclError),
        DaemonStartupFailureCode.aclFailure,
      );
      expect(
        windowsLaunchTokenFailureCodeForError(
          StateError('token file write failed'),
        ),
        DaemonStartupFailureCode.tokenAccessFailed,
      );
      expect(aclError.diagnostic, contains('exitCode=5'));
      expect(aclError.diagnostic, contains('token=<redacted>'));
      expect(aclError.diagnostic, contains('secret=<redacted>'));
      expect(aclError.diagnostic, isNot(contains('should-not-leak')));
      expect(aclError.diagnostic, isNot(contains('also-should-not-leak')));
    },
  );

  test('an unrelated relay 404 log is not an auth failure', () async {
    final log = await writeLog(
      'WARN p2pnet_daemon::relay: Received relay runtime error: code=404, '
      'error_code=peer_not_found\n',
    );
    expect(await logTailShowsPermanentAuthFailure(log.path), isFalse);
  });

  test(
    'classifies actionable startup stages without exposing log contents',
    () {
      final cases = <String, DaemonStartupFailureCode>{
        '[startup] windows_elevated=false':
            DaemonStartupFailureCode.daemonNotElevated,
        'Windows ACL protection failed': DaemonStartupFailureCode.aclFailure,
        'failed to open existing Wintun adapter':
            DaemonStartupFailureCode.wintunAdapterOpenFailed,
        '[tun] IPv4 configuration failed':
            DaemonStartupFailureCode.ipConfigFailed,
        '[tun] MTU configuration failed':
            DaemonStartupFailureCode.mtuConfigFailed,
        'route install failed: access denied':
            DaemonStartupFailureCode.routeInstallFailed,
        'failed to bind diagnostics endpoint at 127.0.0.1:39277':
            DaemonStartupFailureCode.diagnosticsBindFailed,
      };
      for (final entry in cases.entries) {
        expect(classifyDaemonStartupLog(entry.key)?.code, entry.value);
      }
    },
  );

  test(
    'startup probe fails fast on child exit and preserves stage details',
    () {
      final exited = classifyDaemonStartupProbe(
        healthReady: false,
        childAlive: false,
        deadlineReached: false,
      );
      expect(
        exited.failure?.code,
        DaemonStartupFailureCode.daemonExitedDuringStartup,
      );

      final stageFailure = const DaemonStartupFailure(
        DaemonStartupFailureCode.mtuConfigFailed,
        'MTU failed',
      );
      final classified = classifyDaemonStartupProbe(
        healthReady: false,
        childAlive: false,
        logFailure: stageFailure,
        deadlineReached: false,
      );
      expect(
        classified.failure?.code,
        DaemonStartupFailureCode.mtuConfigFailed,
      );

      final ready = classifyDaemonStartupProbe(
        healthReady: true,
        childAlive: true,
        deadlineReached: false,
      );
      expect(ready.ready, isTrue);

      final pending = classifyDaemonStartupProbe(
        healthReady: false,
        childAlive: true,
        deadlineReached: false,
      );
      expect(pending.ready, isFalse);
      expect(pending.failure, isNull);

      final timeout = classifyDaemonStartupProbe(
        healthReady: false,
        childAlive: true,
        deadlineReached: true,
      );
      expect(timeout.failure?.code, DaemonStartupFailureCode.startupTimeout);
    },
  );

  test('classifies UAC cancellation and launch failures', () {
    expect(
      classifyWindowsLaunchFailure('The operation was canceled by the user.')
          .code,
      DaemonStartupFailureCode.uacCancelled,
    );
    expect(
      classifyWindowsLaunchFailure('Start-Process failed: access denied').code,
      DaemonStartupFailureCode.uacLaunchFailed,
    );
    expect(
      classifyWindowsLaunchFailure('Windows ACL protection failed').code,
      DaemonStartupFailureCode.aclFailure,
    );
  });

  test('parses only the elevated child PID marker', () {
    expect(
      parseWindowsChildPidMarker(
        'PowerShell noise\n__P2WLAN_CHILD_PID__=4242\n',
      ),
      4242,
    );
    expect(parseWindowsChildPidMarker('__P2WLAN_CHILD_PID__=0'), isNull);
    expect(parseWindowsChildPidMarker('no marker'), isNull);
    expect(
      parseWindowsChildPidMarker(
        '__P2WLAN_CHILD_PID__=\n+\n[string]@{Id=12345}.Id',
      ),
      isNull,
    );
  });

  test('does not treat the build-info probe as a running daemon', () {
    expect(
      isP2wlanDaemonRuntimeCommandLine(
        '/Applications/P2WLAN.app/Contents/Resources/p2wlan-daemon --build-info',
      ),
      isFalse,
    );
    expect(
      isP2wlanDaemonRuntimeCommandLine(
        '/Applications/P2WLAN.app/Contents/Resources/p2wlan-daemon '
        '--config /Users/test/Library/Application Support/p2wlan/p2wlan-config.json '
        '--diagnostics-bind 127.0.0.1:39277 --manual',
      ),
      isTrue,
    );
    expect(isP2wlanDaemonRuntimeCommandLine('/usr/bin/other-process'), isFalse);
  });

  test('quotes Windows arguments across Start-Process ArgumentList', () {
    expect(windowsCommandLineArgQuote(''), '""');
    expect(
      windowsCommandLineArgQuote('C:\\Program Files\\P2WLAN\\'),
      '"C:\\Program Files\\P2WLAN\\\\"',
    );
    expect(windowsCommandLineArgQuote('a"b'), '"a\\"b"');
    expect(
      windowsCommandLineArgQuote('C:\\用户\\p2wlan-daemon.exe'),
      contains('用户'),
    );
  });
}
