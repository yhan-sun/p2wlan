import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/desktop_tray_controller.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';

const _defaultUiCycles = 8;

void main() {
  test(
    'Flutter desktop UI stop gracefully stops real production daemon cycles',
    () async {
      final evidencePath =
          Platform.environment['P2WLAN_WINDOWS_LIFECYCLE_EVIDENCE'] ??
          'windows-ui-lifecycle-evidence.json';
      final daemonPath = _resolveDaemonPath();
      final cycles =
          int.tryParse(
            Platform.environment['P2WLAN_WINDOWS_LIFECYCLE_UI_CYCLES'] ?? '',
          ) ??
          _defaultUiCycles;
      final records = <Map<String, dynamic>>[];

      if (daemonPath == null) {
        final record = _failedRecord(
          cycle: 1,
          detail: 'P2WLAN_DAEMON_BIN was not provided',
        );
        records.add(record);
        await _writeEvidence(evidencePath, records);
        fail(record['detail']);
      }
      if (!Platform.isWindows) return;

      for (var cycle = 1; cycle <= cycles; cycle++) {
        records.add(await _runUiStopCycle(daemonPath, cycle));
      }
      await _writeEvidence(evidencePath, records);

      final failures = records
          .where((record) => record['graceful_stop'] != true)
          .toList(growable: false);
      expect(
        failures,
        isEmpty,
        reason:
            'Flutter UI lifecycle evidence contains failed cycles: $failures',
      );
    },
    skip: !Platform.isWindows,
    timeout: const Timeout(Duration(minutes: 8)),
  );
}

String? _resolveDaemonPath() {
  final configured = Platform.environment['P2WLAN_DAEMON_BIN']?.trim();
  if (configured != null && configured.isNotEmpty) return configured;
  const fallback = '../../target/release/p2wlan-daemon.exe';
  return File(fallback).existsSync() ? fallback : null;
}

Future<Map<String, dynamic>> _runUiStopCycle(
  String daemonPath,
  int cycle,
) async {
  final root = await Directory.systemTemp.createTemp(
    'p2wlan_flutter_windows_ui_$cycle-',
  );
  final port = await _freeLoopbackPort();
  final baseUrl = 'http://127.0.0.1:$port/status';
  final configPath = File('${root.path}${Platform.pathSeparator}config.json');
  final logPath = File('${root.path}${Platform.pathSeparator}daemon.log');
  final authPath = File(
    '${root.path}${Platform.pathSeparator}p2wlan-daemon.diag-auth',
  );
  final api = DiagnosticsApi(
    authTokenReader: () async {
      if (!await authPath.exists()) return null;
      final token = (await authPath.readAsString()).trim();
      return token.isEmpty ? null : token;
    },
  );
  final settingsStore = SettingsStore(
    settingsFile: File('${root.path}${Platform.pathSeparator}settings.json'),
    tokenRepository: InMemorySecureTokenRepository(),
  );
  final statusStore = StatusStore(
    settingsStore: settingsStore,
    diagnosticsApi: api,
    enableFreshnessTimer: false,
    enableEventPolling: false,
    routeVerificationInterval: Duration.zero,
  );
  Process? process;
  var startSucceeded = false;
  var gracefulStop = false;
  var forcedTermination = false;
  var processExited = false;
  int? exitCode;
  var childrenGone = false;
  var portReleased = false;
  var authTokenRemoved = false;
  var daemonProcessesClean = false;
  var detail = '';

  try {
    await settingsStore.load();
    await settingsStore.updateSettings(
      settingsStore.settings.copyWith(
        diagnosticsUrl: baseUrl,
        manualMode: true,
        tunInterface: 'p2wlan-lifecycle',
      ),
    );
    final executable = File(daemonPath).absolute.path;
    process = await Process.start(
      executable,
      [
        '--config',
        configPath.path,
        '--control',
        'http://127.0.0.1:1',
        '--network',
        'windows-lifecycle',
        '--diagnostics-bind',
        '127.0.0.1:$port',
        '--log-file',
        logPath.path,
        '--manual',
        '--interface',
        'p2wlan-lifecycle',
        '--address',
        '10.20.0.1',
        '--udp-bind',
        '127.0.0.1:0',
        '--stun',
        'none',
        '--socket-pool',
        'off',
      ],
      workingDirectory: File(executable).parent.path,
      environment: {...Platform.environment, 'P2WLAN_DISABLE_TUN': '1'},
    );
    final token = await _waitUntilReady(
      api: api,
      baseUrl: baseUrl,
      authPath: authPath,
      process: process,
    );
    expect(token, isNotEmpty);
    startSucceeded = true;
    await statusStore.refresh(silent: true);
    expect(statusStore.daemonReachable, isTrue);

    final tray = DesktopTrayController(
      settingsStore: settingsStore,
      statusStore: statusStore,
    );
    final result = await tray.stopDaemonForQuitForTesting();
    gracefulStop = result.ok && result.graceful;
    forcedTermination = result.forcedTermination;
    detail = result.message;
    expect(result.ok, isTrue, reason: result.message);
    expect(result.graceful, isTrue, reason: result.message);
    expect(result.forcedTermination, isFalse, reason: result.message);

    exitCode = await process.exitCode.timeout(const Duration(seconds: 20));
    processExited = true;
    childrenGone = await _descendantsGone(process.pid);
    daemonProcessesClean = await _daemonProcessesClean();
    portReleased = await _loopbackPortReleased(port);
    authTokenRemoved = !await authPath.exists();
  } catch (error) {
    detail = detail.isEmpty ? '$error' : '$detail; $error';
    final currentProcess = process;
    if (currentProcess != null) {
      try {
        exitCode = await currentProcess.exitCode.timeout(
          const Duration(milliseconds: 100),
        );
        processExited = true;
      } on TimeoutException {
        forcedTermination = true;
        currentProcess.kill(ProcessSignal.sigkill);
      } catch (_) {}
      if (!processExited) {
        try {
          exitCode = await currentProcess.exitCode.timeout(
            const Duration(seconds: 5),
          );
          processExited = true;
        } catch (_) {}
      }
      childrenGone = await _descendantsGone(currentProcess.pid);
    }
    daemonProcessesClean = await _daemonProcessesClean();
    portReleased = await _loopbackPortReleased(port);
    authTokenRemoved = !await authPath.exists();
  } finally {
    statusStore.dispose();
    settingsStore.dispose();
    if (root.existsSync()) {
      try {
        await root.delete(recursive: true);
      } catch (_) {}
    }
  }

  return {
    'cycle': cycle,
    'entrypoint': 'ui',
    'mode': 'ui',
    'real_wintun': false,
    'start_succeeded': startSucceeded,
    'graceful_stop': gracefulStop && !forcedTermination,
    'forced_termination': forcedTermination,
    'process_exited': processExited,
    'process_exit_code': exitCode,
    'children_gone': childrenGone,
    'diagnostics_port_released': portReleased,
    'auth_token_removed': authTokenRemoved,
    'wintun_stale': false,
    'wintun_observed': false,
    'daemon_processes_clean': daemonProcessesClean,
    'diagnostics_port': port,
    'detail': detail,
  };
}

Future<String> _waitUntilReady({
  required DiagnosticsApi api,
  required String baseUrl,
  required File authPath,
  required Process process,
}) async {
  final deadline = DateTime.now().add(const Duration(seconds: 25));
  var processExited = false;
  int? processExitCode;
  unawaited(
    process.exitCode.then((value) {
      processExited = true;
      processExitCode = value;
    }),
  );
  while (DateTime.now().isBefore(deadline)) {
    if (processExited) {
      throw StateError(
        'daemon exited with code $processExitCode before diagnostics became ready',
      );
    }
    final token = await _readToken(authPath);
    if (token != null && await api.fetchHealth(baseUrl)) return token;
    await Future<void>.delayed(const Duration(milliseconds: 200));
  }
  throw StateError('daemon diagnostics did not become ready at $baseUrl');
}

Future<String?> _readToken(File path) async {
  try {
    if (!await path.exists()) return null;
    final value = (await path.readAsString()).trim();
    return value.isEmpty ? null : value;
  } catch (_) {
    return null;
  }
}

Future<int> _freeLoopbackPort() async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = server.port;
  await server.close();
  return port;
}

Future<bool> _loopbackPortReleased(int port) async {
  try {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, port);
    await server.close();
    return true;
  } catch (_) {
    return false;
  }
}

Future<bool> _descendantsGone(int rootPid) async {
  final script =
      r'''
$deadline = [DateTime]::UtcNow.AddSeconds(5)
do {
  $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
  $frontier = [System.Collections.Generic.Queue[int]]::new()
  $frontier.Enqueue(__ROOT_PID__)
  $descendants = [System.Collections.Generic.HashSet[int]]::new()
  while ($frontier.Count -gt 0) {
    $parent = $frontier.Dequeue()
    foreach ($process in $all | Where-Object { [int]$_.ParentProcessId -eq $parent }) {
      $child = [int]$process.ProcessId
      if ($descendants.Add($child)) { $frontier.Enqueue($child) }
    }
  }
  if ($descendants.Count -eq 0) { exit 0 }
  Start-Sleep -Milliseconds 100
} while ([DateTime]::UtcNow -lt $deadline)
$descendants | ConvertTo-Json -Compress
exit 1
'''
          .replaceFirst('__ROOT_PID__', '$rootPid');
  final result = await _runPowerShell(script);
  return result.exitCode == 0;
}

Future<bool> _daemonProcessesClean() async {
  const script = r'''
$processes = @(Get-CimInstance Win32_Process -Filter "Name = 'p2wlan-daemon.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -notmatch '(?i)(^|\s)--build-info(\s|$)' })
if ($processes.Count -eq 0) { exit 0 }
$processes | Select-Object ProcessId, CommandLine | ConvertTo-Json -Compress
exit 1
''';
  final result = await _runPowerShell(script);
  return result.exitCode == 0;
}

Future<ProcessResult> _runPowerShell(String script) {
  return Process.run('powershell.exe', [
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-Command',
    script,
  ]);
}

Map<String, dynamic> _failedRecord({
  required int cycle,
  required String detail,
}) {
  return {
    'cycle': cycle,
    'entrypoint': 'ui',
    'mode': 'ui',
    'real_wintun': false,
    'start_succeeded': false,
    'graceful_stop': false,
    'forced_termination': false,
    'process_exited': false,
    'process_exit_code': null,
    'children_gone': false,
    'diagnostics_port_released': false,
    'auth_token_removed': false,
    'wintun_stale': false,
    'wintun_observed': false,
    'daemon_processes_clean': false,
    'detail': detail,
  };
}

Future<void> _writeEvidence(
  String path,
  List<Map<String, dynamic>> records,
) async {
  final failed = records.where((record) => record['graceful_stop'] != true);
  final sourceHeadSha = _lifecycleEvidenceSha('P2WLAN_EXACT_HEAD');
  final workflowSha = _lifecycleEvidenceSha('P2WLAN_WORKFLOW_SHA');
  final evidence = {
    'schema_version': 2,
    'repository': 'yhan-sun/p2wlan',
    'source_head_sha': sourceHeadSha,
    'workflow_sha': workflowSha,
    'runner_os': 'windows-latest',
    'generated_at_utc': DateTime.now().toUtc().toIso8601String(),
    'capabilities': [
      {
        'name': 'ui_stop',
        'status': failed.isEmpty ? 'verified' : 'failed',
        'detail': failed.isEmpty
            ? 'Flutter desktop UI quit path stopped real production daemon cycles gracefully'
            : 'one or more Flutter desktop UI stop cycles failed',
      },
    ],
    'cycles': records,
  };
  final file = File(path);
  await file.parent.create(recursive: true);
  await file.writeAsString(
    '${const JsonEncoder.withIndent('  ').convert(evidence)}\n',
    flush: true,
  );
}

String _lifecycleEvidenceSha(String variable) {
  final value = Platform.environment[variable]?.trim();
  if (!Platform.isWindows) return value ?? 'non-windows-local';
  if (value == null || !RegExp(r'^[0-9a-fA-F]{40}$').hasMatch(value)) {
    throw StateError(
      '$variable must be a 40-character git SHA for Windows evidence',
    );
  }
  return value;
}
