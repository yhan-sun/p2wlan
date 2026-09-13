part of '../daemon_controller.dart';

/// Return whether a process command line represents a running daemon rather
/// than the side-effect-free identity probe used to validate a release
/// binary.  The probe has the same executable name, but it must never block a
/// real daemon start or be sent a shutdown signal as if it owned the
/// diagnostics endpoint.
bool isP2wlanDaemonRuntimeCommandLine(String command) {
  final normalized = command.trim();
  if (!normalized.contains(DaemonController.daemonBinaryName)) return false;
  return !RegExp(r'(^|\s)--build-info(?:\s|$)').hasMatch(normalized);
}

/// The OS-returned launch PID and the authenticated diagnostics PID are the
/// only Windows identities allowed to use the fast process-name check. Any PID
/// discovered by scanning the process table must still pass the stricter
/// command-line instance match below.
bool trustedWindowsDaemonIdentityMatches({
  required int pid,
  required int? launchedProcessId,
  required int? authenticatedProcessId,
  required String? processName,
}) {
  final trusted =
      pid == launchedProcessId || pid == authenticatedProcessId;
  if (!trusted || processName == null) return false;
  return processName.toLowerCase() ==
      '${DaemonController.daemonBinaryName}.exe';
}

extension DaemonControllerPids on DaemonController {
  /// Whether a daemon is already occupying the diagnostics instance this
  /// controller is about to start.
  ///
  /// `/health` is deliberately a cheap liveness endpoint and can remain
  /// reachable while the daemon's TUN/dataplane is dead.  Prefer a verified
  /// process identity or a process whose command line contains this exact
  /// diagnostics bind; use health only as a final signal so `start()` can
  /// hand the situation to the verified `stop()` path instead of silently
  /// skipping elevation.
  Future<bool> _hasExistingDaemonForStart(String diagnosticsUrl) async {
    if (Platform.isWindows) {
      // One WMI query is enough to find the old daemon. The previous flow
      // performed a status lookup plus separate exact-bind and single-process
      // PowerShell scans before it even attempted to stop anything.
      if ((await _findWindowsDaemonPids()).isNotEmpty) return true;
      return _diagnosticsApi.fetchHealth(diagnosticsUrl);
    }
    if (await _diagnosticsProcessId(diagnosticsUrl) != null) return true;

    final bind = _diagnosticsBindFromStatusUrl(diagnosticsUrl);
    if (await _findDaemonPidByDiagnosticsBind(bind) != null) return true;

    // If the previous instance used another diagnostics port, the exact-bind
    // scan cannot see it.  Only accept a single daemon process here; the
    // existing stop() path will still re-verify the command line before kill.
    if (await _findSingleDaemonPid() != null) return true;

    return _diagnosticsApi.fetchHealth(diagnosticsUrl);
  }

  Future<int?> _readVerifiedPid() async {
    final pidPath =
        '${_defaultLogDir().path}${Platform.pathSeparator}p2wlan-daemon.pid';
    final file = File(pidPath);
    if (!await file.exists()) return null;
    final pid = int.tryParse((await file.readAsString()).trim());
    if (pid == null) return null;
    if (!await _processLooksLikeDaemon(pid)) return null;
    return pid;
  }

  Future<void> _clearPidMarkerForStart(String pidPath) async {
    final file = File(pidPath);
    if (!await file.exists()) return;
    try {
      await file.delete();
    } catch (error) {
      throw StateError(
        'PID marker could not be cleared before startup: $error',
      );
    }
  }

  /// Clean up only the process returned by this launch attempt. The identity
  /// check in `_terminatePid` prevents a stale/reused PID from being killed.
  Future<void> _cleanupFailedStartup(int? pid) async {
    final candidatePid = pid ?? await _readVerifiedPid();
    if (candidatePid == null) {
      await _removePidMarker();
      return;
    }
    if (await _processLooksLikeDaemon(candidatePid)) {
      // A failed startup must not trigger a second UAC prompt merely to
      // clean up. If the normal token cannot terminate an already elevated
      // child, leave the verified process for the next stale-daemon scan.
      final terminated = await _terminatePid(
        candidatePid,
        allowElevation: false,
      );
      if (terminated) {
        await _waitForDaemonPidExit(candidatePid, const Duration(seconds: 3));
      }
    }
    await _removePidMarker();
  }

  Future<int?> _diagnosticsProcessId(String diagnosticsUrl) async {
    try {
      final snapshot = await _diagnosticsApi.fetchStatus(diagnosticsUrl);
      final pid = snapshot.processId;
      if (pid == null) return null;
      if (Platform.isWindows &&
          await _windowsProcessName(pid) ==
              '${DaemonController.daemonBinaryName}.exe') {
        _authenticatedProcessId = pid;
      }
      if (!await _processLooksLikeDaemon(pid)) return null;
      return pid;
    } catch (_) {
      return null;
    }
  }

  Future<bool> _processLooksLikeDaemon(int pid) async {
    if (Platform.isWindows &&
        (pid == _authenticatedProcessId || pid == _launchedProcessId)) {
      return trustedWindowsDaemonIdentityMatches(
        pid: pid,
        launchedProcessId: _launchedProcessId,
        authenticatedProcessId: _authenticatedProcessId,
        processName: await _windowsProcessName(pid),
      );
    }
    final command = await _processCommandLine(pid);
    if (command != null) return _matchesInstance(command);
    return false;
  }

  Future<bool> _waitForDaemonPidExit(int pid, Duration timeout) async {
    if (Platform.isWindows) {
      // Do not start a new PowerShell process every 400 ms while a Windows
      // daemon is shutting down. One hidden PowerShell can poll the already
      // verified PID in-process, which removes a large source of UI stalls.
      final timeoutMs = timeout.inMilliseconds.clamp(1, 60000);
      final result = await _runWindowsPowerShell(
        '\$targetPid = $pid; '
        '\$deadline = [DateTime]::UtcNow.AddMilliseconds($timeoutMs); '
        'while ([DateTime]::UtcNow -lt \$deadline) { '
        'if (\$null -eq (Get-Process -Id \$targetPid -ErrorAction SilentlyContinue)) { '
        'return '
        '} '
        'Start-Sleep -Milliseconds 100 '
        '} '
        '\$global:LASTEXITCODE = 1',
      );
      return result.exitCode == 0;
    }
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (!await _processLooksLikeDaemon(pid)) return true;
      await Future<void>.delayed(DaemonController._readyPoll);
    }
    return !await _processLooksLikeDaemon(pid);
  }

  Future<bool> _waitForWindowsDaemonPidsExit(
    Iterable<int> pids,
    Duration timeout,
  ) async {
    for (final pid in pids.toSet()) {
      if (!await _waitForDaemonPidExit(pid, timeout)) return false;
    }
    return true;
  }

  Future<bool> _anyDaemonPidStillRunning(Iterable<int> pids) async {
    for (final pid in pids.toSet()) {
      if (await _processLooksLikeDaemon(pid)) return true;
    }
    return false;
  }

  Future<String?> _processCommandLine(int pid) async {
    if (Platform.isWindows) {
      final escapedPid = pid.toString();
      final result = await _runWindowsPowerShell(
        '(Get-CimInstance Win32_Process -Filter "ProcessId = $escapedPid").CommandLine',
      );
      if (result.exitCode != 0) return null;
      final command = result.stdout.toString().trim();
      return command.isEmpty ? null : command;
    }
    final result = await Process.run('ps', ['-p', '$pid', '-o', 'command=']);
    if (result.exitCode != 0) return null;
    final command = result.stdout.toString().trim();
    return command.isEmpty ? null : command;
  }

  Future<int?> _findDaemonPidByDiagnosticsBind(String bind) async {
    final matches = <int>[];
    if (Platform.isWindows) {
      final escapedBind = _powershellSingleQuote(bind);
      final result = await _runWindowsPowerShell(
        r'Get-CimInstance Win32_Process | '
        'Where-Object { \$_.CommandLine -like \'*p2wlan-daemon*\' -and \$_.CommandLine -like \'*--diagnostics-bind*\' -and \$_.CommandLine -like \'*$escapedBind*\' } | '
        r'Select-Object -ExpandProperty ProcessId',
      );
      if (result.exitCode != 0) return null;
      for (final line in result.stdout.toString().split('\n')) {
        final pid = int.tryParse(line.trim());
        if (pid != null) matches.add(pid);
      }
    } else {
      final result = await Process.run('ps', [
        'ax',
        '-o',
        'pid=',
        '-o',
        'command=',
      ]);
      if (result.exitCode != 0) return null;
      final currentPid = pid;
      for (final line in result.stdout.toString().split('\n')) {
        final trimmed = line.trimLeft();
        final splitAt = trimmed.indexOf(RegExp(r'\s'));
        if (splitAt <= 0) continue;
        final parsedPid = int.tryParse(trimmed.substring(0, splitAt).trim());
        if (parsedPid == null || parsedPid == currentPid) continue;
        final command = trimmed.substring(splitAt).trim();
        if (_matchesInstance(command) &&
            command.contains('--diagnostics-bind') &&
            command.contains(bind)) {
          matches.add(parsedPid);
        }
      }
    }
    final verified = <int>[];
    for (final candidate in matches) {
      if (await _processLooksLikeDaemon(candidate)) verified.add(candidate);
    }
    return verified.length == 1 ? verified.single : null;
  }

  Future<List<int>> _findWindowsDaemonPids({
    bool requireReliableScan = false,
  }) async {
    if (!Platform.isWindows) return const <int>[];
    final result = await _runWindowsPowerShell(
      '''@(Get-CimInstance Win32_Process -Filter "Name = 'p2wlan-daemon.exe'" -ErrorAction ${requireReliableScan ? 'Stop' : 'SilentlyContinue'}) | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress''',
    );
    if (result.exitCode != 0) {
      if (requireReliableScan) throw StateError('Room process query failed');
      return const <int>[];
    }
    try {
      if (result.stdout.toString().trim().isEmpty) return const <int>[];
      final decoded = jsonDecode(result.stdout.toString());
      final rows = decoded is List ? decoded : [decoded];
      if (requireReliableScan &&
          rows.any(
            (row) =>
                row is! Map ||
                row['ProcessId'] is! num ||
                row['CommandLine'] is! String,
          )) {
        throw StateError('Room process identity is unavailable');
      }
      return [
        for (final row in rows)
          if (row is Map &&
              row['ProcessId'] is num &&
              row['CommandLine'] is String &&
              _matchesInstance(row['CommandLine'] as String))
            (row['ProcessId'] as num).toInt(),
      ];
    } on FormatException {
      if (requireReliableScan) rethrow;
      return const <int>[];
    }
  }

  Future<int?> _findSingleDaemonPid() async {
    final matches = Platform.isWindows
        ? await _findWindowsDaemonPids()
        : await _findUnixDaemonPids();
    return matches.length == 1 ? matches.single : null;
  }

  Future<List<int>> _findUnixDaemonPids({
    bool requireReliableScan = false,
  }) async {
    final result = await Process.run('ps', [
      'ax',
      '-o',
      'pid=',
      '-o',
      'command=',
    ]);
    if (result.exitCode != 0) {
      if (requireReliableScan) throw StateError('Room process query failed');
      return const <int>[];
    }
    final matches = <int>[];
    for (final line in result.stdout.toString().split('\n')) {
      final match = RegExp(r'^\s*(\d+)\s+(.+)$').firstMatch(line);
      if (match == null || !_matchesInstance(match.group(2)!)) continue;
      final candidate = int.tryParse(match.group(1)!);
      if (candidate != null && candidate != pid) matches.add(candidate);
    }
    return matches;
  }

  bool _matchesInstance(String command) => daemonCommandMatchesLog(
    command,
    '${_defaultLogDir().path}${Platform.pathSeparator}p2wlan-daemon.log',
    windows: Platform.isWindows,
  );

  Future<String?> _windowsProcessName(int processId) async {
    if (!Platform.isWindows) return null;
    final result = await _runWindowsPowerShell(
      '\$process = Get-Process -Id $processId -ErrorAction SilentlyContinue; '
      'if (\$null -ne \$process) { \$process.ProcessName + ".exe" }',
    );
    if (result.exitCode != 0) return null;
    final name = result.stdout.toString().trim();
    return name.isEmpty ? null : name;
  }

  Future<bool> _terminatePid(int pid, {bool allowElevation = true}) async {
    if (!await _processLooksLikeDaemon(pid)) return false;
    if (Platform.isWindows) {
      // Keep taskkill hidden, then retry once through a hidden elevated
      // PowerShell if the old daemon was started with a higher integrity
      // level. This is what lets a normal P2WLAN launch clean up an older
      // administrator-launched daemon before starting its replacement.
      final result = await _runWindowsPowerShell(
        '& taskkill.exe /PID $pid /T /F',
      );
      if (result.exitCode == 0) return true;
      if (!allowElevation) return false;
      final elevated = await _runWindowsPowerShell(
        '\$ErrorActionPreference = \'Stop\'; '
        '\$killed = Start-Process -Verb RunAs -WindowStyle Hidden '
        '-FilePath \'taskkill.exe\' '
        '-ArgumentList \'/PID $pid /T /F\' -Wait -PassThru; '
        '\$global:LASTEXITCODE = \$killed.ExitCode',
      );
      return elevated.exitCode == 0;
    }
    if (await _sendUnixSignal(pid, 'TERM')) {
      if (await _waitForDaemonPidExit(pid, const Duration(seconds: 2))) {
        return true;
      }
      if (await _sendUnixSignal(pid, 'KILL')) {
        return _waitForDaemonPidExit(pid, const Duration(seconds: 2));
      }
    }
    if (Platform.isMacOS && !_isRootUser()) {
      try {
        final command = await _processCommandLine(pid);
        if (command == null || !_matchesInstance(command)) return false;
        final sameCommand =
            '[ "\$(/bin/ps -p ${_shellQuote('$pid')} -o command= '
            '2>/dev/null | /usr/bin/sed -e \'s/^[[:space:]]*//\' '
            '-e \'s/[[:space:]]*\$//\')" = ${_shellQuote(command)} ]';
        await _startMacosElevated(
          'if $sameCommand; then /bin/kill -TERM ${_shellQuote('$pid')}; fi; '
          '/bin/sleep 2; '
          'if $sameCommand; then /bin/kill -KILL ${_shellQuote('$pid')}; fi',
        );
        return await _waitForDaemonPidExit(pid, const Duration(seconds: 3));
      } catch (_) {
        return false;
      }
    }
    return false;
  }

  Future<bool> _sendUnixSignal(int pid, String signal) async {
    if (!await _processLooksLikeDaemon(pid)) return false;
    final result = await Process.run('kill', ['-$signal', '$pid']);
    return result.exitCode == 0;
  }

  Future<void> _removePidMarker() async {
    final pidPath =
        '${_defaultLogDir().path}${Platform.pathSeparator}p2wlan-daemon.pid';
    final file = File(pidPath);
    try {
      if (await file.exists()) await file.delete();
    } catch (_) {
      // Best effort cleanup; a root-owned marker must not turn a stopped
      // daemon into a reported failure.
    }
    // The launch token file is also removed once the daemon is stopped, so no
    // credential remains on disk after shutdown.
    try {
      await cleanupStaleLaunchTokenFiles(_defaultLogDir());
    } catch (_) {}
  }

  bool _isRootUser() {
    if (!Platform.isMacOS && !Platform.isLinux) return false;
    try {
      final result = Process.runSync('id', ['-u']);
      return result.exitCode == 0 && result.stdout.toString().trim() == '0';
    } catch (_) {
      return Platform.environment['USER'] == 'root';
    }
  }

  String _shellQuote(String value) => "'${value.replaceAll("'", "'\\''")}'";

  Future<bool> _isWindowsAdministrator() async {
    if (!Platform.isWindows) return false;
    final result = await _runWindowsPowerShell(
      '[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)',
    );
    return result.exitCode == 0 &&
        _equalsIgnoreCase(result.stdout.toString().trim(), 'true');
  }

  @visibleForTesting
  Future<ProcessResult> runWindowsPowerShellForTesting(
    String script, {
    Duration timeout = const Duration(seconds: 10),
  }) => _runWindowsPowerShell(script, timeout: timeout);

  /// Run a Windows helper as a normal short-lived child process.
  ///
  /// Flutter's Windows runner is a GUI process. The hidden window style keeps
  /// PowerShell invisible, while normal process mode gives us a reliable
  /// process exit code. Detached process modes cannot expose [exitCode], so
  /// they must not be used for helpers whose result controls startup.
  Future<ProcessResult> _runWindowsPowerShell(
    String script, {
    Duration timeout = const Duration(seconds: 10),
  }) async {
    final windir = Platform.environment['WINDIR']?.trim();
    final executable = windir == null || windir.isEmpty
        ? 'powershell.exe'
        : '$windir\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
    final wrappedScript =
        '\$utf8 = [System.Text.UTF8Encoding]::new(\$false); '
        '[Console]::OutputEncoding = \$utf8; '
        '\$OutputEncoding = \$utf8; '
        '\$ErrorActionPreference = \'Stop\'; '
        'try { & { $script }; '
        '\$exitCode = if (\$null -ne \$LASTEXITCODE) { '
        '[int]\$LASTEXITCODE } else { 0 } '
        '} catch { '
        '[Console]::Error.WriteLine(\$_.Exception.Message); '
        '\$exitCode = 1 '
        '} '
        'exit \$exitCode';

    Process? process;
    try {
      final started = await Process.start(executable, [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-WindowStyle',
        'Hidden',
        '-ExecutionPolicy',
        'Bypass',
        '-Command',
        wrappedScript,
      ], mode: ProcessStartMode.normal);
      process = started;

      const decoder = Utf8Decoder(allowMalformed: true);
      final stdoutFuture = started.stdout.transform(decoder).join();
      final stderrFuture = started.stderr.transform(decoder).join();
      final exitCodeFuture = started.exitCode;
      final valuesFuture = Future.wait<Object>([
        stdoutFuture,
        stderrFuture,
        exitCodeFuture,
      ]);
      final values = await valuesFuture.timeout(timeout);
      return ProcessResult(
        started.pid,
        values[2] as int,
        values[0] as String,
        values[1] as String,
      );
    } on TimeoutException {
      process?.kill();
      if (process != null) {
        // stdout/stderr already have active listeners above. Do not attach a
        // second listener here; just give the killed child a short window to
        // close those streams and complete the existing exit-code future.
        try {
          await process.exitCode.timeout(const Duration(seconds: 1));
        } on Object {
          // The timeout result below is the useful startup diagnostic.
        }
      }
      return ProcessResult(
        process?.pid ?? -1,
        1,
        '',
        'Windows helper timed out after ${timeout.inMilliseconds} milliseconds',
      );
    } catch (error) {
      return ProcessResult(process?.pid ?? -1, 1, '', error.toString());
    }
  }

  String _windowsCommandLineArgQuote(String value) {
    return windowsCommandLineArgQuote(value);
  }

  String _powershellSingleQuote(String value) {
    return value.replaceAll("'", "''");
  }

  String _powershellSingleQuoted(String value) {
    return "'${_powershellSingleQuote(value)}'";
  }

  String _powershellDoubleQuote(String value) {
    return '"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"';
  }

  bool _equalsIgnoreCase(String left, String right) =>
      left.toLowerCase() == right.toLowerCase();
}

/// Quote one argument using the Windows CRT command-line grammar. PowerShell
/// receives one `ArgumentList` string from `Start-Process`, so this preserves
/// spaces, trailing backslashes, quotes, and non-ASCII paths across that
/// boundary.
String windowsCommandLineArgQuote(String value) {
  if (value.isNotEmpty && !value.contains(RegExp(r'[\s"]'))) {
    return value;
  }
  final buffer = StringBuffer('"');
  var backslashes = 0;
  for (final codeUnit in value.codeUnits) {
    final char = String.fromCharCode(codeUnit);
    if (char == '\\') {
      backslashes += 1;
    } else if (char == '"') {
      buffer
        ..write(List.filled(backslashes * 2 + 1, '\\').join())
        ..write('"');
      backslashes = 0;
    } else {
      buffer
        ..write(List.filled(backslashes, '\\').join())
        ..write(char);
      backslashes = 0;
    }
  }
  buffer
    ..write(List.filled(backslashes * 2, '\\').join())
    ..write('"');
  return buffer.toString();
}