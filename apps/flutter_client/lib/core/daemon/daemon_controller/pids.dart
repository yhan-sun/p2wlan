part of '../daemon_controller.dart';

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

  Future<int?> _diagnosticsProcessId(String diagnosticsUrl) async {
    try {
      final snapshot = await _diagnosticsApi.fetchStatus(diagnosticsUrl);
      final pid = snapshot.processId;
      if (pid == null) return null;
      if (!await _processLooksLikeDaemon(pid)) return null;
      return pid;
    } catch (_) {
      return null;
    }
  }

  Future<bool> _processLooksLikeDaemon(int pid) async {
    final command = await _processCommandLine(pid);
    return command != null &&
        command.contains(DaemonController.daemonBinaryName);
  }

  Future<bool> _waitForDaemonPidExit(int pid, Duration timeout) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (!await _processLooksLikeDaemon(pid)) return true;
      await Future<void>.delayed(DaemonController._readyPoll);
    }
    return !await _processLooksLikeDaemon(pid);
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
      final result = await Process.run('powershell', [
        '-NoProfile',
        '-Command',
        '(Get-CimInstance Win32_Process -Filter "ProcessId = $escapedPid").CommandLine',
      ]);
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
      final result = await Process.run('powershell', [
        '-NoProfile',
        '-Command',
        r'Get-CimInstance Win32_Process | '
            'Where-Object { \$_.CommandLine -like \'*p2wlan-daemon*\' -and \$_.CommandLine -like \'*--diagnostics-bind*\' -and \$_.CommandLine -like \'*$escapedBind*\' } | '
            r'Select-Object -ExpandProperty ProcessId',
      ]);
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
        if (command.contains(DaemonController.daemonBinaryName) &&
            command.contains('--diagnostics-bind') &&
            command.contains(bind)) {
          matches.add(parsedPid);
        }
      }
    }
    return matches.length == 1 ? matches.single : null;
  }

  Future<int?> _findSingleDaemonPid() async {
    final matches = <int>[];
    if (Platform.isWindows) {
      final result = await Process.run('powershell', [
        '-NoProfile',
        '-Command',
        r'Get-CimInstance Win32_Process | '
            r"Where-Object { $_.CommandLine -like '*p2wlan-daemon*' } | "
            r'Select-Object -ExpandProperty ProcessId',
      ]);
      if (result.exitCode != 0) return null;
      for (final line in result.stdout.toString().split('\n')) {
        final parsedPid = int.tryParse(line.trim());
        if (parsedPid != null) matches.add(parsedPid);
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
        if (command.contains(DaemonController.daemonBinaryName)) {
          matches.add(parsedPid);
        }
      }
    }
    return matches.length == 1 ? matches.single : null;
  }

  Future<bool> _terminatePid(int pid) async {
    if (Platform.isWindows) {
      final result = await Process.run('taskkill', [
        '/PID',
        '$pid',
        '/T',
        '/F',
      ]);
      return result.exitCode == 0;
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
        await _runMacosElevated(
          '/bin/kill -TERM ${_shellQuote('$pid')}; '
              '/bin/sleep 2; '
              'if /bin/ps -p ${_shellQuote('$pid')} -o command= 2>/dev/null | '
              '/usr/bin/grep -q p2wlan-daemon; then '
              '/bin/kill -KILL ${_shellQuote('$pid')}; '
              'fi',
          'p2wlan 需要管理员权限停止后台 p2wlan-daemon。',
        );
        return await _waitForDaemonPidExit(pid, const Duration(seconds: 3));
      } catch (_) {
        return false;
      }
    }
    return false;
  }

  Future<bool> _sendUnixSignal(int pid, String signal) async {
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
    final result = await Process.run('net', ['session']);
    return result.exitCode == 0;
  }

  String _windowsCommandLineArgQuote(String value) {
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
          ..write(_repeat('\\', backslashes * 2 + 1))
          ..write('"');
        backslashes = 0;
      } else {
        buffer
          ..write(_repeat('\\', backslashes))
          ..write(char);
        backslashes = 0;
      }
    }
    buffer
      ..write(_repeat('\\', backslashes * 2))
      ..write('"');
    return buffer.toString();
  }

  String _repeat(String value, int count) => List.filled(count, value).join();

  String _powershellSingleQuote(String value) {
    return value.replaceAll("'", "''");
  }

  String _powershellSingleQuoted(String value) {
    return "'${_powershellSingleQuote(value)}'";
  }

  String _powershellDoubleQuote(String value) {
    return '"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"';
  }

  String _appleScriptQuote(String value) {
    return value.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
  }
}
