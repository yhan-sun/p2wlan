import 'dart:async';
import 'dart:io';

import '../api/diagnostics_api.dart';
import '../models/diagnostics_models.dart';

class DaemonCommandResult {
  const DaemonCommandResult({
    required this.ok,
    required this.message,
    this.manualCommand,
  });

  final bool ok;
  final String message;
  final String? manualCommand;
}

class DaemonController {
  DaemonController({required DiagnosticsApi diagnosticsApi})
    : _diagnosticsApi = diagnosticsApi;

  static const daemonBinaryName = 'p2wlan-daemon';
  static const envDaemonBin = 'P2WLAN_DAEMON_BIN';
  static const _readyPoll = Duration(milliseconds: 400);
  static const _macosReadyTimeout = Duration(seconds: 60);
  static const _directReadyTimeout = Duration(seconds: 20);

  final DiagnosticsApi _diagnosticsApi;

  Future<DaemonCommandResult> start(AppSettings settings) async {
    if (!_supportsProcessControl) {
      return const DaemonCommandResult(
        ok: false,
        message:
            'This platform does not support local daemon process control yet.',
      );
    }

    if (await _diagnosticsApi.fetchHealth(settings.diagnosticsUrl)) {
      return const DaemonCommandResult(
        ok: true,
        message: 'p2wlan-daemon is already running.',
      );
    }

    final binary = await _resolveDaemonBinary();
    if (binary == null) {
      return const DaemonCommandResult(
        ok: false,
        message:
            'Could not find p2wlan-daemon. Build it with cargo or set P2WLAN_DAEMON_BIN.',
      );
    }

    final bind = _diagnosticsBindFromStatusUrl(settings.diagnosticsUrl);
    final configPath = _defaultConfigPath();
    final logDir = _defaultLogDir();
    final logPath = '${logDir.path}${Platform.pathSeparator}p2wlan-daemon.log';
    final pidPath = '${logDir.path}${Platform.pathSeparator}p2wlan-daemon.pid';
    final authToken = settings.authToken.trim();
    final deviceName = settings.deviceName.trim();
    final useManualMode = settings.manualMode || authToken.isEmpty;
    final udpAdvertise = settings.udpAdvertise.trim();
    final relayServers = settings.relayServers.trim();
    final args = [
      '--config',
      configPath.path,
      '--control',
      settings.controlServer,
      '--network',
      settings.networkId.trim().isEmpty
          ? defaultNetworkId
          : settings.networkId.trim(),
      '--diagnostics-bind',
      bind,
      '--log-file',
      logPath,
      if (deviceName.isNotEmpty) ...['--device-name', deviceName],
      '--interface',
      settings.effectiveTunInterface,
      '--mtu',
      settings.mtu.toString(),
      '--udp-bind',
      settings.udpBind.trim().isEmpty
          ? defaultUdpBind
          : settings.udpBind.trim(),
      if (udpAdvertise.isNotEmpty) ...['--udp-advertise', udpAdvertise],
      if (settings.socketPool.trim().isNotEmpty) ...[
        '--socket-pool',
        settings.socketPool.trim(),
      ],
      if (relayServers.isNotEmpty) ...['--relay', relayServers],
      if (useManualMode) '--manual' else ...['--managed', '--token', authToken],
    ];

    await configPath.parent.create(recursive: true);
    await logDir.create(recursive: true);

    final elevatedShell = _buildElevatedShell(
      binary: binary,
      args: args,
      configDir: configPath.parent,
      logDir: logDir,
      logPath: logPath,
      pidPath: pidPath,
    );
    final manualCommand = _manualCommandForPlatform(
      elevatedShell: elevatedShell,
      binary: binary,
      args: args,
    );

    try {
      if (Platform.isMacOS && !_isRootUser()) {
        await _startMacosElevated(elevatedShell);
      } else if (Platform.isWindows && !await _isWindowsAdministrator()) {
        await _startWindowsElevated(binary: binary, args: args);
      } else if (Platform.isLinux && !_isRootUser()) {
        await _startLinuxElevated(binary: binary, args: args);
      } else {
        final process = await _startDetached(binary: binary, args: args);
        await _writePidMarker(pidPath, process.pid);
      }
    } catch (error) {
      return DaemonCommandResult(
        ok: false,
        message: _startFailureMessage(error),
        manualCommand: manualCommand,
      );
    }

    final timeout = Platform.isMacOS ? _macosReadyTimeout : _directReadyTimeout;
    final ready = await _waitForHealth(settings.diagnosticsUrl, timeout);
    if (!ready) {
      return DaemonCommandResult(
        ok: false,
        message:
            '已完成启动授权，但 p2wlan-daemon 没有在 ${timeout.inSeconds} 秒内响应诊断端点。请查看日志：$logPath',
        manualCommand: manualCommand,
      );
    }
    return DaemonCommandResult(
      ok: true,
      message: useManualMode
          ? 'p2wlan-daemon started in manual/offline mode. Add a control token in Settings to join the managed P2WLAN network.'
          : 'p2wlan-daemon started.',
    );
  }

  Future<DaemonCommandResult> stop(String diagnosticsUrl) async {
    if (!_supportsProcessControl) {
      return const DaemonCommandResult(
        ok: false,
        message:
            'This platform does not support local daemon process control yet.',
      );
    }

    final statusPid = await _diagnosticsProcessId(diagnosticsUrl);
    final shutdownRequested = await _diagnosticsApi.requestShutdown(
      diagnosticsUrl,
    );
    if (shutdownRequested) {
      final endpointDown = await _waitForHealthDown(
        diagnosticsUrl,
        const Duration(seconds: 8),
      );
      final processDown =
          statusPid == null ||
          await _waitForDaemonPidExit(statusPid, const Duration(seconds: 3));
      if (endpointDown && processDown) {
        await _removePidMarker();
        return const DaemonCommandResult(
          ok: true,
          message: 'p2wlan-daemon stopped.',
        );
      }
    }

    final diagnosticsBind = _diagnosticsBindFromStatusUrl(diagnosticsUrl);
    final candidatePids = <int?>[
      statusPid,
      await _readVerifiedPid(),
      await _findDaemonPidByDiagnosticsBind(diagnosticsBind),
      await _findSingleDaemonPid(),
    ];
    final attempted = <int>{};
    for (final pid in candidatePids.whereType<int>()) {
      if (!attempted.add(pid)) continue;
      if (!await _processLooksLikeDaemon(pid)) continue;
      if (!await _terminatePid(pid)) continue;
      final processDown = await _waitForDaemonPidExit(
        pid,
        const Duration(seconds: 3),
      );
      final stopped = await _waitForHealthDown(
        diagnosticsUrl,
        const Duration(seconds: 5),
      );
      if (stopped && processDown) {
        await _removePidMarker();
        return DaemonCommandResult(ok: true, message: 'p2wlan-daemon stopped.');
      }
    }

    final knownPids = [statusPid, ...attempted].whereType<int>();
    final knownProcessesDown = !await _anyDaemonPidStillRunning(knownPids);
    if (!await _diagnosticsApi.fetchHealth(diagnosticsUrl) &&
        knownProcessesDown) {
      await _removePidMarker();
      return const DaemonCommandResult(
        ok: true,
        message: 'p2wlan-daemon stopped.',
      );
    }

    if (attempted.isEmpty) {
      return DaemonCommandResult(
        ok: false,
        message: shutdownRequested
            ? 'Requested daemon shutdown, but diagnostics is still reachable and no safe p2wlan-daemon PID could be found.'
            : 'Could not stop p2wlan-daemon: diagnostics is reachable but no safe p2wlan-daemon PID could be found.',
      );
    }

    return DaemonCommandResult(
      ok: false,
      message:
          'Tried to stop p2wlan-daemon PID(s) ${attempted.join(', ')}, but diagnostics is still reachable.',
    );
  }

  bool get _supportsProcessControl {
    return Platform.isMacOS || Platform.isLinux || Platform.isWindows;
  }

  Future<File?> _resolveDaemonBinary() async {
    final envPath = Platform.environment[envDaemonBin];
    if (envPath != null && envPath.trim().isNotEmpty) {
      final file = File(envPath.trim());
      if (await file.exists()) return file;
    }

    final names = _binaryNames;
    final candidates = <File>[];
    final executable = File(Platform.resolvedExecutable);
    final exeDir = executable.parent;
    for (final name in names) {
      candidates.add(File('${exeDir.path}${Platform.pathSeparator}$name'));
      final contents = exeDir.parent;
      candidates.add(
        File(
          '${contents.path}${Platform.pathSeparator}Resources${Platform.pathSeparator}$name',
        ),
      );
    }

    var dir = Directory.current;
    for (var depth = 0; depth < 6; depth += 1) {
      for (final name in names) {
        candidates.add(
          File('${dir.path}${Platform.pathSeparator}target/debug/$name'),
        );
        candidates.add(
          File('${dir.path}${Platform.pathSeparator}target/release/$name'),
        );
      }
      final parent = dir.parent;
      if (parent.path == dir.path) break;
      dir = parent;
    }

    for (final candidate in candidates) {
      if (await candidate.exists()) return candidate;
    }

    for (final name in names) {
      final found = await _which(name);
      if (found != null) return found;
    }
    return null;
  }

  List<String> get _binaryNames {
    final extension = Platform.isWindows ? '.exe' : '';
    return ['$daemonBinaryName$extension'];
  }

  Future<File?> _which(String name) async {
    final executable = Platform.isWindows ? 'where' : 'which';
    final result = await Process.run(executable, [name]);
    if (result.exitCode != 0) return null;
    final first = result.stdout.toString().split('\n').first.trim();
    if (first.isEmpty) return null;
    final file = File(first);
    return file.existsSync() ? file : null;
  }

  Future<Process> _startDetached({
    required File binary,
    required List<String> args,
  }) async {
    return Process.start(
      binary.path,
      args,
      mode: ProcessStartMode.detached,
      environment: {'P2WLAN_DAEMON_BIN': binary.path},
    );
  }

  Future<void> _writePidMarker(String pidPath, int pid) async {
    try {
      final file = File(pidPath);
      await file.parent.create(recursive: true);
      await file.writeAsString('$pid');
    } catch (_) {
      // Best-effort only; stop() can still recover by diagnostics process id.
    }
  }

  String _buildElevatedShell({
    required File binary,
    required List<String> args,
    required Directory configDir,
    required Directory logDir,
    required String logPath,
    required String pidPath,
  }) {
    final repairOwnership = _macosRepairOwnershipShell(configDir, logDir);
    final repairBefore = repairOwnership.isEmpty ? '' : '$repairOwnership; ';
    final repairAfter = repairOwnership.isEmpty
        ? ''
        : '; /bin/sleep 1; $repairOwnership';
    final terminateExisting = _macosTerminateRecordedDaemonShell(pidPath);
    return 'mkdir -p ${_shellQuote(configDir.path)} ${_shellQuote(logDir.path)}; '
        '$repairBefore'
        '$terminateExisting'
        ': > ${_shellQuote(logPath)}; chmod 644 ${_shellQuote(logPath)}; '
        '(P2WLAN_DAEMON_BIN=${_shellQuote(binary.path)} '
        '${_shellQuote(binary.path)} ${args.map(_shellQuote).join(' ')} '
        '>> ${_shellQuote(logPath)} 2>&1 < /dev/null & echo \$! > ${_shellQuote(pidPath)})'
        '$repairAfter';
  }

  String _macosTerminateRecordedDaemonShell(String pidPath) {
    if (!Platform.isMacOS) return '';
    final quotedPidPath = _shellQuote(pidPath);
    return 'if [ -f $quotedPidPath ]; then '
        'oldpid="\$(/bin/cat $quotedPidPath 2>/dev/null || true)"; '
        'case "\$oldpid" in ""|*[!0-9]*) ;; *) '
        'if /bin/ps -p "\$oldpid" -o command= 2>/dev/null | /usr/bin/grep -q p2wlan-daemon; then '
        '/bin/kill "\$oldpid" >/dev/null 2>&1 || true; /bin/sleep 1; '
        'fi ;; esac; fi; ';
  }

  String _macosRepairOwnershipShell(Directory configDir, Directory logDir) {
    if (!Platform.isMacOS) return '';
    final owner = _macosUserOwnerForUserPaths();
    if (owner == null || owner.isEmpty || owner == 'root') return '';
    final quotedOwner = _shellQuote(owner);
    final quotedConfigDir = _shellQuote(configDir.path);
    final quotedLogDir = _shellQuote(logDir.path);
    return 'owner=$quotedOwner; '
        'group="\$(/usr/bin/id -gn "\$owner" 2>/dev/null || /bin/echo staff)"; '
        '/usr/sbin/chown -R "\$owner:\$group" $quotedConfigDir $quotedLogDir >/dev/null 2>&1 || true';
  }

  String? _macosUserOwnerForUserPaths() {
    for (final key in const ['SUDO_USER', 'USER', 'LOGNAME']) {
      final value = Platform.environment[key]?.trim();
      if (value != null && value.isNotEmpty && value != 'root') {
        return value;
      }
    }
    final home = Platform.environment['HOME']?.trim();
    if (home == null || home.isEmpty || home == '/var/root') return null;
    final parts = home.split('/').where((part) => part.isNotEmpty).toList();
    if (parts.isEmpty) return null;
    final user = parts.last.trim();
    if (user.isEmpty || user == 'root') return null;
    return user;
  }

  Future<void> _startMacosElevated(String command) async {
    await _runMacosElevated(
      command,
      'p2wlan 需要管理员权限以创建虚拟网卡并安装 Overlay 路由。p2wlan 不会读取或保存你的密码。',
    );
  }

  Future<void> _runMacosElevated(String command, String prompt) async {
    final script =
        'do shell script "${_appleScriptQuote(command)}" '
        'with administrator privileges '
        'with prompt "${_appleScriptQuote(prompt)}"';
    final result = await Process.run('osascript', ['-e', script]);
    if (result.exitCode != 0) {
      final stderr = result.stderr.toString().trim();
      if (stderr.contains('-128')) {
        throw '已取消管理员授权。';
      }
      throw stderr.isEmpty ? '管理员授权启动失败。' : stderr;
    }
  }

  String _manualSudoCommand(String elevatedShell) {
    return 'sudo /bin/sh -c ${_shellQuote(elevatedShell)}';
  }

  String? _manualCommandForPlatform({
    required String elevatedShell,
    required File binary,
    required List<String> args,
  }) {
    if ((Platform.isMacOS || Platform.isLinux) && !_isRootUser()) {
      return _manualSudoCommand(elevatedShell);
    }
    if (Platform.isWindows) {
      final argLine = args.map(_windowsCommandLineArgQuote).join(' ');
      return 'powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath ${_powershellDoubleQuote(binary.path)} -ArgumentList ${_powershellDoubleQuote(argLine)}"';
    }
    return null;
  }

  Future<void> _startLinuxElevated({
    required File binary,
    required List<String> args,
  }) async {
    final pkexec = await _which('pkexec');
    if (pkexec == null) {
      throw '当前 Linux 桌面未找到 pkexec。请复制 sudo 命令手动启动，或使用 setcap 给 p2wlan-daemon 添加 CAP_NET_ADMIN。';
    }
    await Process.start(pkexec.path, [
      'env',
      '$envDaemonBin=${binary.path}',
      binary.path,
      ...args,
    ], mode: ProcessStartMode.detached);
  }

  Future<void> _startWindowsElevated({
    required File binary,
    required List<String> args,
  }) async {
    final argLine = args.map(_windowsCommandLineArgQuote).join(' ');
    final script =
        'Start-Process -Verb RunAs -WindowStyle Hidden '
        '-FilePath ${_powershellSingleQuoted(binary.path)} '
        '-ArgumentList ${_powershellSingleQuoted(argLine)}';
    final result = await Process.run('powershell', [
      '-NoProfile',
      '-ExecutionPolicy',
      'Bypass',
      '-Command',
      script,
    ]);
    if (result.exitCode != 0) {
      final stderr = result.stderr.toString().trim();
      throw stderr.isEmpty ? 'Windows UAC 启动失败。' : stderr;
    }
  }

  String _startFailureMessage(Object error) {
    final raw = error.toString().trim();
    final normalized = raw.toLowerCase();
    if (raw.contains('1273') ||
        raw.contains('用户名或密码不正确') ||
        normalized.contains('user name or password') ||
        normalized.contains('username or password') ||
        normalized.contains('password was incorrect')) {
      return '管理员认证失败：请在 macOS 系统弹窗中输入当前 Mac 的管理员账号和密码；如果当前账号不是管理员，请使用管理员账号授权。';
    }
    if (raw.contains('-128') ||
        raw.contains('已取消') ||
        normalized.contains('cancel')) {
      return '已取消管理员授权，p2wlan-daemon 未启动。';
    }
    if (normalized.contains('operation not permitted') ||
        normalized.contains('not permitted') ||
        normalized.contains('sandbox')) {
      return '系统拒绝启动 p2wlan-daemon：请使用未启用 App Sandbox 的 P2WLAN 构建版本，或复制 sudo 命令手动启动。原始错误：$raw';
    }
    return '无法启动 p2wlan-daemon：$raw';
  }

  Future<bool> _waitForHealth(String diagnosticsUrl, Duration timeout) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (await _diagnosticsApi.fetchHealth(diagnosticsUrl)) return true;
      await Future<void>.delayed(_readyPoll);
    }
    return _diagnosticsApi.fetchHealth(diagnosticsUrl);
  }

  Future<bool> _waitForHealthDown(
    String diagnosticsUrl,
    Duration timeout,
  ) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (!await _diagnosticsApi.fetchHealth(diagnosticsUrl)) return true;
      await Future<void>.delayed(_readyPoll);
    }
    return !await _diagnosticsApi.fetchHealth(diagnosticsUrl);
  }

  String _diagnosticsBindFromStatusUrl(String diagnosticsUrl) {
    final parsed = Uri.parse(normalizeDiagnosticsUrl(diagnosticsUrl));
    final host = parsed.host.contains(':') ? '[${parsed.host}]' : parsed.host;
    return '$host:${parsed.port}';
  }

  File _defaultConfigPath() {
    final override = Platform.environment['P2WLAN_CONFIG'];
    if (override != null && override.trim().isNotEmpty) {
      return File(override.trim());
    }
    return File(
      '${_configBaseDir().path}${Platform.pathSeparator}p2wlan-config.json',
    );
  }

  Directory _configBaseDir() {
    if (Platform.isMacOS) {
      final home = Platform.environment['HOME'];
      if (home != null && home.isNotEmpty) {
        return Directory('$home/Library/Application Support/p2wlan');
      }
    }
    if (Platform.isWindows) {
      final appData = Platform.environment['APPDATA'];
      if (appData != null && appData.isNotEmpty) {
        return Directory('$appData\\p2wlan');
      }
    }
    final xdg = Platform.environment['XDG_CONFIG_HOME'];
    if (xdg != null && xdg.isNotEmpty) return Directory('$xdg/p2wlan');
    final home = Platform.environment['HOME'];
    if (home != null && home.isNotEmpty) {
      return Directory('$home/.config/p2wlan');
    }
    return Directory(
      '${Directory.systemTemp.path}${Platform.pathSeparator}p2wlan',
    );
  }

  Directory _defaultLogDir() {
    if (Platform.isMacOS) {
      final home = Platform.environment['HOME'];
      if (home != null && home.isNotEmpty) {
        return Directory('$home/Library/Logs/p2wlan');
      }
    }
    if (Platform.isWindows) {
      final localAppData = Platform.environment['LOCALAPPDATA'];
      if (localAppData != null && localAppData.isNotEmpty) {
        return Directory('$localAppData\\p2wlan\\logs');
      }
    }
    final home = Platform.environment['HOME'];
    if (home != null && home.isNotEmpty) {
      return Directory('$home/.local/state/p2wlan');
    }
    return Directory(
      '${Directory.systemTemp.path}${Platform.pathSeparator}p2wlan',
    );
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
    return command != null && command.contains(daemonBinaryName);
  }

  Future<bool> _waitForDaemonPidExit(int pid, Duration timeout) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (!await _processLooksLikeDaemon(pid)) return true;
      await Future<void>.delayed(_readyPoll);
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
        if (command.contains(daemonBinaryName) &&
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
        if (command.contains(daemonBinaryName)) {
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
        return _waitForDaemonPidExit(pid, const Duration(seconds: 3));
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
