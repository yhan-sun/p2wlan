part of '../daemon_controller.dart';

const _windowsChildPidMarker = '__P2WLAN_CHILD_PID__=';

/// Parse the marker emitted by the single elevated `Start-Process -PassThru`
/// launch. Keeping this pure makes PID supervision testable without running
/// UAC or PowerShell on the Dart test host.
int? parseWindowsChildPidMarker(String output) {
  for (final line in output.split(RegExp(r'[\r\n]+'))) {
    final value = line.trim();
    if (!value.startsWith(_windowsChildPidMarker)) continue;
    final pid = int.tryParse(
      value.substring(_windowsChildPidMarker.length).trim(),
    );
    if (pid != null && pid > 0) return pid;
  }
  return null;
}

DaemonStartupFailure classifyWindowsLaunchFailure(String rawError) {
  final raw = rawError.trim();
  final normalized = raw.toLowerCase();
  final cancelled =
      raw.contains('1223') ||
      raw.contains('0x800704c7') ||
      raw.contains('已取消') ||
      normalized.contains('cancel') ||
      normalized.contains('canceled') ||
      normalized.contains('cancelled');
  if (cancelled) {
    return const DaemonStartupFailure(
      DaemonStartupFailureCode.uacCancelled,
      '已取消 Windows 管理员授权，p2wlan-daemon 未启动。',
    );
  }
  if (raw.contains('PID_MARKER_FAILED')) {
    return const DaemonStartupFailure(
      DaemonStartupFailureCode.pidMarkerFailed,
      '无法写入或验证 elevated daemon 的 PID 标记文件。',
    );
  }
  if (raw.contains('ACL') ||
      normalized.contains('icacls') ||
      normalized.contains('permission')) {
    return const DaemonStartupFailure(
      DaemonStartupFailureCode.aclFailure,
      '无法为当前用户和本地 Administrators 组设置安全运行目录权限。',
    );
  }
  return const DaemonStartupFailure(
    DaemonStartupFailureCode.uacLaunchFailed,
    'Windows UAC 启动失败：请确认已允许管理员授权，并检查发布包完整性。',
  );
}

extension DaemonControllerElevation on DaemonController {
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
    final rotateLog = _macosRotateLogShell(logPath);
    return 'mkdir -p ${_shellQuote(configDir.path)} ${_shellQuote(logDir.path)}; '
        '$repairBefore'
        '$terminateExisting'
        '$rotateLog'
        ': > ${_shellQuote(logPath)}; chmod 600 ${_shellQuote(logPath)}; '
        '$repairBefore'
        '(P2WLAN_DAEMON_BIN=${_shellQuote(binary.path)} '
        '${_shellQuote(binary.path)} ${args.map(_shellQuote).join(' ')} '
        '>> ${_shellQuote(logPath)} 2>&1 < /dev/null & echo \$! > ${_shellQuote(pidPath)})'
        '$repairAfter';
  }

  String _macosRotateLogShell(String logPath) {
    if (!Platform.isMacOS) return '';
    final current = _shellQuote(logPath);
    final previous = _shellQuote('$logPath.1');
    return 'if [ -f $current ]; then '
        '/bin/rm -f $previous || exit 72; '
        '/bin/mv $current $previous || exit 73; '
        'fi; ';
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

  Future<void> _startMacosElevated(String command, {String? password}) async {
    final credentials = _MacosElevationCredentials();
    try {
      var activePassword = password;
      var shouldPersistPassword = false;
      activePassword ??= readMacosAdminPassword?.call();
      if (activePassword == null || activePassword.isEmpty) {
        final promptedPassword = await credentials.promptPassword();
        if (promptedPassword == null || promptedPassword.isEmpty) {
          throw '已取消保存管理员密码。';
        }
        activePassword = promptedPassword;
        shouldPersistPassword = true;
      }

      var run = await credentials.runWithPassword(command, activePassword);
      if (run.missingCredential || run.authenticationFailed) {
        // The locally saved password may have changed. Forget the encrypted
        // config value and allow exactly one fresh prompt; never loop.
        await clearMacosAdminPassword?.call();
        final freshPassword = await credentials.promptPassword();
        if (freshPassword == null || freshPassword.isEmpty) {
          throw '已取消保存管理员密码。';
        }
        activePassword = freshPassword;
        shouldPersistPassword = true;
        run = await credentials.runWithPassword(command, freshPassword);
      }
      if (!run.ok) {
        throw run.error ?? '管理员权限启动失败。';
      }
      if (shouldPersistPassword) {
        await saveMacosAdminPassword?.call(activePassword);
      }
    } on MissingPluginException {
      throw '当前 macOS 构建不支持本地管理员凭据存储，请重新安装 P2WLAN。';
    } on PlatformException catch (error) {
      throw error.message?.trim().isNotEmpty == true
          ? error.message!.trim()
          : '无法访问本地管理员凭据配置。';
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
      '${DaemonController.envDaemonBin}=${binary.path}',
      binary.path,
      ...args,
    ], mode: ProcessStartMode.detached);
  }

  Future<int> _startWindowsElevated({
    required File binary,
    required List<String> args,
    required String pidPath,
  }) async {
    final argLine = args.map(windowsCommandLineArgQuote).join(' ');
    final script =
        '\$ErrorActionPreference = \'Stop\'; '
        '\$child = Start-Process -Verb RunAs -WindowStyle Hidden '
        '-WorkingDirectory ${_powershellSingleQuoted(binary.parent.path)} '
        '-FilePath ${_powershellSingleQuoted(binary.path)} '
        '-ArgumentList ${_powershellSingleQuoted(argLine)} -PassThru; '
        // The ACL grants the local Administrators group access to this file,
        // so an alternate UAC account can publish the marker. A marker write
        // failure is launch-fatal: without the exact child PID, cleanup could
        // target the wrong process.
        'Set-Content -LiteralPath ${_powershellSingleQuoted(pidPath)} '
        '-Value ([string]\$child.Id) -Encoding ascii -Force; '
        'Write-Output \'$_windowsChildPidMarker\' + [string]\$child.Id';
    final result = await _runWindowsPowerShell(script);
    if (result.exitCode != 0) {
      final stderr = result.stderr.toString().trim();
      throw StateError(stderr.isEmpty ? 'Windows UAC 启动失败。' : stderr);
    }
    final pid = parseWindowsChildPidMarker(result.stdout.toString());
    if (pid != null) return pid;
    throw StateError(
      'PID_MARKER_FAILED: Windows UAC did not return the elevated child PID.',
    );
  }

  Future<String?> _windowsCurrentUserSid() async {
    if (!Platform.isWindows) return null;
    final result = await _runWindowsPowerShell(
      '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
    );
    if (result.exitCode != 0) return null;
    final sid = result.stdout.toString().trim();
    return RegExp(r'^S-\d-\d+(?:-\d+)+$').hasMatch(sid) ? sid : null;
  }

  String _startFailureMessage(Object error) {
    final raw = error.toString().trim();
    final normalized = raw.toLowerCase();
    if (Platform.isWindows) {
      final failure = classifyWindowsLaunchFailure(raw);
      return '[${failure.codeValue}] ${failure.message}';
    }
    if (raw.contains('1273') ||
        raw.contains('用户名或密码不正确') ||
        normalized.contains('user name or password') ||
        normalized.contains('username or password') ||
        normalized.contains('password was incorrect')) {
      return '管理员认证失败：配置文件中的 macOS 管理员密码无效，请重新启动并输入当前管理员密码。';
    }
    if (raw.contains('-128') ||
        raw.contains('已取消') ||
        normalized.contains('cancel')) {
      return '已取消管理员密码保存，p2wlan-daemon 未启动。';
    }
    if (normalized.contains('operation not permitted') ||
        normalized.contains('not permitted') ||
        normalized.contains('sandbox')) {
      return '系统拒绝启动 p2wlan-daemon：请使用未启用 App Sandbox 的 P2WLAN 构建版本，或复制 sudo 命令手动启动。原始错误：$raw';
    }
    return '无法启动 p2wlan-daemon：$raw';
  }
}

/// The native bridge only displays the secure input field and pipes the
/// password to sudo. Persistence is owned by [SettingsStore], which writes
/// authenticated ciphertext to the local settings file; no Keychain API is
/// involved.
class _MacosElevationCredentials {
  static const _channel = MethodChannel('p2wlan/macos_elevation');

  Future<String?> promptPassword() async {
    return _channel.invokeMethod<String>('promptPassword');
  }

  Future<_MacosElevationRunResult> runWithPassword(
    String command,
    String password,
  ) async {
    final result = await _channel.invokeMapMethod<String, dynamic>(
      'runWithPassword',
      <String, Object>{'command': command, 'password': password},
    );
    if (result == null) {
      return const _MacosElevationRunResult(
        ok: false,
        error: 'macOS 提权执行没有返回结果。',
      );
    }
    return _MacosElevationRunResult(
      ok: result['ok'] == true,
      missingCredential: result['missingCredential'] == true,
      authenticationFailed: result['authenticationFailed'] == true,
      error: (result['error'] as String?)?.trim(),
    );
  }
}

class _MacosElevationRunResult {
  const _MacosElevationRunResult({
    required this.ok,
    this.missingCredential = false,
    this.authenticationFailed = false,
    this.error,
  });

  final bool ok;
  final bool missingCredential;
  final bool authenticationFailed;
  final String? error;
}
