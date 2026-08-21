part of '../daemon_controller.dart';

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
    return 'mkdir -p ${_shellQuote(configDir.path)} ${_shellQuote(logDir.path)}; '
        '$repairBefore'
        '$terminateExisting'
        ': > ${_shellQuote(logPath)}; chmod 600 ${_shellQuote(logPath)}; '
        '$repairBefore'
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
    final credentials = _MacosElevationCredentials();
    try {
      if (!await credentials.hasStoredPassword()) {
        final saved = await credentials.promptAndStorePassword();
        if (!saved) throw '已取消保存管理员密码。';
      }

      var run = await credentials.runWithStoredPassword(command);
      if (run.missingCredential || run.authenticationFailed) {
        // A password can be removed from Keychain or changed outside P2WLAN.
        // Forget the stale item and allow exactly one fresh secure prompt.
        await credentials.clearStoredPassword();
        final saved = await credentials.promptAndStorePassword();
        if (!saved) throw '已取消保存管理员密码。';
        run = await credentials.runWithStoredPassword(command);
      }
      if (!run.ok) {
        throw run.error ?? '管理员权限启动失败。';
      }
    } on MissingPluginException {
      throw '当前 macOS 构建不支持安全管理员凭据存储，请重新安装 P2WLAN。';
    } on PlatformException catch (error) {
      throw error.message?.trim().isNotEmpty == true
          ? error.message!.trim()
          : '无法访问 macOS 登录钥匙串。';
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

  Future<void> _startWindowsElevated({
    required File binary,
    required List<String> args,
  }) async {
    final argLine = args.map(_windowsCommandLineArgQuote).join(' ');
    final script =
        '\$ErrorActionPreference = \'Stop\'; '
        'Start-Process -Verb RunAs -WindowStyle Hidden '
        '-WorkingDirectory ${_powershellSingleQuoted(binary.parent.path)} '
        '-FilePath ${_powershellSingleQuoted(binary.path)} '
        '-ArgumentList ${_powershellSingleQuoted(argLine)} | Out-Null';
    final result = await _runWindowsPowerShell(script);
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
      return '管理员认证失败：已保存的 macOS 管理员密码无效，请重新启动并输入当前管理员密码。';
    }
    if (raw.contains('-128') ||
        raw.contains('已取消') ||
        normalized.contains('cancel')) {
      return '已取消管理员密码保存，p2wlan-daemon 未启动。';
    }
    if (Platform.isWindows) {
      if (normalized.contains('access denied') ||
          normalized.contains('permission') ||
          normalized.contains('elevation')) {
        return 'Windows UAC 启动失败：当前账户没有启动虚拟网卡所需的权限，请确认已允许管理员授权。';
      }
      return 'Windows UAC 启动失败：请确认 P2WLAN 安装包完整，并允许一次管理员授权。';
    }
    if (normalized.contains('operation not permitted') ||
        normalized.contains('not permitted') ||
        normalized.contains('sandbox')) {
      return '系统拒绝启动 p2wlan-daemon：请使用未启用 App Sandbox 的 P2WLAN 构建版本，或复制 sudo 命令手动启动。原始错误：$raw';
    }
    return '无法启动 p2wlan-daemon：$raw';
  }
}

/// The macOS implementation deliberately keeps the password inside the
/// native Keychain/privilege boundary. Dart receives only a success result;
/// the password is never put in a Dart string, process argument, environment
/// variable, settings file, or log.
class _MacosElevationCredentials {
  static const _channel = MethodChannel('p2wlan/macos_elevation');

  Future<bool> hasStoredPassword() async {
    return await _channel.invokeMethod<bool>('hasStoredPassword') ?? false;
  }

  Future<bool> promptAndStorePassword() async {
    return await _channel.invokeMethod<bool>('promptAndStorePassword') ?? false;
  }

  Future<_MacosElevationRunResult> runWithStoredPassword(String command) async {
    final result = await _channel.invokeMapMethod<String, dynamic>(
      'runWithStoredPassword',
      <String, Object>{'command': command},
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

  Future<void> clearStoredPassword() async {
    await _channel.invokeMethod<void>('clearStoredPassword');
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
