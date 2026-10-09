part of '../daemon_controller.dart';

const _windowsChildPidMarker = '__P2WLAN_CHILD_PID__=';
const _posixChildPidMarker = '__P2WLAN_POSIX_CHILD_PID__=';

/// The elevated shell returns only the launched PID. Log rotation and PID
/// file writes belong to the interactive user; the daemon owns its fd-safe
/// log writer and config persistence.
String buildPosixDaemonLaunchShell(String binaryPath, List<String> args) {
  String quote(String value) => "'${value.replaceAll("'", "'\\''")}'";
  return '(P2WLAN_DAEMON_BIN=${quote(binaryPath)} '
      '${quote(binaryPath)} ${args.map(quote).join(' ')} '
      '> /dev/null 2>&1 < /dev/null & '
      'printf \'$_posixChildPidMarker%s\\n\' "\$!")';
}

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
      normalized.contains('permission') ||
      normalized.contains('拒绝访问') ||
      normalized.contains('errno = 5') ||
      normalized.contains('os error: 5') ||
      normalized.contains('pathaccessexception') ||
      normalized.contains('unauthorizedaccessexception')) {
    return const DaemonStartupFailure(
      DaemonStartupFailureCode.aclFailure,
      '无法为当前用户和本地 Administrators 组设置安全运行目录权限或访问日志。',
    );
  }
  if (normalized.contains('timed out') || normalized.contains('超时')) {
    return const DaemonStartupFailure(
      DaemonStartupFailureCode.uacLaunchFailed,
      'Windows UAC 授权等待超时，请在系统提示中及时允许管理员授权后重试。',
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
  }) {
    return buildPosixDaemonLaunchShell(binary.path, args);
  }

  Future<_MacosElevatedCommandResult> _startMacosElevated(
    String command, {
    String? password,
  }) async {
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
        throw _MacosElevationException(
          run.error ?? '管理员权限启动失败。',
          childPid: run.childPid,
        );
      }
      if (shouldPersistPassword) {
        try {
          await saveMacosAdminPassword?.call(activePassword);
        } catch (_) {
          throw _MacosElevationException(
            '无法保存本地管理员凭据。',
            childPid: run.childPid,
          );
        }
      }
      return _MacosElevatedCommandResult(
        password: activePassword,
        childPid: run.childPid,
      );
    } on MissingPluginException {
      throw '当前 macOS 构建不支持本地管理员凭据存储，请重新安装 P2WLAN。';
    } on PlatformException catch (error) {
      throw error.message?.trim().isNotEmpty == true
          ? error.message!.trim()
          : '无法访问本地管理员凭据配置。';
    }
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
  }) async {
    final argLine = args.map(windowsCommandLineArgQuote).join(' ');
    final script =
        '\$ErrorActionPreference = \'Stop\'; '
        '\$child = Start-Process -Verb RunAs -WindowStyle Hidden '
        '-WorkingDirectory ${_powershellSingleQuoted(binary.parent.path)} '
        '-FilePath ${_powershellSingleQuoted(binary.path)} '
        '-ArgumentList ${_powershellSingleQuoted(argLine)} -PassThru; '
        // The ACL grants the local Administrators group access to this file,
        // so an alternate UAC account can start the child.  The stdout marker
        // is the only producer-side identity; Dart validates it and writes the
        // canonical PID file as the interactive user.
        'Write-Output (\'$_windowsChildPidMarker\' + [string]\$child.Id)';
    final result = await _runWindowsPowerShell(
      script,
      timeout: const Duration(seconds: 45),
    );
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

  Future<void> _verifyWindowsChildIdentity(int pid) async {
    final process = await waitForWindowsProcess(pid);
    await _startupTrace?.detail(
      '10 child_identity state=${process.state.name} '
      'pid=$pid operation=${process.operation ?? 'none'} '
      'win32_error=${process.win32Error ?? 0} '
      'exit_code=${process.exitCode ?? 'unknown'}',
    );
    final failure = classifyWindowsChildIdentity(
      process: process,
      pid: pid,
      launchedProcessId: _launchedProcessId,
    );
    if (failure != null) throw _WindowsChildIdentityException(failure);
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

DaemonStartupFailure? classifyWindowsChildIdentity({
  required WindowsProcessProbe process,
  required int pid,
  required int? launchedProcessId,
}) {
  if (process.state == WindowsProcessState.exited) {
    return const DaemonStartupFailure(
      DaemonStartupFailureCode.daemonExitedDuringStartup,
      'p2wlan-daemon 在启动身份校验前已退出，请查看启动日志。',
    );
  }
  if (trustedWindowsDaemonIdentityMatches(
    pid: pid,
    launchedProcessId: launchedProcessId,
    authenticatedProcessId: null,
    processName: process.processName,
  )) {
    return null;
  }
  return const DaemonStartupFailure(
    DaemonStartupFailureCode.pidMarkerFailed,
    '无法确认 Windows 后台网络服务的进程身份，请查看启动日志。',
  );
}

class _WindowsChildIdentityException implements Exception {
  const _WindowsChildIdentityException(this.failure);

  final DaemonStartupFailure failure;

  @override
  String toString() => failure.codeValue;
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
      childPid: switch (result['childPid']) {
        int pid when pid > 0 => pid,
        _ => null,
      },
      error: (result['error'] as String?)?.trim(),
    );
  }
}

class _MacosElevationRunResult {
  const _MacosElevationRunResult({
    required this.ok,
    this.missingCredential = false,
    this.authenticationFailed = false,
    this.childPid,
    this.error,
  });

  final bool ok;
  final bool missingCredential;
  final bool authenticationFailed;
  final int? childPid;
  final String? error;
}

/// The credential remains local to one launch and is never rendered in
/// debug output. Preparation and launch can share a newly entered password.
class _MacosElevatedCommandResult {
  const _MacosElevatedCommandResult({required this.password, this.childPid});

  final String password;
  final int? childPid;
}

class _MacosElevationException implements Exception {
  const _MacosElevationException(this.message, {this.childPid});

  final String message;
  final int? childPid;

  @override
  String toString() => message;
}
