part of '../daemon_controller.dart';

/// Stable categories returned by the Windows/macOS/Linux daemon startup
/// handshake.  The UI can translate these codes without parsing a localized
/// error string, while the message remains useful in logs and support reports.
enum DaemonStartupFailureCode {
  uacCancelled,
  uacLaunchFailed,
  daemonBinaryLoadFailed,
  daemonExitedDuringStartup,
  daemonNotElevated,
  tokenAccessFailed,
  wintunDllMissing,
  wintunLoadFailed,
  wintunAdapterCreateFailed,
  wintunAdapterOpenFailed,
  ipConfigFailed,
  mtuConfigFailed,
  wintunSessionFailed,
  routeConflict,
  routeInstallFailed,
  diagnosticsBindFailed,
  startupTimeout,
  aclFailure,
  pidMarkerFailed,
  controlAuthFailed,
  clientDaemonBuildMismatch,
  staleDaemonCleanupFailed,
}

extension DaemonStartupFailureCodeText on DaemonStartupFailureCode {
  String get value => switch (this) {
    DaemonStartupFailureCode.uacCancelled => 'UAC_CANCELLED',
    DaemonStartupFailureCode.uacLaunchFailed => 'UAC_LAUNCH_FAILED',
    DaemonStartupFailureCode.daemonBinaryLoadFailed =>
      'DAEMON_BINARY_LOAD_FAILED',
    DaemonStartupFailureCode.daemonExitedDuringStartup =>
      'DAEMON_EXITED_DURING_STARTUP',
    DaemonStartupFailureCode.daemonNotElevated => 'DAEMON_NOT_ELEVATED',
    DaemonStartupFailureCode.tokenAccessFailed => 'TOKEN_ACCESS_FAILED',
    DaemonStartupFailureCode.wintunDllMissing => 'WINTUN_DLL_MISSING',
    DaemonStartupFailureCode.wintunLoadFailed => 'WINTUN_LOAD_FAILED',
    DaemonStartupFailureCode.wintunAdapterCreateFailed =>
      'WINTUN_ADAPTER_CREATE_FAILED',
    DaemonStartupFailureCode.wintunAdapterOpenFailed =>
      'WINTUN_ADAPTER_OPEN_FAILED',
    DaemonStartupFailureCode.ipConfigFailed => 'IP_CONFIG_FAILED',
    DaemonStartupFailureCode.mtuConfigFailed => 'MTU_CONFIG_FAILED',
    DaemonStartupFailureCode.wintunSessionFailed => 'WINTUN_SESSION_FAILED',
    DaemonStartupFailureCode.routeConflict => 'ROUTE_CONFLICT',
    DaemonStartupFailureCode.routeInstallFailed => 'ROUTE_INSTALL_FAILED',
    DaemonStartupFailureCode.diagnosticsBindFailed => 'DIAGNOSTICS_BIND_FAILED',
    DaemonStartupFailureCode.startupTimeout => 'STARTUP_TIMEOUT',
    DaemonStartupFailureCode.aclFailure => 'ACL_FAILURE',
    DaemonStartupFailureCode.pidMarkerFailed => 'PID_MARKER_FAILED',
    DaemonStartupFailureCode.controlAuthFailed => 'CONTROL_AUTH_FAILED',
    DaemonStartupFailureCode.clientDaemonBuildMismatch =>
      'CLIENT_DAEMON_BUILD_MISMATCH',
    DaemonStartupFailureCode.staleDaemonCleanupFailed =>
      'STALE_DAEMON_CLEANUP_FAILED',
  };
}

class DaemonStartupFailure {
  const DaemonStartupFailure(this.code, this.message);

  final DaemonStartupFailureCode code;
  final String message;

  String get codeValue => code.value;
}

/// Result of one readiness probe. A result with neither `ready` nor
/// `failure` is still pending and is used by the pure startup state machine
/// tests.
class DaemonStartupWaitResult {
  const DaemonStartupWaitResult({required this.ready, this.failure});

  const DaemonStartupWaitResult.pending() : ready = false, failure = null;

  const DaemonStartupWaitResult.ready() : ready = true, failure = null;

  const DaemonStartupWaitResult.failed(DaemonStartupFailure this.failure)
    : ready = false;

  final bool ready;
  final DaemonStartupFailure? failure;
}

/// Classify a daemon log without exposing command-line arguments, tokens, or
/// full log contents to the UI. The order is intentional: a present-but-
/// unloadable DLL is not the same problem as a missing DLL.
DaemonStartupFailure? classifyDaemonStartupLog(String contents) {
  final lower = contents.toLowerCase();
  DaemonStartupFailure failure(DaemonStartupFailureCode code, String message) =>
      DaemonStartupFailure(code, message);

  if (lower.contains('windows acl protection failed') ||
      lower.contains('acl protection failed') ||
      lower.contains('acl_failure')) {
    return failure(
      DaemonStartupFailureCode.aclFailure,
      '运行目录 ACL 配置失败，当前用户和本地 Administrators 组无法安全访问 daemon 运行文件。',
    );
  }
  if (lower.contains('pid marker') &&
      (lower.contains('failed') ||
          lower.contains('could not') ||
          lower.contains('permission'))) {
    return failure(
      DaemonStartupFailureCode.pidMarkerFailed,
      'daemon PID 标记文件无法写入或验证。',
    );
  }
  if (lower.contains('daemon_binary_load_failed') ||
      lower.contains('daemon identity probe') ||
      lower.contains('daemon 无法加载')) {
    return failure(
      DaemonStartupFailureCode.daemonBinaryLoadFailed,
      'p2wlan-daemon 本体或其运行库无法加载。',
    );
  }
  if (lower.contains('windows_elevated=false') ||
      lower.contains('daemon_not_elevated') ||
      lower.contains('without elevation') ||
      lower.contains('requires an elevated administrator token')) {
    return failure(
      DaemonStartupFailureCode.daemonNotElevated,
      'daemon 没有以 Windows elevated administrator token 运行，无法初始化 TUN。',
    );
  }
  if (lower.contains('token_access_failed')) {
    return failure(
      DaemonStartupFailureCode.tokenAccessFailed,
      'daemon 无法读取或验证自身 Windows access token。',
    );
  }
  if (lower.contains('launch token') &&
      (lower.contains('failed') ||
          lower.contains('unreadable') ||
          lower.contains('permission') ||
          lower.contains('could not'))) {
    return failure(
      DaemonStartupFailureCode.tokenAccessFailed,
      '一次性启动凭据无法安全读取，daemon 已停止。',
    );
  }
  if (lower.contains('wintun.dll not found') ||
      lower.contains('wintun.dll not found or not loadable')) {
    return failure(
      DaemonStartupFailureCode.wintunDllMissing,
      '找不到 wintun.dll，请确认它与 p2wlan-daemon.exe 位于同一发布目录。',
    );
  }
  if (lower.contains('wintun.dll is present but not loadable') ||
      lower.contains('dynamic library load failed') ||
      lower.contains('wintun load failed') ||
      lower.contains('symbol not found in library')) {
    return failure(
      DaemonStartupFailureCode.wintunLoadFailed,
      'wintun.dll 存在但无法加载，可能缺少依赖或导出符号。',
    );
  }
  if (lower.contains('wintunopenadapter') ||
      lower.contains('failed to open existing wintun adapter')) {
    return failure(
      DaemonStartupFailureCode.wintunAdapterOpenFailed,
      'Wintun 已有适配器无法打开，可能需要清理残留适配器或检查权限。',
    );
  }
  if (lower.contains('wintuncreateadapter') ||
      lower.contains('failed to create wintun adapter')) {
    return failure(
      DaemonStartupFailureCode.wintunAdapterCreateFailed,
      'Wintun 适配器创建失败，请检查管理员权限和驱动状态。',
    );
  }
  if (lower.contains('ipv4 configuration failed') ||
      lower.contains('ip configuration failed') ||
      lower.contains('netsh address set failed')) {
    return failure(
      DaemonStartupFailureCode.ipConfigFailed,
      'TUN IPv4 地址配置失败，daemon 已回滚并停止。',
    );
  }
  if (lower.contains('mtu configuration failed') ||
      lower.contains('netsh mtu set failed')) {
    return failure(
      DaemonStartupFailureCode.mtuConfigFailed,
      'TUN MTU 配置失败，daemon 已回滚并停止。',
    );
  }
  if (lower.contains('wintunstartsession') ||
      lower.contains('wintun session failed') ||
      lower.contains('failed to start wintun session')) {
    return failure(
      DaemonStartupFailureCode.wintunSessionFailed,
      'Wintun 数据会话启动失败，daemon 已回滚并停止。',
    );
  }
  if (lower.contains('routing conflict') || lower.contains('route conflict')) {
    return failure(
      DaemonStartupFailureCode.routeConflict,
      '覆盖网段路由与现有接口冲突，daemon 未保持半启动状态。',
    );
  }
  if (lower.contains('route install failed') ||
      lower.contains('new-netroute failed') ||
      lower.contains('netsh fallback failed')) {
    return failure(
      DaemonStartupFailureCode.routeInstallFailed,
      '覆盖网段路由安装失败，daemon 已清理本次启动状态。',
    );
  }
  if (lower.contains('failed to bind diagnostics endpoint') ||
      lower.contains('diagnostics endpoint start failed') ||
      lower.contains('diagnostics bind failed')) {
    return failure(
      DaemonStartupFailureCode.diagnosticsBindFailed,
      '诊断端点无法绑定，可能被旧 daemon 或其他进程占用。',
    );
  }
  return null;
}

/// Decide whether the readiness loop should keep polling, return ready, or
/// fail fast. `childAlive == null` is used on platforms where no PID marker
/// is available; health remains authoritative there.
DaemonStartupWaitResult classifyDaemonStartupProbe({
  required bool healthReady,
  required bool? childAlive,
  DaemonStartupFailure? logFailure,
  required bool deadlineReached,
}) {
  if (healthReady && childAlive != false) {
    return const DaemonStartupWaitResult.ready();
  }
  if (logFailure != null) {
    return DaemonStartupWaitResult.failed(logFailure);
  }
  if (childAlive == false) {
    return DaemonStartupWaitResult.failed(
      const DaemonStartupFailure(
        DaemonStartupFailureCode.daemonExitedDuringStartup,
        'p2wlan-daemon 在诊断端点就绪前退出。',
      ),
    );
  }
  if (deadlineReached) {
    return DaemonStartupWaitResult.failed(
      const DaemonStartupFailure(
        DaemonStartupFailureCode.startupTimeout,
        'p2wlan-daemon 未在启动时限内完成诊断端点就绪。',
      ),
    );
  }
  return const DaemonStartupWaitResult.pending();
}

extension DaemonControllerDiagnosticsPaths on DaemonController {
  Future<DaemonStartupWaitResult> _waitForHealth(
    String diagnosticsUrl,
    Duration timeout,
    String logPath,
    int? expectedPid,
  ) async {
    final deadline = DateTime.now().add(timeout);
    // Start-Process returns the child PID before WMI/Get-Process is always
    // able to observe the new process. Give that identity probe one poll
    // interval of grace; a real early exit still fails in roughly 1–2 s.
    final processProbeGrace = DateTime.now().add(const Duration(seconds: 1));
    while (DateTime.now().isBefore(deadline)) {
      final childAlive = await _startupChildAlive(expectedPid);
      final result = classifyDaemonStartupProbe(
        healthReady: await _diagnosticsApi.fetchHealth(diagnosticsUrl),
        childAlive:
            childAlive == false && DateTime.now().isBefore(processProbeGrace)
            ? null
            : childAlive,
        logFailure: await _startupLogFailure(logPath),
        deadlineReached: false,
      );
      if (result.ready || result.failure != null) return result;
      await Future<void>.delayed(DaemonController._readyPoll);
    }
    final childAlive = await _startupChildAlive(expectedPid);
    final result = classifyDaemonStartupProbe(
      healthReady: await _diagnosticsApi.fetchHealth(diagnosticsUrl),
      childAlive: childAlive,
      logFailure: await _startupLogFailure(logPath),
      deadlineReached: true,
    );
    return result.failure == null && !result.ready
        ? const DaemonStartupWaitResult.failed(
            DaemonStartupFailure(
              DaemonStartupFailureCode.startupTimeout,
              'p2wlan-daemon 未在启动时限内完成诊断端点就绪。',
            ),
          )
        : result;
  }

  Future<bool?> _startupChildAlive(int? expectedPid) async {
    final pid = expectedPid;
    if (pid == null) {
      final markerPid = await _readVerifiedPid();
      if (markerPid == null) return null;
      return _processLooksLikeDaemon(markerPid);
    }
    final lastProbeAt = _lastLaunchExitProbeAt;
    final lastProbeResult = _lastLaunchExitProbeResult;
    if (lastProbeAt != null &&
        lastProbeResult != null &&
        DateTime.now().difference(lastProbeAt) <
            const Duration(milliseconds: 600)) {
      return lastProbeResult;
    }
    final alive = await _processLooksLikeDaemon(pid);
    _lastLaunchExitProbeAt = DateTime.now();
    _lastLaunchExitProbeResult = alive;
    return alive;
  }

  Future<DaemonStartupFailure?> _startupLogFailure(String logPath) async {
    final logFailure = await logTailClassifyStartupFailure(logPath);
    if (logFailure != null) return logFailure;
    if (await _logShowsPermanentAuthFailure(logPath)) {
      return const DaemonStartupFailure(
        DaemonStartupFailureCode.controlAuthFailed,
        '控制端认证失败，请重新登录后再启动 daemon。',
      );
    }
    return null;
  }

  /// Whether the daemon log tail carries a permanent control auth failure
  /// (expired token / revoked credential).  The daemon exits after a
  /// permanent 401/403 instead of retrying, so a fresh start with a stale
  /// token never reaches diagnostics readiness.
  Future<bool> _logShowsPermanentAuthFailure(String logPath) {
    return logTailShowsPermanentAuthFailure(logPath);
  }

  Future<bool> _waitForHealthDown(
    String diagnosticsUrl,
    Duration timeout,
  ) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (!await _diagnosticsApi.fetchHealth(diagnosticsUrl)) return true;
      await Future<void>.delayed(DaemonController._readyPoll);
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
}

/// Whether the daemon log tail carries a permanent control auth failure
/// (expired token / revoked credential).  The daemon exits after a permanent
/// 401/403 instead of retrying, so a fresh start with a stale token never
/// reaches diagnostics readiness and the GUI must surface "登录已过期，请重新
/// 登录" instead of a generic TUN-start timeout.
///
/// Public for direct unit testing; the daemon-controller start flow uses it
/// to fast-fail (well under the 60 s macOS readiness window) when the
/// elevated launch produced a daemon that immediately exited.
Future<bool> logTailShowsPermanentAuthFailure(String logPath) async {
  final logFile = File(logPath);
  if (!await logFile.exists()) return false;
  try {
    final length = await logFile.length();
    final start = length > _authFailureScanBytes
        ? length - _authFailureScanBytes
        : 0;
    final contents = await logFile
        .openRead(start)
        .fold<String>(
          '',
          (buffer, chunk) => buffer + utf8.decode(chunk, allowMalformed: true),
        );
    final lower = contents.toLowerCase();
    return const [
      'permanent auth failure',
      're-authentication required',
      'register request returned http 401',
      'list nodes request returned http 401',
      'list signals returned http 401',
    ].any(lower.contains);
  } catch (_) {
    return false;
  }
}

/// Whether the Windows daemon exited because its side-by-side Wintun runtime
/// could not be loaded. This is kept separate from permission failures: UAC
/// elevation cannot fix a missing DLL, and the UI should say so directly.
Future<bool> logTailShowsWintunMissing(String logPath) async {
  return (await logTailClassifyStartupFailure(logPath))?.code ==
      DaemonStartupFailureCode.wintunDllMissing;
}

Future<DaemonStartupFailure?> logTailClassifyStartupFailure(
  String logPath,
) async {
  final logFile = File(logPath);
  if (!await logFile.exists()) return null;
  try {
    final length = await logFile.length();
    final start = length > _authFailureScanBytes
        ? length - _authFailureScanBytes
        : 0;
    final contents = await logFile
        .openRead(start)
        .fold<String>(
          '',
          (buffer, chunk) => buffer + utf8.decode(chunk, allowMalformed: true),
        );
    return classifyDaemonStartupLog(contents);
  } catch (_) {
    return null;
  }
}

const _authFailureScanBytes = 128 * 1024;
