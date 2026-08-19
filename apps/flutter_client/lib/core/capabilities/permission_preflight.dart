// Real permission preflight for local P2WLAN node operation.
//
// The onboarding permission step and the diagnostics platform panel both read
// this. It detects what the current platform can actually do right now
// (create a TUN interface, modify overlay routes) from the live system state,
// never from an in-memory boolean or an optimistic click. The daemon start
// itself is the authoritative elevation grant: once the daemon is reachable
// with a TUN, permission is real regardless of what this static probe reports.
import 'dart:io';

/// One real permission check (label + status + human detail).
class PermissionCheck {
  const PermissionCheck({
    required this.label,
    required this.status,
    required this.detail,
    this.code,
  });

  final String label;
  final String status;
  final String detail;

  /// Stable machine-readable key for this check (e.g. `euid`, `dev_net_tun`,
  /// `admin`). The UI uses it to render localized copy instead of [label] /
  /// [detail], which may carry raw technical text in any language.
  final String? code;
}

enum PermissionPreflightState {
  satisfied,
  elevationRequired,
  runtimeVerificationRequired,
  unsupported,
  failed,
}

/// Result of the live permission preflight.
class PermissionPreflight {
  const PermissionPreflight({
    required this.platform,
    required this.state,
    required this.canCreateTun,
    required this.canModifyRoutes,
    required this.elevationSupported,
    required this.reasonCode,
    required this.message,
    required this.checks,
    this.sudoCommand,
  });

  final String platform;
  final PermissionPreflightState state;

  /// A fact, not a final state: null means the platform needs runtime proof.
  final bool? canCreateTun;

  /// A fact, not a final state: null means the platform needs runtime proof.
  final bool? canModifyRoutes;

  final bool elevationSupported;
  final String reasonCode;
  final String message;

  final List<PermissionCheck> checks;
  final String? sudoCommand;

  bool get bad =>
      state == PermissionPreflightState.elevationRequired ||
      state == PermissionPreflightState.failed ||
      state == PermissionPreflightState.unsupported ||
      checks.any((check) => check.status == 'fail');

  bool get warn =>
      state == PermissionPreflightState.runtimeVerificationRequired ||
      checks.any((check) => check.status == 'warn') ||
      (canCreateTun == null && state != PermissionPreflightState.failed) ||
      (canModifyRoutes == null && state != PermissionPreflightState.failed);

  bool get needsElevation =>
      state == PermissionPreflightState.elevationRequired;

  bool get satisfied => state == PermissionPreflightState.satisfied;

  String get recommendedAction => message;

  String get canCreateTunLabel => _factLabel(canCreateTun);

  String get canModifyRoutesLabel => _factLabel(canModifyRoutes);

  String _factLabel(bool? value) => switch (value) {
    true => 'true',
    false => 'false',
    null => 'unknown',
  };
}

/// Run the live permission preflight for the current platform.
Future<PermissionPreflight> runPermissionPreflight() async {
  if (Platform.isWindows) return _checkWindowsPermissions();
  if (Platform.isLinux) return _checkLinuxPermissions();
  if (Platform.isMacOS) return _checkMacosPermissions();
  return const PermissionPreflight(
    platform: 'other',
    state: PermissionPreflightState.unsupported,
    canCreateTun: null,
    canModifyRoutes: null,
    elevationSupported: false,
    reasonCode: 'platform_unsupported',
    message:
        'Local daemon process control is not supported on this platform yet.',
    checks: [
      PermissionCheck(
        label: 'Desktop platform',
        status: 'fail',
        detail: 'unsupported',
        code: 'platform',
      ),
    ],
  );
}

PermissionPreflight _checkMacosPermissions() {
  final euid = _effectiveUserId();
  final isRoot = euid == 0;
  final hasDevTun =
      File('/dev/net/tun').existsSync() || File('/dev/tun').existsSync();
  return PermissionPreflight(
    platform: 'macOS',
    state: isRoot
        ? PermissionPreflightState.runtimeVerificationRequired
        : PermissionPreflightState.elevationRequired,
    canCreateTun: isRoot ? null : false,
    canModifyRoutes: isRoot ? true : false,
    elevationSupported: true,
    reasonCode: isRoot ? 'tun_runtime_verification' : 'elevation_required',
    message: isRoot
        ? '已获得 root 权限；macOS utun 创建需要 daemon 运行时验证。'
        : '启动 TUN 时需要管理员授权；P2WLAN 会使用系统授权弹窗，不读取或保存密码。',
    sudoCommand: isRoot ? null : _suggestedSudoCommand(),
    checks: [
      PermissionCheck(
        label: 'Effective user permissions',
        status: isRoot ? 'pass' : 'fail',
        detail: 'euid=$euid',
        code: 'euid',
      ),
      PermissionCheck(
        label: 'TUN device node',
        status: hasDevTun ? 'pass' : 'warn',
        detail: hasDevTun ? 'found' : 'dynamic utun expected',
        code: 'tun_node',
      ),
    ],
  );
}

PermissionPreflight _checkLinuxPermissions() {
  final euid = _effectiveUserId();
  final isRoot = euid == 0;
  final devTun = File('/dev/net/tun');
  final hasDevTun = devTun.existsSync();
  final daemonBinary = _resolveDaemonBinaryForPermissions();
  final hasCapNetAdmin = _hasNetAdminCapability(daemonBinary);
  final privileged = isRoot || hasCapNetAdmin;
  return PermissionPreflight(
    platform: 'Linux',
    state: !privileged
        ? PermissionPreflightState.elevationRequired
        : !hasDevTun
        ? PermissionPreflightState.failed
        : PermissionPreflightState.satisfied,
    canCreateTun: hasDevTun && privileged
        ? true
        : hasDevTun
        ? null
        : false,
    canModifyRoutes: privileged ? true : null,
    elevationSupported: true,
    reasonCode: !privileged
        ? 'elevation_required'
        : !hasDevTun
        ? 'tun_device_missing'
        : 'ready',
    message: privileged && hasDevTun
        ? '权限已满足，daemon 可以创建 TUN 并维护路由。'
        : privileged
        ? '当前权限已满足，但缺少 /dev/net/tun，无法创建 Linux TUN。'
        : '请使用 pkexec/sudo 启动 daemon，或对 p2wlan-daemon 设置 CAP_NET_ADMIN。',
    sudoCommand: privileged ? null : _suggestedSudoCommand(),
    checks: [
      PermissionCheck(
        label: 'Effective user permissions',
        status: isRoot
            ? 'pass'
            : hasCapNetAdmin
            ? 'warn'
            : 'fail',
        detail: 'euid=$euid',
        code: 'euid',
      ),
      PermissionCheck(
        label: '/dev/net/tun',
        status: hasDevTun ? 'pass' : 'fail',
        detail: hasDevTun ? 'found' : 'missing',
        code: 'dev_net_tun',
      ),
      PermissionCheck(
        label: 'daemon capability',
        status: hasCapNetAdmin ? 'pass' : 'warn',
        detail: hasCapNetAdmin
            ? 'cap_net_admin present'
            : 'cap_net_admin absent',
        code: 'daemon_cap',
      ),
    ],
  );
}

PermissionPreflight _checkWindowsPermissions() {
  final isAdmin = _isWindowsAdministrator();
  final wintun = _findWintunDll();
  return PermissionPreflight(
    platform: 'Windows',
    state: !isAdmin
        ? PermissionPreflightState.elevationRequired
        : wintun == null
        ? PermissionPreflightState.failed
        : PermissionPreflightState.satisfied,
    canCreateTun: isAdmin && wintun != null ? true : false,
    canModifyRoutes: isAdmin ? true : false,
    elevationSupported: true,
    reasonCode: !isAdmin
        ? 'elevation_required'
        : wintun == null
        ? 'wintun_missing'
        : 'ready',
    message: isAdmin && wintun != null
        ? 'Windows 管理员权限和 Wintun 运行库均已就绪。'
        : !isAdmin
        ? '启动 TUN 时请确认 Windows UAC 授权，并确保 wintun.dll 与客户端/daemon 同级或在 PATH 中。'
        : '请把 wintun.dll 放到客户端/daemon 同级目录，或设置 P2WLAN_WINTUN_DLL。',
    checks: [
      PermissionCheck(
        label: 'Windows administrator',
        status: isAdmin ? 'pass' : 'fail',
        detail: isAdmin ? 'granted' : 'required',
        code: 'admin',
      ),
      PermissionCheck(
        label: 'Wintun runtime',
        status: wintun == null ? 'fail' : 'pass',
        detail: wintun == null ? 'not found' : wintun.path,
        code: 'wintun',
      ),
    ],
  );
}

int? _effectiveUserId() {
  if (!Platform.isMacOS && !Platform.isLinux) return null;
  try {
    final result = Process.runSync('id', ['-u']);
    if (result.exitCode != 0) return null;
    return int.tryParse(result.stdout.toString().trim());
  } catch (_) {
    return Platform.environment['USER'] == 'root' ? 0 : null;
  }
}

bool _isWindowsAdministrator() {
  if (!Platform.isWindows) return false;
  try {
    final result = Process.runSync('net', ['session']);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

File? _findWintunDll() {
  if (!Platform.isWindows) return null;
  final candidates = <String>{};
  final envPath = Platform.environment['P2WLAN_WINTUN_DLL']?.trim();
  if (envPath != null && envPath.isNotEmpty) candidates.add(envPath);

  final exeDir = File(Platform.resolvedExecutable).parent.path;
  candidates.add('$exeDir${Platform.pathSeparator}wintun.dll');
  candidates.add(
    '${Directory.current.path}${Platform.pathSeparator}wintun.dll',
  );

  final pathValue = Platform.environment['PATH'];
  if (pathValue != null && pathValue.isNotEmpty) {
    for (final dir in pathValue.split(';')) {
      final trimmed = dir.trim();
      if (trimmed.isNotEmpty) {
        candidates.add('$trimmed${Platform.pathSeparator}wintun.dll');
      }
    }
  }

  for (final path in candidates) {
    final file = File(path);
    if (file.existsSync()) return file;
  }
  return null;
}

File? _resolveDaemonBinaryForPermissions() {
  final envPath = Platform.environment['P2WLAN_DAEMON_BIN']?.trim();
  if (envPath != null && envPath.isNotEmpty) {
    final file = File(envPath);
    if (file.existsSync()) return file;
  }

  final extension = Platform.isWindows ? '.exe' : '';
  final name = 'p2wlan-daemon$extension';
  final candidates = <File>[];
  final exeDir = File(Platform.resolvedExecutable).parent;
  candidates.add(File('${exeDir.path}${Platform.pathSeparator}$name'));
  candidates.add(
    File(
      '${exeDir.parent.path}${Platform.pathSeparator}Resources${Platform.pathSeparator}$name',
    ),
  );

  var dir = Directory.current;
  for (var depth = 0; depth < 6; depth += 1) {
    candidates.add(
      File('${dir.path}${Platform.pathSeparator}target/release/$name'),
    );
    candidates.add(
      File('${dir.path}${Platform.pathSeparator}target/debug/$name'),
    );
    final parent = dir.parent;
    if (parent.path == dir.path) break;
    dir = parent;
  }

  for (final candidate in candidates) {
    if (candidate.existsSync()) return candidate;
  }
  return _whichFile(name);
}

File? _whichFile(String name) {
  try {
    final result = Process.runSync(Platform.isWindows ? 'where' : 'which', [
      name,
    ]);
    if (result.exitCode != 0) return null;
    final first = result.stdout.toString().split('\n').first.trim();
    if (first.isEmpty) return null;
    final file = File(first);
    return file.existsSync() ? file : null;
  } catch (_) {
    return null;
  }
}

bool _hasNetAdminCapability(File? binary) {
  if (binary == null || !Platform.isLinux) return false;
  try {
    final result = Process.runSync('getcap', [binary.path]);
    if (result.exitCode != 0) return false;
    return result.stdout.toString().contains('cap_net_admin');
  } catch (_) {
    return false;
  }
}

String _suggestedSudoCommand() {
  final envPath = Platform.environment['P2WLAN_DAEMON_BIN']?.trim();
  final binary = envPath != null && envPath.isNotEmpty
      ? envPath
      : 'p2wlan-daemon';
  final quoted = _shellQuote(binary);
  return 'sudo -E P2WLAN_DAEMON_BIN=$quoted $quoted --diagnostics-bind 127.0.0.1:39277';
}

String _shellQuote(String value) => "'${value.replaceAll("'", "'\\''")}'";
