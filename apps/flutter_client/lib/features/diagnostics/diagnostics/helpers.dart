part of '../diagnostics_page.dart';

class _LogPreview {
  const _LogPreview({
    required this.path,
    required this.content,
    required this.shownLineCount,
    this.error,
  });

  final String path;
  final String content;
  final int shownLineCount;
  final String? error;
}

class _PermissionSnapshot {
  const _PermissionSnapshot({
    required this.platform,
    required this.canCreateTun,
    required this.canModifyRoutes,
    required this.needsElevation,
    required this.recommendedAction,
    required this.checks,
    this.sudoCommand,
  });

  final String platform;
  final String canCreateTun;
  final String canModifyRoutes;
  final bool needsElevation;
  final String recommendedAction;
  final List<_PermissionCheck> checks;
  final String? sudoCommand;

  bool get bad =>
      needsElevation || checks.any((check) => check.status == 'fail');
  bool get warn =>
      checks.any((check) => check.status == 'warn') ||
      canCreateTun == 'unknown' ||
      canModifyRoutes == 'unknown';
}

class _PermissionCheck {
  const _PermissionCheck({
    required this.label,
    required this.status,
    required this.detail,
  });

  final String label;
  final String status;
  final String detail;
}

Future<_PermissionSnapshot> _checkPermissions() async {
  if (Platform.isWindows) return _checkWindowsPermissions();
  if (Platform.isLinux) return _checkLinuxPermissions();
  if (Platform.isMacOS) return _checkMacosPermissions();
  return _PermissionSnapshot(
    platform: _platformName(),
    canCreateTun: 'unknown',
    canModifyRoutes: 'unknown',
    needsElevation: true,
    recommendedAction:
        'Local daemon process control is not supported on this platform yet.',
    checks: const [
      _PermissionCheck(
        label: 'Desktop platform',
        status: 'fail',
        detail: 'Use macOS, Linux, or Windows for local TUN control.',
      ),
    ],
  );
}

_PermissionSnapshot _checkMacosPermissions() {
  final euid = _effectiveUserId();
  final isRoot = euid == 0;
  final hasDevTun =
      File('/dev/net/tun').existsSync() || File('/dev/tun').existsSync();
  return _PermissionSnapshot(
    platform: 'macOS',
    canCreateTun: isRoot ? 'unknown' : 'false',
    canModifyRoutes: isRoot ? 'true' : 'false',
    needsElevation: !isRoot,
    recommendedAction: isRoot
        ? '权限已满足；macOS utun 创建仍会在 daemon 启动时做运行时验证。'
        : '启动 TUN 时需要管理员授权；P2WLAN 会使用系统授权弹窗，不读取或保存密码。',
    sudoCommand: isRoot ? null : _suggestedSudoCommand(),
    checks: [
      _PermissionCheck(
        label: '有效用户权限',
        status: isRoot ? 'pass' : 'fail',
        detail: isRoot
            ? '已以 root 身份运行 (euid=$euid)。'
            : '当前是普通用户 (euid=${euid ?? 'unknown'})。',
      ),
      _PermissionCheck(
        label: 'TUN 设备节点',
        status: hasDevTun ? 'pass' : 'warn',
        detail: hasDevTun
            ? '/dev 中存在 TUN 设备节点。'
            : 'macOS 通常动态创建 utun；未找到静态 /dev/net/tun 属于正常情况。',
      ),
    ],
  );
}

_PermissionSnapshot _checkLinuxPermissions() {
  final euid = _effectiveUserId();
  final isRoot = euid == 0;
  final devTun = File('/dev/net/tun');
  final hasDevTun = devTun.existsSync();
  final daemonBinary = _resolveDaemonBinaryForPermissions();
  final hasCapNetAdmin = _hasNetAdminCapability(daemonBinary);
  final privileged = isRoot || hasCapNetAdmin;
  return _PermissionSnapshot(
    platform: 'Linux',
    canCreateTun: hasDevTun && privileged
        ? 'true'
        : hasDevTun
        ? 'unknown'
        : 'false',
    canModifyRoutes: privileged ? 'true' : 'unknown',
    needsElevation: !privileged,
    recommendedAction: privileged && hasDevTun
        ? '权限已满足，daemon 可以创建 TUN 并维护路由。'
        : '请使用 pkexec/sudo 启动 daemon，或对 p2wlan-daemon 设置 CAP_NET_ADMIN。',
    sudoCommand: privileged ? null : _suggestedSudoCommand(),
    checks: [
      _PermissionCheck(
        label: '有效用户权限',
        status: isRoot
            ? 'pass'
            : hasCapNetAdmin
            ? 'warn'
            : 'fail',
        detail: isRoot
            ? '已以 root 身份运行 (euid=$euid)。'
            : hasCapNetAdmin
            ? '当前不是 root，但 daemon 二进制带 cap_net_admin。'
            : '当前是普通用户 (euid=${euid ?? 'unknown'})，需要提权或 setcap。',
      ),
      _PermissionCheck(
        label: '/dev/net/tun',
        status: hasDevTun ? 'pass' : 'fail',
        detail: hasDevTun
            ? '/dev/net/tun 设备节点可访问。'
            : '未找到 /dev/net/tun，无法创建 Linux TUN。',
      ),
      _PermissionCheck(
        label: 'daemon capability',
        status: hasCapNetAdmin
            ? 'pass'
            : daemonBinary == null
            ? 'warn'
            : 'warn',
        detail: daemonBinary == null
            ? '未定位到 p2wlan-daemon，无法检查 cap_net_admin。'
            : hasCapNetAdmin
            ? '${daemonBinary.path} 具备 cap_net_admin。'
            : '${daemonBinary.path} 未检测到 cap_net_admin。',
      ),
    ],
  );
}

_PermissionSnapshot _checkWindowsPermissions() {
  final isAdmin = _isWindowsAdministrator();
  final wintun = _findWintunDll();
  return _PermissionSnapshot(
    platform: 'Windows',
    canCreateTun: isAdmin && wintun != null ? 'true' : 'false',
    canModifyRoutes: isAdmin ? 'true' : 'false',
    needsElevation: !isAdmin,
    recommendedAction: isAdmin && wintun != null
        ? 'Windows 管理员权限和 Wintun 运行库均已就绪。'
        : !isAdmin
        ? '启动 TUN 时请确认 Windows UAC 授权，并确保 wintun.dll 与客户端/daemon 同级或在 PATH 中。'
        : '请把 wintun.dll 放到客户端/daemon 同级目录，或设置 P2WLAN_WINTUN_DLL。',
    checks: [
      _PermissionCheck(
        label: 'Windows 管理员权限',
        status: isAdmin ? 'pass' : 'fail',
        detail: isAdmin ? '当前已具备管理员权限。' : '安装 Wintun 虚拟网卡和更新路由需要管理员权限。',
      ),
      _PermissionCheck(
        label: 'Wintun 运行库',
        status: wintun == null ? 'fail' : 'pass',
        detail: wintun == null
            ? '未在客户端/daemon 同级目录、P2WLAN_WINTUN_DLL 或 PATH 中找到 wintun.dll。'
            : '已找到 ${wintun.path}',
      ),
    ],
  );
}

Future<_LogPreview> _loadLogPreview() async {
  const previewLines = 120;
  final path =
      '${_defaultLogDir().path}${Platform.pathSeparator}p2wlan-daemon.log';
  final file = File(path);
  try {
    if (!await file.exists()) {
      return _LogPreview(path: path, content: '', shownLineCount: 0);
    }
    // Bounded tail read: memory cost is O(preview window), never O(file size).
    // A 100 MB log previews identically cheaply to a small one.
    final content = await tailLines(file, lines: previewLines);
    // We only read a bounded window, so we do not (and cannot, without an
    // O(size) scan) report the total file line count. The shown count is
    // bounded by the window; the UI labels it accordingly.
    final shownLines = content.isEmpty ? 0 : content.split('\n').length;
    return _LogPreview(
      path: path,
      content: redactLines(content.split('\n')),
      shownLineCount: shownLines,
    );
  } catch (error) {
    return _LogPreview(
      path: path,
      content: '',
      shownLineCount: 0,
      error: 'Failed to read $path: $error',
    );
  }
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

String _platformName() {
  if (Platform.isMacOS) return 'macOS';
  if (Platform.isWindows) return 'Windows';
  if (Platform.isLinux) return 'Linux';
  if (Platform.isAndroid) return 'Android';
  if (Platform.isIOS) return 'iOS';
  if (Platform.isFuchsia) return 'Fuchsia';
  return Platform.operatingSystem;
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

JsonMap _map(dynamic value) {
  if (value is Map) return Map<String, dynamic>.from(value);
  return {};
}

String _value(dynamic value) {
  if (value == null) return '—';
  if (value is bool) return value ? 'yes' : 'no';
  if (value is num) return value.toString();
  if (value is Iterable) return value.join(', ');
  if (value is Map) return jsonEncode(value);
  final text = value.toString().trim();
  return text.isEmpty ? '—' : text;
}
