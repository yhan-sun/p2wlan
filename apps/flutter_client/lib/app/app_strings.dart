import 'package:flutter/widgets.dart';

import '../core/models/diagnostics_models.dart';

class AppStringsScope extends InheritedWidget {
  const AppStringsScope({
    super.key,
    required this.strings,
    required super.child,
  });

  final AppStrings strings;

  static AppStrings of(BuildContext context) {
    final scope = context.dependOnInheritedWidgetOfExactType<AppStringsScope>();
    return scope?.strings ?? AppStrings.fromCode(defaultLanguageCode);
  }

  @override
  bool updateShouldNotify(AppStringsScope oldWidget) {
    return oldWidget.strings.appLanguage.code != strings.appLanguage.code;
  }
}

class AppStrings {
  const AppStrings(this.appLanguage);

  factory AppStrings.fromCode(String code) {
    return AppStrings(AppLanguage.fromCode(code));
  }

  final AppLanguage appLanguage;

  bool get isZh => appLanguage == AppLanguage.simplifiedChinese;

  String get appName => 'P2WLAN';

  String get dashboard => isZh ? '仪表盘' : 'Dashboard';
  String get nodes => isZh ? '节点' : 'Nodes';
  String get tunnels => isZh ? '隧道' : 'Tunnels';
  String get diagnostics => isZh ? '诊断' : 'Diagnostics';
  String get settings => isZh ? '设置' : 'Settings';

  String get online => isZh ? '在线' : 'Online';
  String get offline => isZh ? '离线' : 'Offline';
  String get degraded => isZh ? '降级' : 'Degraded';
  String get healthy => isZh ? '健康' : 'Healthy';
  String get unhealthy => isZh ? '异常' : 'Unhealthy';
  String get unavailable => isZh ? '不可用' : 'Unavailable';
  String get reachable => isZh ? '可达' : 'reachable';
  String get loaded => isZh ? '已加载' : 'loaded';
  String get error => isZh ? '错误' : 'error';
  String get skipped => isZh ? '已跳过' : 'skipped';
  String get connected => isZh ? '已连接' : 'connected';
  String get notConnected => isZh ? '未连接' : 'not connected';
  String get yes => isZh ? '是' : 'yes';
  String get no => isZh ? '否' : 'no';

  String get refresh => isZh ? '刷新' : 'Refresh';
  String get refreshNow => isZh ? '立即刷新' : 'Refresh now';
  String get refreshing => isZh ? '刷新中...' : 'Refreshing...';
  String get startP2wlan => isZh ? '启动 P2WLAN' : 'Start P2WLAN';
  String get stopP2wlan => isZh ? '停止 P2WLAN' : 'Stop P2WLAN';
  String get daemonWorking => isZh ? '处理中...' : 'Working...';
  String get lastDaemonAction => isZh ? '最近操作' : 'Last action';
  String get cancel => isZh ? '取消' : 'Cancel';
  String get continueAction => isZh ? '继续' : 'Continue';
  String get openConsole => isZh ? '打开控制台' : 'Open console';
  String get openLogs => isZh ? '打开日志' : 'Open logs';
  String get quitP2wlan => isZh ? '退出 P2WLAN' : 'Quit P2WLAN';
  String get trayStatus => isZh ? '状态' : 'Status';
  String get devices => isZh ? '设备' : 'Devices';
  String get noOnlineDevices => isZh ? '暂无在线设备' : 'No online devices';
  String get macosAuthorizationTitle =>
      isZh ? '需要 macOS 管理员授权' : 'macOS administrator access required';
  String get macosAuthorizationBody => isZh
      ? 'P2WLAN 需要启动 p2wlan-daemon 来创建虚拟网卡并安装路由。下一步会打开 macOS 系统密码弹窗；P2WLAN 不会读取或保存你的密码。'
      : 'P2WLAN needs to start p2wlan-daemon to create the virtual adapter and install routes. macOS will ask for an administrator password next; P2WLAN does not read or store it.';
  String get manualLaunchCommand => isZh ? '手动启动命令' : 'Manual launch command';
  String get manualLaunchCommandBody => isZh
      ? '如果系统授权失败，可以复制下面的命令到终端执行，然后回到 P2WLAN 点击刷新。'
      : 'If system authorization fails, copy this command into Terminal, then return to P2WLAN and refresh.';
  String get copyLaunchCommand => isZh ? '复制命令' : 'Copy command';
  String get copiedLaunchCommand => isZh ? '启动命令已复制' : 'Launch command copied';
  String autoRefresh(int seconds) =>
      isZh ? '自动刷新 (${seconds}s)' : 'Auto refresh (${seconds}s)';

  String get dashboardSubtitle => isZh
      ? '启动、停止并监控本机 P2WLAN 虚拟网络。'
      : 'Start, stop, and monitor the local P2WLAN virtual network.';
  String get localDiagnostics => isZh ? 'P2WLAN 守护进程' : 'P2WLAN daemon';
  String get diagnosticsUrl => isZh ? '诊断 URL' : 'Diagnostics URL';
  String get endpointState => isZh ? '端点状态' : 'Endpoint state';
  String get lastRefresh => isZh ? '上次刷新' : 'Last refresh';
  String get requestDuration => isZh ? '请求耗时' : 'Request duration';
  String get lastError => isZh ? '最近错误' : 'Last error';
  String get snapshot => isZh ? '快照' : 'Snapshot';
  String get offlineSnapshotMessage => isZh
      ? '当前没有运行快照。点击“启动 P2WLAN”启动本机 p2wlan-daemon。'
      : 'No runtime snapshot is available. Click Start P2WLAN to launch the local p2wlan-daemon.';
  String get runtimeSnapshot => isZh ? '运行快照' : 'Runtime snapshot';
  String get nodeId => isZh ? '节点 ID' : 'Node ID';
  String get virtualIp => isZh ? '虚拟 IP' : 'Virtual IP';
  String get networkId => isZh ? '网络 ID' : 'Network ID';
  String get serviceHealth => isZh ? '服务健康' : 'Service health';
  String get udpLocalAddr => isZh ? 'UDP 本地地址' : 'UDP local addr';
  String get relay => isZh ? '中继' : 'Relay';
  String get relayRegion => isZh ? '中继区域' : 'Relay region';
  String get peers => isZh ? '设备数' : 'Devices';
  String get peerPaths => isZh ? '设备路径' : 'Device paths';
  String get totalPeers => isZh ? '总设备数' : 'Total devices';
  String get directPaths => isZh ? '直连路径' : 'Direct paths';
  String get relayPaths => isZh ? '中继路径' : 'Relay paths';
  String get bytesSent => isZh ? '已发送' : 'Bytes sent';
  String get bytesReceived => isZh ? '已接收' : 'Bytes received';

  String get diagnosticsSubtitle => isZh
      ? 'GET /status 的摘要和原始 JSON。'
      : 'Summary plus raw JSON from GET /status.';
  String get summary => isZh ? '摘要' : 'Summary';
  String get statusLoaded => isZh ? '状态已加载' : 'Status loaded';
  String get noSnapshot => isZh ? '无快照' : 'No snapshot';
  String get controlConnected => isZh ? '控制面连接' : 'Control connected';
  String get reauthRequired => isZh ? '需要重新认证' : 'Reauth required';
  String get udpSockets => isZh ? 'UDP sockets' : 'UDP sockets';
  String get socketPoolActive => isZh ? 'Socket pool 启用' : 'Socket pool active';
  String get relayConnected => isZh ? '中继连接' : 'Relay connected';
  String get peerCount => isZh ? '设备数' : 'Device count';
  String get healthReason => isZh ? '健康原因' : 'Health reason';
  String get rawStatusJson => isZh ? '原始 /status JSON' : 'Raw /status JSON';
  String get showRawJson => isZh ? '显示 JSON' : 'Show JSON';
  String get hideRawJson => isZh ? '收起 JSON' : 'Hide JSON';
  String get rawJsonCollapsed => isZh
      ? '默认不渲染完整 JSON，减少调试页内存占用。'
      : 'Full JSON is not rendered by default to keep this debug page light.';
  String get copy => isZh ? '复制' : 'Copy';
  String get copied => isZh ? '已复制' : 'Copied';
  String get copiedDiagnosticsJson =>
      isZh ? '诊断 JSON 已复制到剪贴板' : 'Diagnostics JSON copied to clipboard';

  String get nodesSubtitle => isZh
      ? '查看本机节点和网络中的其他设备，管理名称、IP 与连接路径。'
      : 'View this device and other devices in the network, including names, IPs, and paths.';
  String get noPeers => isZh
      ? '当前没有发现其他设备。'
      : 'No other devices are present in the current snapshot.';
  String get peerSummary => isZh ? '设备概览' : 'Device summary';
  String get device => isZh ? '设备' : 'Device';
  String get peerId => isZh ? '节点 ID' : 'Node ID';
  String get state => isZh ? '状态' : 'State';
  String get path => isZh ? '路径' : 'Path';
  String get type => isZh ? '类型' : 'Type';
  String get route => isZh ? '路由' : 'Route';
  String get latency => isZh ? '延迟' : 'Latency';
  String get endpoint => isZh ? '端点' : 'Endpoint';
  String get connectionType => isZh ? '连接类型' : 'Connection type';
  String get direct => isZh ? '直连' : 'Direct';
  String get directTrial => isZh ? '直连试探' : 'Direct trial';
  String get probing => isZh ? '探测中' : 'probing';

  String get settingsSubtitle =>
      isZh ? '本地 P2WLAN 客户端配置。' : 'Local P2WLAN client configuration.';
  String get connectionSettings => isZh ? '连接设置' : 'Connection settings';
  String get language => isZh ? '语言' : 'Language';
  String get languageHelper =>
      isZh ? '仅影响此 Flutter 客户端界面。' : 'Changes only this Flutter client UI.';
  String get english => 'English';
  String get simplifiedChinese => '简体中文';
  String get languageSaved => isZh ? '语言设置已保存' : 'Language saved';
  String get themeMode => isZh ? '主题模式' : 'Theme Mode';
  String get themeModeHelper =>
      isZh ? '支持跟随系统、浅色模式和暗色模式。' : 'Supports system, light, and dark mode.';
  String get themeSystem => isZh ? '跟随系统' : 'System';
  String get themeLight => isZh ? '浅色模式' : 'Light';
  String get themeDark => isZh ? '暗色模式' : 'Dark';
  String get themeSaved => isZh ? '主题设置已保存' : 'Theme saved';
  String get diagnosticsEndpoint => isZh ? '诊断端点' : 'Diagnostics endpoint';
  String get diagnosticsUrlHelper => isZh
      ? '用于本客户端控制、关闭和读取 p2wlan-daemon。'
      : 'Used by this client to control, stop, and read p2wlan-daemon.';
  String get controlServer => isZh ? '控制面服务器' : 'Control server';
  String get authToken => isZh ? '认证 Token' : 'Auth token';
  String get authTokenHelper => isZh
      ? '留空时会以手动/离线模式启动，只用于本机诊断和本地 TUN 验证。'
      : 'Leave empty to start in manual/offline mode for local diagnostics and TUN validation.';
  String get deviceName => isZh ? '设备名称' : 'Device name';
  String get manualMode => isZh ? '手动/离线模式' : 'Manual/offline mode';
  String get manualModeHelper => isZh
      ? '开启后不连接控制面；关闭且提供 Token 后加入托管 P2WLAN 网络。'
      : 'When enabled, the daemon skips control-plane registration. Disable it and provide a token to join the managed P2WLAN network.';
  String get save => isZh ? '保存' : 'Save';
  String get restoreDefaultUrl => isZh ? '恢复默认 URL' : 'Restore default URL';
  String localSettingsFile(String path) =>
      isZh ? '本地设置文件：$path' : 'Local settings file: $path';
  String get daemonControl => isZh ? '守护进程控制' : 'Daemon control';
  String get daemonControlText => isZh
      ? 'Flutter UI 负责跨平台界面；Rust p2wlan-daemon 负责虚拟网卡、路由、加密、NAT 穿透和中继。'
      : 'Flutter owns the cross-platform UI; Rust p2wlan-daemon owns the virtual adapter, routes, crypto, NAT traversal, and relay path.';
  String get diagnosticsUrlSaved =>
      isZh ? '连接设置已保存到本地' : 'Connection settings saved locally';
  String get diagnosticsUrlNotSaved =>
      isZh ? '诊断 URL 未保存' : 'Diagnostics URL was not saved';
  String get failedToSaveLocalSettings =>
      isZh ? '保存本地设置失败' : 'Failed to save local settings';

  String sectionLabel(String sectionName) {
    return switch (sectionName) {
      'dashboard' => dashboard,
      'nodes' => nodes,
      'tunnels' => tunnels,
      'diagnostics' => diagnostics,
      'settings' => settings,
      _ => sectionName,
    };
  }

  String boolLabel(bool value) => value ? yes : no;

  String optionalBoolLabel(bool? value) {
    if (value == null) return '—';
    return boolLabel(value);
  }

  String endpointStatusLabel({
    required bool statusReachable,
    required bool healthReachable,
  }) {
    if (statusReachable) return loaded;
    if (healthReachable) return error;
    return skipped;
  }

  String healthStatusLabel(String status) {
    return switch (status.toLowerCase()) {
      'healthy' => healthy,
      'degraded' => degraded,
      'unhealthy' => unhealthy,
      'shutting_down' => unavailable,
      _ => status,
    };
  }

  String pathLabel(String value) {
    return switch (value) {
      'direct' => direct,
      'relay' => relay,
      'direct_trial' => directTrial,
      'offline' => offline,
      'probing' => probing,
      _ => value.trim().isEmpty ? '—' : value,
    };
  }

  String routeLabel(String path, bool isRelay) {
    if (path == 'direct') return direct;
    if (path == 'relay' || isRelay) return relay;
    return '—';
  }

  String diagnosticsUrlError(String message) {
    if (!isZh) return message;
    return switch (message) {
      'Diagnostics URL is required' => '诊断 URL 不能为空',
      'Diagnostics URL must use http or https' => '诊断 URL 必须使用 http 或 https',
      'Diagnostics URL must include a host' => '诊断 URL 必须包含主机名',
      _ => message,
    };
  }

  String? statusMessage(String? message) {
    if (message == null || !isZh) return message;
    if (message == 'GET /health is offline or unreadable') {
      return 'GET /health 离线或不可读';
    }
    if (message == 'GET /status skipped because /health is offline') {
      return '由于 /health 离线，已跳过 GET /status';
    }
    if (message == 'GET /status skipped because /health failed') {
      return '由于 /health 失败，已跳过 GET /status';
    }
    if (message.startsWith('GET /status failed: ')) {
      return 'GET /status 失败：${message.substring('GET /status failed: '.length)}';
    }
    if (message.startsWith('GET /health failed: ')) {
      return 'GET /health 失败：${message.substring('GET /health failed: '.length)}';
    }
    return message;
  }

  String languageLabel(String code) {
    return switch (AppLanguage.fromCode(code)) {
      AppLanguage.english => english,
      AppLanguage.simplifiedChinese => simplifiedChinese,
    };
  }
}
