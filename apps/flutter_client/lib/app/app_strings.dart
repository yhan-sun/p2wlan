import 'package:flutter/widgets.dart';

import '../core/models/daemon_models.dart';

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

  String get appName => 'P2WLAN Diagnostics';

  String get dashboard => isZh ? '仪表盘' : 'Dashboard';
  String get nodes => isZh ? '节点' : 'Nodes';
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
  String autoRefresh(int seconds) =>
      isZh ? '自动刷新 (${seconds}s)' : 'Auto refresh (${seconds}s)';

  String get dashboardSubtitle => isZh
      ? '只读查看本地 P2WLAN daemon 诊断端点。'
      : 'Read-only view of the local P2WLAN daemon diagnostics endpoint.';
  String get localDaemon => isZh ? '本地 daemon' : 'Local daemon';
  String get diagnosticsUrl => isZh ? '诊断 URL' : 'Diagnostics URL';
  String get daemonState => isZh ? 'Daemon 状态' : 'Daemon state';
  String get lastRefresh => isZh ? '上次刷新' : 'Last refresh';
  String get requestDuration => isZh ? '请求耗时' : 'Request duration';
  String get lastError => isZh ? '最近错误' : 'Last error';
  String get snapshot => isZh ? '快照' : 'Snapshot';
  String get offlineSnapshotMessage => isZh
      ? '当前没有 daemon 快照。请在本 app 外部启动本地 p2pnet-daemon；此客户端只读取诊断信息。'
      : 'No daemon snapshot is available. Run local p2pnet-daemon outside this app; this client operates in read-only diagnostics mode.';
  String get runtimeSnapshot => isZh ? '运行快照' : 'Runtime snapshot';
  String get nodeId => isZh ? '节点 ID' : 'Node ID';
  String get virtualIp => isZh ? '虚拟 IP' : 'Virtual IP';
  String get networkId => isZh ? '网络 ID' : 'Network ID';
  String get daemonHealth => isZh ? 'Daemon 健康' : 'Daemon health';
  String get udpLocalAddr => isZh ? 'UDP 本地地址' : 'UDP local addr';
  String get relay => isZh ? '中继' : 'Relay';
  String get relayRegion => isZh ? '中继区域' : 'Relay region';
  String get peers => isZh ? 'Peer 数' : 'Peers';
  String get peerPaths => isZh ? 'Peer 路径' : 'Peer paths';
  String get totalPeers => isZh ? '总 Peer 数' : 'Total peers';
  String get directPaths => isZh ? '直连路径' : 'Direct paths';
  String get relayPaths => isZh ? '中继路径' : 'Relay paths';
  String get bytesSent => isZh ? '已发送' : 'Bytes sent';
  String get bytesReceived => isZh ? '已接收' : 'Bytes received';

  String get diagnosticsSubtitle => isZh
      ? 'Daemon GET /status 的摘要和原始 JSON。'
      : 'Summary plus raw JSON from daemon GET /status.';
  String get summary => isZh ? '摘要' : 'Summary';
  String get statusLoaded => isZh ? '状态已加载' : 'Status loaded';
  String get noSnapshot => isZh ? '无快照' : 'No snapshot';
  String get controlConnected => isZh ? '控制面连接' : 'Control connected';
  String get reauthRequired => isZh ? '需要重新认证' : 'Reauth required';
  String get udpSockets => isZh ? 'UDP sockets' : 'UDP sockets';
  String get socketPoolActive => isZh ? 'Socket pool 启用' : 'Socket pool active';
  String get relayConnected => isZh ? '中继连接' : 'Relay connected';
  String get peerCount => isZh ? 'Peer 数' : 'Peer count';
  String get healthReason => isZh ? '健康原因' : 'Health reason';
  String get rawStatusJson => isZh ? '原始 /status JSON' : 'Raw /status JSON';
  String get copy => isZh ? '复制' : 'Copy';
  String get copied => isZh ? '已复制' : 'Copied';
  String get copiedDiagnosticsJson =>
      isZh ? '诊断 JSON 已复制到剪贴板' : 'Diagnostics JSON copied to clipboard';

  String get nodesSubtitle => isZh
      ? '从 daemon 状态快照读取的只读 peer 列表。'
      : 'Read-only peer list from the daemon status snapshot.';
  String get noPeers => isZh
      ? '当前 daemon 快照中没有 peers。'
      : 'No peers are present in the current daemon snapshot.';
  String get peerSummary => isZh ? 'Peer 摘要' : 'Peer summary';
  String get device => isZh ? '设备' : 'Device';
  String get peerId => isZh ? 'Peer ID' : 'Peer ID';
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
      isZh ? '本地 Flutter 客户端配置。' : 'Local Flutter client configuration.';
  String get language => isZh ? '语言' : 'Language';
  String get languageHelper =>
      isZh ? '仅影响此 Flutter 客户端界面。' : 'Changes only this Flutter client UI.';
  String get english => 'English';
  String get simplifiedChinese => '简体中文';
  String get languageSaved => isZh ? '语言设置已保存' : 'Language saved';
  String get diagnosticsEndpoint => isZh ? '诊断端点' : 'Diagnostics endpoint';
  String get diagnosticsUrlHelper => isZh
      ? '仅保存到客户端，本 app 只读取 GET /health 和 GET /status。'
      : 'Client-only endpoint configuration (read-only GET /health and GET /status).';
  String get save => isZh ? '保存' : 'Save';
  String get restoreDefaultUrl => isZh ? '恢复默认 URL' : 'Restore default URL';
  String localSettingsFile(String path) =>
      isZh ? '本地设置文件：$path' : 'Local settings file: $path';
  String get p1Boundary => isZh ? 'P1 边界' : 'P1 boundary';
  String get p1BoundaryText => isZh
      ? '此客户端严格保持只读模式，只通过 GET 请求读取 daemon 诊断。进程生命周期、提权、TUN 接口和路由仍完全由核心二进制管理。'
      : 'This client operates strictly in read-only mode, fetching daemon diagnostics via GET requests. Process lifecycle, elevation, TUN interfaces, and routing remain managed exclusively by the core binary.';
  String get diagnosticsUrlSaved =>
      isZh ? '诊断 URL 已保存到本地' : 'Diagnostics URL saved locally';
  String get diagnosticsUrlNotSaved =>
      isZh ? '诊断 URL 未保存' : 'Diagnostics URL was not saved';
  String get failedToSaveLocalSettings =>
      isZh ? '保存本地设置失败' : 'Failed to save local settings';

  String sectionLabel(String sectionName) {
    return switch (sectionName) {
      'dashboard' => dashboard,
      'nodes' => nodes,
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

  String daemonHealthStatus(String status) {
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
