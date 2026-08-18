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
  String get more => isZh ? '更多' : 'More';
  String get navGroupOverview => isZh ? '概览' : 'Overview';
  String get navGroupNetwork => isZh ? '网络' : 'Network';
  String get navGroupTools => isZh ? '工具' : 'Tools';
  String get moreDescription => isZh
      ? '诊断与设置等低频功能。'
      : 'Diagnostics, settings, and other less frequent features.';
  String get restartRequired =>
      isZh ? '需要重启 P2WLAN' : 'P2WLAN restart required';
  String get restartRequiredDetail => isZh
      ? '已保存的网络配置会在重启 daemon 后应用。'
      : 'The saved network configuration is applied when the daemon restarts.';
  String get restartNow => isZh ? '立即重启并应用' : 'Restart and apply';
  String get settingsSavedRestartRequired => isZh
      ? '配置已保存；重启 P2WLAN 后生效。'
      : 'Configuration saved. Restart P2WLAN to apply it.';
  String get settingsApplied => isZh ? '已重启并应用配置。' : 'Configuration applied.';

  String get online => isZh ? '在线' : 'Online';
  String get offline => isZh ? '离线' : 'Offline';
  String get degraded => isZh ? '降级' : 'Degraded';
  String get stale => isZh ? '数据已过期' : 'Stale';
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
  String get refreshNow => isZh ? '手动同步数据' : 'Refresh now';
  String get refreshing => isZh ? '同步数据中...' : 'Refreshing...';
  String get startP2wlan => isZh ? '启动 P2WLAN' : 'Start P2WLAN';
  String get stopP2wlan => isZh ? '停止 P2WLAN' : 'Stop P2WLAN';
  String get daemonWorking => isZh ? '处理中...' : 'Working...';
  String get cancel => isZh ? '取消' : 'Cancel';
  String get close => isZh ? '关闭' : 'Close';
  String get closeWindow => isZh ? '退出应用' : 'Close window';
  String get continueAction => isZh ? '继续' : 'Continue';
  String get lastDaemonAction => isZh ? '最近操作' : 'Last action';
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

  String get dashboardSubtitle => isZh
      ? '启动、停止并监控本机 P2WLAN 虚拟网络。'
      : 'Start, stop, and monitor the local P2WLAN virtual network.';
  String get networkCockpit => isZh ? '虚拟内网驾驶舱' : 'Virtual network cockpit';
  String get virtualNetwork => isZh ? '虚拟内网' : 'Virtual network';
  String get virtualNetworkRunning =>
      isZh ? '虚拟内网运行中' : 'Virtual network running';
  String get virtualNetworkStopped =>
      isZh ? '虚拟内网未启动' : 'Virtual network stopped';
  String get virtualNetworkRunningDetail => isZh
      ? '本机已加入虚拟内网，可查看控制面、设备路径和中继状态。'
      : 'This device is on the virtual network; control-plane, device paths, and relay status are available.';
  String get virtualNetworkStoppedDetail => isZh
      ? '启动后会显示虚拟 IP、控制面和设备路径状态。'
      : 'Start P2WLAN to see virtual IP, control-plane, and device path status.';
  String get networkTitle => isZh ? 'P2WLAN 网络' : 'P2WLAN network';
  String get connectionOverview => isZh ? '连接概览' : 'Connection overview';
  String get networkEnvironment => isZh ? '网络环境' : 'Network environment';
  String get localNode => isZh ? '本机' : 'This device';
  String get udp => isZh ? 'UDP' : 'UDP';
  String get udpAvailable => isZh ? 'UDP 可用' : 'UDP available';
  String get udpUnavailable => isZh ? 'UDP 不可用' : 'UDP unavailable';
  String get dashboardStoppedTitle =>
      isZh ? 'P2WLAN 尚未运行' : 'P2WLAN is not running';
  String get dashboardStoppedDetail => isZh
      ? '启动 P2WLAN 后，这里会显示你的设备和连接状态。'
      : 'Start P2WLAN to see your devices and connection status here.';
  String get dashboardUnavailableTitle =>
      isZh ? '暂时无法获取网络状态' : 'Network status unavailable';
  String get dashboardUnavailableDetail => isZh
      ? '连接控制服务器后，这里会显示你的设备和连接状态。'
      : 'Connect to the control server to see your devices and connection status here.';
  String probeRtt(int probeRttMs) =>
      isZh ? '探测 RTT $probeRttMs ms' : 'probe RTT $probeRttMs ms';
  String moreDevices(int count) => isZh
      ? '还有 $count 台设备，可在「设备」页查看。'
      : '$count more devices — see the Devices page.';
  String get daemonStatus => isZh ? '守护进程' : 'Daemon';
  String get controlPlane => isZh ? '控制面' : 'Control plane';
  String get onlineDevices => isZh ? '在线设备' : 'Online devices';
  String get pathOverview => isZh ? '路径概况' : 'Path overview';
  String get needsAttention => isZh ? '需要处理' : 'Needs attention';
  String get reviewRecommended => isZh ? '建议确认' : 'Review recommended';
  String get noActionNeeded => isZh ? '当前无需处理' : 'No action needed';
  String get dashboardAllGood => isZh
      ? '守护进程、控制面和设备路径没有上报需要处理的问题。'
      : 'Daemon, control-plane, and device paths are not reporting anything that needs action.';
  String get issueControlDisconnected => isZh
      ? '控制面未连接，设备目录和配置同步可能不可用。'
      : 'Control plane is disconnected; device catalog and config sync may be unavailable.';
  String get issueReauthRequired => isZh
      ? '控制面要求重新认证，请检查 Token 或重新登录。'
      : 'Control plane requires re-authentication. Check the token or sign in again.';
  String get issueRelayDisconnected => isZh
      ? '中继未连接，跨 NAT 路径可能不可用。'
      : 'Relay is not connected; cross-NAT paths may be unavailable.';
  String peerWarnings(int count) =>
      isZh ? '$count 台设备上报路径告警。' : '$count device(s) report path warnings.';
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
  String get staleSnapshotMessage => isZh
      ? '运行状态已超过 90 秒未更新。请检查本机 daemon 后手动刷新。'
      : 'Runtime status has not updated for over 90 seconds. Check the local daemon, then refresh.';
  String get snapshotExpired => isZh ? '数据已过期' : 'Snapshot expired';
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
  String get natNetworkType => isZh ? '网络类型' : 'Network type';
  String get natAutoDetected => isZh ? '自动检测' : 'Auto detected';
  String get natDetectionUnavailable =>
      isZh ? '等待 NAT 探测' : 'Waiting for NAT probe';
  String get natDetectionUnavailableDetail => isZh
      ? '启动并刷新后，P2WLAN 会通过 STUN 观测自动判断本机 NAT 类型。'
      : 'Start and refresh P2WLAN to classify this network from STUN observations.';
  String get natPublicEndpoint => isZh ? '公网端点' : 'Public endpoint';
  String get natMappingBehavior => isZh ? '映射行为' : 'Mapping';
  String get natFilteringBehavior => isZh ? '过滤行为' : 'Filtering';
  String get natConfidence => isZh ? '探测置信度' : 'Probe confidence';
  String get natProbabilityTotal => isZh ? '概率合计' : 'Probability total';
  String get natMaxProbability => isZh ? '最大概率' : 'Max probability';
  String get natTypeProbabilities => isZh ? '四类 NAT 概率' : 'NAT probabilities';
  String get natGuideTitle => isZh ? 'NAT 类型说明' : 'NAT type guide';
  String get natGuideAction => isZh ? '查看说明' : 'View guide';
  String get natGuideIntro => isZh
      ? 'P2WLAN 根据本机 UDP/STUN 观测自动分类。下方概率合计会归一为 100%；最大概率表示当前最可能的 NAT 类型。类型越靠前，直连越容易。'
      : 'P2WLAN classifies the local network from UDP/STUN observations. Earlier types are easier for direct paths; later types may need coordinated punching or relay.';
  String get speedTest => isZh ? '测速' : 'Speed test';
  String get speedTesting => isZh ? '测速中 10s...' : 'Testing 10s...';
  String get speedTestTitle => isZh ? '设备测速' : 'Device speed test';
  String get startSpeedTest => isZh ? '开始 10 秒测速' : 'Start 10s test';
  String get speedTestDuration =>
      isZh ? '测试时长：10 秒' : 'Test duration: 10 seconds';
  String get speedTestUnavailable => isZh
      ? '设备离线或没有虚拟 IP，暂时无法测速。'
      : 'This device is offline or has no virtual IP.';
  String speedTestRunningOn(String peer) => isZh
      ? '正在测试 $peer；其他设备请等待本次完成。'
      : 'Testing $peer. Wait for this test to finish.';
  String get speedTestDownload => isZh ? '下行' : 'Download';
  String get speedTestUpload => isZh ? '上行' : 'Upload';
  String get speedTestTransferred => isZh ? '传输数据' : 'Transferred';
  String get speedTestElapsed => isZh ? '已用时间' : 'Elapsed';
  String speedTestProgress(int elapsedSeconds) =>
      isZh ? '$elapsedSeconds / 10 秒' : '$elapsedSeconds / 10 s';
  String get retrySpeedTest => isZh ? '重新测速' : 'Run again';
  String get speedTestTooltip =>
      isZh ? '测试此设备的链路速度' : 'Test this device connection';
  String speedTestPeer(String peer) =>
      isZh ? '链路测速 · $peer' : 'Connection test · $peer';
  String speedTestFailed(String message) =>
      isZh ? '测速失败：$message' : 'Speed test failed: $message';

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
  String get diagnosticIssues =>
      isZh ? '需要处理的问题/建议' : 'Issues and recommendations';
  String get diagnosticNoIssues => isZh
      ? '当前诊断没有发现需要立即处理的问题。'
      : 'Diagnostics found no issue that needs immediate action.';
  String get platformPermissions => isZh ? '平台权限' : 'Platform permissions';
  String get protocolAndMtu => isZh ? '协议与 MTU' : 'Protocol and MTU';
  String get criticalTasks => isZh ? '关键任务' : 'Critical tasks';
  String get recentDaemonLogs => isZh ? '最近 daemon 日志' : 'Recent daemon logs';

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
  String get attentionDevices => isZh ? '异常/需确认' : 'Attention';
  String get directDevices => isZh ? '直连设备' : 'Direct devices';
  String get relayDevices => isZh ? '中继设备' : 'Relay devices';
  String get offlineDevices => isZh ? '离线设备' : 'Offline devices';

  String get searchDevicesPlaceholder => isZh
      ? '搜索设备名称、虚拟 IP 或 Node ID'
      : 'Search device name, virtual IP, or Node ID';
  String get filterAll => isZh ? '全部' : 'All';
  String get sortRecommended => isZh ? '推荐' : 'Recommended';
  String get sortByName => isZh ? '名称' : 'Name';
  String get sortByLatency => isZh ? '延迟' : 'Latency';
  String deviceCountSummary(int total, int online) =>
      isZh ? '$total 台设备 · $online 在线' : '$total devices · $online online';
  String get clearSearch => isZh ? '清除搜索' : 'Clear search';
  String get clearFilter => isZh ? '清除筛选' : 'Clear filters';
  String get noPeersTitle => isZh ? '还没有其他设备' : 'No other devices yet';
  String get noPeersBody => isZh
      ? '登录另一台设备后，它会显示在这里。'
      : 'Sign in on another device and it will appear here.';
  String get noSearchResultsTitle => isZh ? '没有找到匹配设备' : 'No matching devices';
  String get noSearchResultsBody => isZh
      ? '换个关键词，或清除搜索查看全部设备。'
      : 'Try a different query, or clear the search to see all devices.';
  String get noFilterResultsTitle => isZh ? '没有匹配的设备' : 'No matching devices';
  String get noFilterResultsBody => isZh
      ? '当前筛选条件下没有设备，清除筛选查看全部。'
      : 'No devices match this filter. Clear it to see everything.';
  String get sectionConnection => isZh ? '连接' : 'Connection';
  String get sectionNetwork => isZh ? '网络' : 'Network';
  String get sectionDevice => isZh ? '设备' : 'Device';
  String get sectionIssues => isZh ? '问题' : 'Issues';
  String get sectionActions => isZh ? '操作' : 'Actions';
  String get onlineState => isZh ? '在线状态' : 'Online state';
  String get lastSeen => isZh ? '最后在线' : 'Last seen';
  String get pathDecision => isZh ? '路径判定' : 'Path decision';
  String get deviceActions => isZh ? '设备操作' : 'Device actions';
  String get viewDetails => isZh ? '查看详情' : 'View details';
  String get removeDevice => isZh ? '移除设备' : 'Remove device';
  String get copyVirtualIp => isZh ? '复制虚拟 IP' : 'Copy virtual IP';
  String get copyPingCommand => isZh ? '复制 ping 命令' : 'Copy ping command';
  String get renameDevice => isZh ? '修改名称' : 'Rename';
  String get noSelectionHint =>
      isZh ? '选择一台设备查看详情' : 'Select a device to view its details';

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

  /// Label for the "探测中" state: a candidate probe succeeded (RTT shown)
  /// but the DATA path is NOT verified — never displayed as a connection.
  String probingWithProbeRtt(int? probeRttMs) {
    if (probeRttMs == null) return probing;
    return isZh
        ? '探测中 · 候选 RTT ${probeRttMs}ms（未直连）'
        : 'probing · candidate RTT ${probeRttMs}ms (no direct)';
  }

  String routeLabel(String path, bool isRelay) {
    if (path == 'direct') return direct;
    if (path == 'relay' || isRelay) return relay;
    return '—';
  }

  String natTraversalTypeLabel(NatTraversalType type) {
    return switch (type) {
      NatTraversalType.fullCone => isZh ? '全锥形 NAT（FullCone）' : 'FullCone NAT',
      NatTraversalType.restrictedCone =>
        isZh ? '受限锥形 NAT（Restricted Cone）' : 'Restricted Cone NAT',
      NatTraversalType.portRestrictedCone =>
        isZh ? '端口受限锥形 NAT（Port Restricted Cone）' : 'Port Restricted Cone NAT',
      NatTraversalType.symmetric =>
        isZh ? '对称型 NAT（Symmetric）' : 'Symmetric NAT',
      NatTraversalType.openInternet => isZh ? '公网直连' : 'Open Internet',
      NatTraversalType.udpBlocked => isZh ? 'UDP 受阻' : 'UDP blocked',
      NatTraversalType.unknown => isZh ? '未确认' : 'Unknown',
    };
  }

  String natTraversalTypeDescription(NatTraversalType type) {
    return switch (type) {
      NatTraversalType.fullCone =>
        isZh
            ? '公网 IP:Port 稳定，外部任意地址通常都能从该映射回包，直连成功率最高。'
            : 'The public IP:port is stable and replies from any external address are usually accepted, so direct paths are easiest.',
      NatTraversalType.restrictedCone =>
        isZh
            ? '公网端口稳定，但只接受已联系过的外部 IP 回包；同步探测通常可以建立直连。'
            : 'The public port is stable, but replies are accepted only from contacted external IPs; coordinated probing usually works.',
      NatTraversalType.portRestrictedCone =>
        isZh
            ? '公网端口稳定，但外部 IP 和端口都必须先被本机联系过；打洞时序更敏感。'
            : 'The public port is stable, but the remote IP and port must be contacted first; punch timing matters more.',
      NatTraversalType.symmetric =>
        isZh
            ? '访问不同外部地址会产生不同公网端点，是最难直连的类型，常需要预测端口或回退中继。'
            : 'Different destinations create different public endpoints, making direct paths hardest and often requiring prediction or relay.',
      NatTraversalType.openInternet =>
        isZh
            ? '本机 UDP 端点看起来可被公网直接访问，通常不需要 NAT 打洞。'
            : 'The local UDP endpoint appears directly reachable from the public network, so NAT punching is usually unnecessary.',
      NatTraversalType.udpBlocked =>
        isZh
            ? 'STUN/UDP 探测没有可用响应，直连可能不可用，建议优先检查防火墙或使用中继。'
            : 'STUN/UDP probing did not receive usable responses; direct paths may be unavailable, so check firewalls or use relay.',
      NatTraversalType.unknown =>
        isZh
            ? '当前观测不足以精确区分 NAT 类型，可刷新或换网络后再确认。'
            : 'Current observations are not enough to classify the NAT precisely; refresh or retry on another network.',
    };
  }

  String natTraversalTypeAdvice(NatTraversalType type) {
    return switch (type) {
      NatTraversalType.fullCone =>
        isZh
            ? '提示：这是最友好的直连环境，P2WLAN 通常可以优先尝试 Direct。'
            : 'Tip: this is the friendliest direct-path environment, so P2WLAN can usually prefer Direct.',
      NatTraversalType.restrictedCone =>
        isZh
            ? '提示：保持双端在线并让双方同时探测，有助于快速建立直连。'
            : 'Tip: keep both peers online and probing at the same time to establish Direct quickly.',
      NatTraversalType.portRestrictedCone =>
        isZh
            ? '提示：如果直连不稳定，保留中继作为兜底，并尽量避免频繁切换网络。'
            : 'Tip: keep relay as a fallback if Direct is unstable, and avoid frequent network switching.',
      NatTraversalType.symmetric =>
        isZh
            ? '提示：这是困难 NAT。P2WLAN 会尝试预测/生日探测，但中继可能更稳定。'
            : 'Tip: this is a hard NAT. P2WLAN will try prediction/birthday probing, but relay may be more stable.',
      NatTraversalType.openInternet =>
        isZh
            ? '提示：请确认系统防火墙允许 P2WLAN UDP 入站。'
            : 'Tip: confirm that the system firewall allows inbound P2WLAN UDP.',
      NatTraversalType.udpBlocked =>
        isZh
            ? '提示：检查路由器、系统防火墙或公司网络策略是否阻断 UDP。'
            : 'Tip: check whether the router, system firewall, or corporate policy blocks UDP.',
      NatTraversalType.unknown =>
        isZh
            ? '提示：保持自动轮询或手动刷新，等待更多 STUN 观测。'
            : 'Tip: keep auto sync on or refresh manually to collect more STUN observations.',
    };
  }

  String natBehaviorLabel(String value) {
    return switch (value.toLowerCase()) {
      'open_internet' => isZh ? '公网直连' : 'Open Internet',
      'endpoint_independent' => isZh ? '端点无关' : 'Endpoint independent',
      'likely_endpoint_independent' =>
        isZh ? '可能端点无关' : 'Likely endpoint independent',
      'address_dependent' => isZh ? '地址相关' : 'Address dependent',
      'address_or_port_dependent' =>
        isZh ? '地址/端口相关' : 'Address/port dependent',
      'udp_blocked' => isZh ? 'UDP 受阻' : 'UDP blocked',
      'unknown' => isZh ? '未知' : 'Unknown',
      '' => '—',
      _ => value,
    };
  }

  String natTraversalShortLabel(NatTraversalType type) {
    return switch (type) {
      NatTraversalType.fullCone => isZh ? '全锥形' : 'FullCone',
      NatTraversalType.restrictedCone => isZh ? '受限锥形' : 'Restricted',
      NatTraversalType.portRestrictedCone => isZh ? '端口受限' : 'Port restricted',
      NatTraversalType.symmetric => isZh ? '对称型' : 'Symmetric',
      NatTraversalType.openInternet => isZh ? '公网' : 'Open',
      NatTraversalType.udpBlocked => isZh ? 'UDP 受阻' : 'UDP blocked',
      NatTraversalType.unknown => isZh ? '未知' : 'Unknown',
    };
  }

  String natMostLikelyTitle(List<NatTraversalType> types, String probability) {
    final labels = types.map(natTraversalShortLabel).join(isZh ? ' / ' : ' / ');
    if (types.length > 1) {
      return isZh
          ? '最大概率并列：$labels（各 $probability）'
          : 'Max probability tie: $labels ($probability each)';
    }
    return isZh
        ? '最大概率：$labels（$probability）'
        : 'Max probability: $labels ($probability)';
  }

  String natCurrentTypeWithProbability(
    List<NatTraversalType> types,
    String probability,
  ) {
    final labels = types.map(natTraversalShortLabel).join(' / ');
    if (types.length > 1) {
      return isZh ? '$labels（各 $probability）' : '$labels ($probability each)';
    }
    return isZh ? '$labels（$probability）' : '$labels ($probability)';
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
