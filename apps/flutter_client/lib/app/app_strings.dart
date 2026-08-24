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

  String get nodes => isZh ? '节点' : 'Nodes';
  String get diagnostics => isZh ? '诊断' : 'Diagnostics';
  String get settings => isZh ? '设置' : 'Settings';

  /// User-level navigation labels.
  String get home => isZh ? '首页' : 'Home';
  String get troubleshooting => isZh ? '故障排查' : 'Troubleshooting';
  String get menu => isZh ? '菜单' : 'Menu';

  // --- Shell status summary (desktop sidebar footer) ---
  String get shellStatusHealthy => isZh ? '网络正常' : 'Network OK';
  String get shellStatusAttention => isZh ? '网络异常' : 'Network issue';
  String get shellStatusOffline => isZh ? '当前离线' : 'Offline';
  String get shellStatusOfflineDetail =>
      isZh ? '无法连接本地服务' : 'Cannot reach local service';
  String get shellStatusStaleDetail =>
      isZh ? '刷新查看最新状态' : 'Refresh to see latest status';
  String shellPeersOnline(int count) => isZh
      ? '$count 台设备在线'
      : count == 1
      ? '1 device online'
      : '$count devices online';
  String get openTroubleshooting => isZh ? '打开故障排查' : 'Open troubleshooting';
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
  String get back => isZh ? '返回' : 'Back';
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
      ? 'P2WLAN 需要管理员权限创建虚拟网卡和路由。首次输入后，密码会加密保存在本地配置文件中。'
      : 'P2WLAN needs administrator access for the virtual adapter and routes. Enter the password once; it is encrypted in the local configuration file.';
  String get manualLaunchCommand => isZh ? '手动启动命令' : 'Manual launch command';
  String get manualLaunchCommandBody => isZh
      ? '如果系统授权失败，可以复制下面的命令到终端执行，然后回到 P2WLAN 点击刷新。'
      : 'If system authorization fails, copy this command into Terminal, then return to P2WLAN and refresh.';
  String get copyLaunchCommand => isZh ? '复制命令' : 'Copy command';
  String get copiedLaunchCommand => isZh ? '启动命令已复制' : 'Launch command copied';

  // --- Home (network overview) ---
  String get homePageSubtitle =>
      isZh ? '网络状态与在线设备一览。' : 'Network status and online devices.';
  String get homeNetworkTitle => isZh ? '网络状态' : 'Network status';
  String get homeJoinedSubtitle =>
      isZh ? '你的设备已加入 P2WLAN 网络' : 'Your device is on the P2WLAN network';
  String get virtualIpLabel => isZh ? '虚拟 IP 地址' : 'Virtual IP address';
  String get homeLoading => isZh ? '正在获取网络状态…' : 'Fetching network status…';
  String get homeStoppedTitle => isZh ? 'P2WLAN 未运行' : 'P2WLAN is not running';
  String get homeStoppedDetail =>
      isZh ? '启动后即可加入虚拟网络。' : 'Start it to join the virtual network.';
  String get homeUnavailableTitle =>
      isZh ? '无法连接 P2WLAN' : 'Cannot reach P2WLAN';
  String get homeUnavailableDetail => isZh
      ? '本地网络服务当前不可用。'
      : 'The local network service is currently unavailable.';
  String get mobileModeBadge => isZh ? '移动端' : 'Mobile';
  String get mobileModeTitle => isZh ? '移动端管理模式' : 'Mobile management mode';
  String get mobileModeDetail => isZh
      ? 'Android 当前用于查看和管理网络、设备。本机不启动桌面 daemon；需要本地 VPN 节点时，请使用已支持的桌面端。'
      : 'Android is used to view and manage the network and devices. It does not start the desktop daemon locally; use a supported desktop node when this device needs a local VPN tunnel.';
  String get mobileModeOpenDevices => isZh ? '查看设备' : 'View devices';
  String get statusNormal => isZh ? '正常' : 'Normal';
  String get notRunning => isZh ? '未运行' : 'Not running';
  String get checkAgain => isZh ? '重新检查' : 'Check again';
  String get homeStaleNote => isZh ? '数据可能已过期' : 'Data may be out of date';
  String get viewAllDevices => isZh ? '查看全部' : 'View all';
  String get noDevicesOnline => isZh ? '暂无其他设备在线' : 'No other devices online';
  String get noDevicesOnlineDetail =>
      isZh ? '设备上线后会显示在这里。' : 'Devices appear here when they come online.';
  String get networkComponents => isZh ? '网络组件状态' : 'Network components';
  String get componentControlServer => isZh ? '控制服务器' : 'Control server';
  String get componentOverlayRoute => isZh ? 'Overlay 路由' : 'Overlay route';
  String get componentPeerConnectivity => isZh ? '设备连接' : 'Device connectivity';
  String get componentStatusNormal => isZh ? '正常' : 'Normal';
  String get componentStatusDisconnected => isZh ? '未连接' : 'Disconnected';
  String get componentStatusLeaseLost =>
      isZh ? '在线租约刷新失败' : 'Online lease refresh failed';
  String get componentStatusConnecting => isZh ? '连接中' : 'Connecting';
  String get componentStatusError => isZh ? '异常' : 'Error';
  String get componentStatusUnknown => isZh ? '未知' : 'Unknown';
  String get homeIssueTitle => isZh ? '发现网络问题' : 'Network issue found';
  String get checkIssues => isZh ? '检查问题' : 'Check issues';
  String get manualStartNeeded =>
      isZh ? '需要手动启动 P2WLAN' : 'Manual start needed';
  String get viewCommand => isZh ? '查看命令' : 'View command';
  String get hideCommand => isZh ? '收起' : 'Hide';

  String probeRtt(int probeRttMs) =>
      isZh ? '探测 RTT $probeRttMs ms' : 'probe RTT $probeRttMs ms';
  String get onlineDevices => isZh ? '在线设备' : 'Online devices';
  String get needsAttention => isZh ? '需要处理' : 'Needs attention';
  String get noActionNeeded => isZh ? '当前无需处理' : 'No action needed';
  String get issueControlDisconnected => isZh
      ? '控制面未连接，设备目录和配置同步可能不可用。'
      : 'Control plane is disconnected; device catalog and config sync may be unavailable.';
  String get issueDeviceLeaseLost => isZh
      ? '本设备的服务端在线租约刷新失败，对端可能已将本机标记为离线。'
      : "This device's server-side online lease could not be refreshed; peers may now see it as offline.";
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
  String get natType => isZh ? 'NAT 类型' : 'NAT type';
  String get natNetworkType => isZh ? '网络类型' : 'Network type';
  String get natAutoDetected => isZh ? '自动检测' : 'Auto detected';
  String get natDetectionUnavailable =>
      isZh ? '等待 NAT 探测' : 'Waiting for NAT probe';
  String get natDetectionUnavailableDetail => isZh
      ? '启动并刷新后，P2WLAN 会通过 STUN 观测自动判断本机 NAT 类型。'
      : 'Start and refresh P2WLAN to classify this network from STUN observations.';
  String get natTypeDetectionInProgress => isZh ? '检测中' : 'Detecting';
  String get natTypeDetectionInProgressDetail => isZh
      ? '正在探测过滤规则，完成后显示全锥形、受限锥形、端口受限锥形或对称型。'
      : 'Filtering behavior is being probed. The result will be Full Cone, Restricted Cone, Port-Restricted Cone, or Symmetric.';
  String get natTypeConservativeFallbackDetail => isZh
      ? '公网映射已确认稳定；当前 STUN 服务不支持过滤探测，暂按最保守的端口受限锥形显示。'
      : 'The public mapping is stable, but this STUN service does not expose filtering probes; Port-Restricted Cone is shown as the conservative fallback.';
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
  String get speedTestDownloadRate => isZh ? '下行速度' : 'Download speed';
  String get speedTestUploadRate => isZh ? '上行速度' : 'Upload speed';
  String get speedTestAverageDownload => isZh ? '平均下行' : 'Average download';
  String get speedTestAverageUpload => isZh ? '平均上行' : 'Average upload';
  String get speedTestLocalRtt => isZh ? '本端 RTT' : 'Local RTT';
  String get speedTestMbps => 'Mbps';
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
      ? '检查 P2WLAN 服务状态，并查看需要处理的问题。'
      : 'Check P2WLAN service status and see what needs attention.';
  String get systemStatus => isZh ? '系统状态' : 'System status';
  String get rechecking => isZh ? '正在检查…' : 'Checking…';
  String get openDevices => isZh ? '查看设备' : 'View devices';
  String get openSettings => isZh ? '打开设置' : 'Open settings';
  String get networkAndRoutes => isZh ? '网络与路由' : 'Network & routes';
  String get virtualNetwork => isZh ? '虚拟网络' : 'Virtual network';
  String get supportTools => isZh ? '支持工具' : 'Support tools';
  String get diagnosticsOverview => isZh ? '诊断概览' : 'Diagnostics overview';
  String get healthChecks => isZh ? '状态检查' : 'Health checks';
  String get p2wlanService => isZh ? 'P2WLAN 服务' : 'P2WLAN service';
  String get controlService => isZh ? '控制服务' : 'Control service';
  String get deviceConnections => isZh ? '设备连接' : 'Device connections';
  String get runningNormally => isZh ? '正常运行' : 'Running normally';
  String get needsAction => isZh ? '需要处理' : 'Needs attention';
  String get advancedDiagnostics => isZh ? '高级诊断' : 'Advanced diagnostics';
  String get advancedDiagnosticsSubtitle => isZh
      ? '端点、权限、协议、日志和原始状态'
      : 'Endpoints, permissions, protocol, logs, and raw status';
  String get runtimeDetails => isZh ? '运行详情' : 'Runtime details';
  String get healthEndpoint => isZh ? '健康端点' : 'Health endpoint';
  String get statusEndpoint => isZh ? '状态端点' : 'Status endpoint';
  String get healthEndpointReachable =>
      isZh ? '健康端点可达' : 'Health endpoint reachable';
  String get healthEndpointOffline =>
      isZh ? '健康端点不可达' : 'Health endpoint offline';
  String get overviewHealthyTitle =>
      isZh ? 'P2WLAN 运行正常' : 'P2WLAN is running normally';
  String get overviewHealthyDetail =>
      isZh ? '当前没有发现需要处理的问题。' : 'No issues found that need your attention.';
  String get overviewAttentionTitle =>
      isZh ? 'P2WLAN 需要检查' : 'P2WLAN needs attention';
  String get overviewAttentionDetail =>
      isZh ? '部分网络功能当前可能受影响。' : 'Some network features may be affected.';
  String get overviewUnavailableTitle =>
      isZh ? '暂时无法获取诊断状态' : 'Diagnostics unavailable';
  String get overviewUnavailableDetail => isZh
      ? '无法读取 P2WLAN 当前运行状态，请稍后重试。'
      : 'Unable to read the current P2WLAN status. Please try again.';
  String get overviewStaleTitle =>
      isZh ? '诊断数据已过期' : 'Diagnostics data is stale';
  String get overviewStaleDetail => isZh
      ? '当前显示的是上一次成功获取的数据。'
      : 'Showing data from the last successful refresh.';
  String devicesOnlineOk(int online) =>
      isZh ? '$online 台在线，无路径异常' : '$online online, no path anomalies';
  String devicesOnlineNeedsCheck(int online, int count) =>
      isZh ? '$online 台在线，$count 台需检查' : '$online online, $count need review';
  String get issueCannotReachService =>
      isZh ? '无法连接 P2WLAN 服务' : 'Cannot reach the P2WLAN service';
  String get issueCannotReachServiceDetail => isZh
      ? '请稍后重试，或检查 P2WLAN 服务是否已启动。'
      : 'Please try again, or check whether the P2WLAN service is running.';
  String get issueStatusUnavailableTitle =>
      isZh ? '运行状态暂时不可用' : 'Runtime status temporarily unavailable';
  String get issueStatusUnavailableDetail => isZh
      ? '服务可达，但运行状态暂时不可用。'
      : 'The service is reachable, but runtime status is temporarily unavailable.';
  String get issueReauthTitle => isZh ? '需要重新登录' : 'Re-authentication required';
  String get issueReauthDetail => isZh
      ? '当前认证已失效，请重新登录后再试。'
      : 'Your authentication has expired. Please sign in again.';
  String get issueControlServerTitle =>
      isZh ? '控制服务器连接异常' : 'Control server connection issue';
  String get issueControlServerDetail => isZh
      ? '设备目录和配置同步可能暂时不可用。请检查网络或控制服务器设置后刷新。'
      : 'Device catalog and config sync may be temporarily unavailable. Check your network or control server settings, then refresh.';
  String get issueCriticalTaskTitle =>
      isZh ? '关键网络任务需要处理' : 'Critical network tasks need attention';
  String get issueCriticalTaskDetail =>
      isZh ? '后台网络任务出现异常。' : 'A background network task is failing.';
  String get issueServiceStatusTitle =>
      isZh ? '运行状态异常' : 'Runtime status degraded';
  String get issueServiceStatusDetail => isZh
      ? 'P2WLAN 服务上报了异常状态。'
      : 'The P2WLAN service reported an abnormal status.';
  String get issueStaleDetail =>
      isZh ? '建议刷新状态。' : 'Try refreshing the status.';
  String get issueRelayTitle =>
      isZh ? '中继路径需要检查' : 'Relay path needs attention';
  String get issueRelayDetail => isZh
      ? '中继路径出现异常，部分跨 NAT 连接可能受影响。'
      : 'The relay path is failing; some cross-NAT connections may be affected.';
  String devicesNeedPathReview(int count) => isZh
      ? '$count 台设备的连接路径需要检查'
      : count == 1
      ? '1 device needs path review'
      : '$count devices need path review';
  String get issuePeerPathsDetail =>
      isZh ? '具体设备请到「设备」页查看。' : 'See the Devices page for specific devices.';
  String get copyDiagnosticsSummary =>
      isZh ? '复制诊断摘要' : 'Copy diagnostics summary';
  String get diagnosticsSummaryCopied =>
      isZh ? '诊断摘要已复制' : 'Diagnostics summary copied';
  String get cannotReadLogs => isZh ? '无法读取日志' : 'Unable to read logs';
  String get cannotOpenLogsTitle => isZh ? '无法打开日志目录' : 'Could not open logs';
  String get cannotOpenLogsDetail =>
      isZh ? '请确认系统文件管理器可用。' : 'Make sure a file manager is available.';
  String get logsOpened => isZh ? '日志目录已打开' : 'Log directory opened';
  String get summary => isZh ? '摘要' : 'Summary';
  String get statusLoaded => isZh ? '状态已加载' : 'Status loaded';
  String get noSnapshot => isZh ? '无快照' : 'No snapshot';
  String get controlConnected => isZh ? '控制面连接' : 'Control connected';
  String get controlApiReachable =>
      isZh ? '控制 API 可达' : 'Control API reachable';
  String get deviceLeaseHealthy => isZh ? '服务端在线租约' : 'Server online lease';
  String get lastDeviceLeaseSuccess => isZh ? '上次租约刷新' : 'Last lease refresh';
  String get reauthRequired => isZh ? '需要重新认证' : 'Reauth required';
  String get udpSockets => isZh ? 'UDP Socket 数' : 'UDP sockets';
  String get socketPoolActive => isZh ? 'Socket 池状态' : 'Socket pool active';
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
      ? '查看本机和网络中的其他设备，管理名称、IP 与连接方式。'
      : 'View this device and other devices in the network, including names, IPs, and paths.';
  String get noPeers => isZh
      ? '当前没有发现其他设备。'
      : 'No other devices are present in the current snapshot.';
  String get device => isZh ? '设备' : 'Device';
  String get peerId => isZh ? '节点 ID' : 'Node ID';
  String get state => isZh ? '状态' : 'State';
  String get path => isZh ? '路径' : 'Path';
  String get type => isZh ? '类型' : 'Type';
  String get route => isZh ? '路由' : 'Route';
  String get latency => isZh ? '本端 RTT' : 'Local RTT';
  String get localAverageRtt => isZh ? '本端平均 RTT' : 'Local average RTT';
  String get transferSpeed => isZh ? '传输速度' : 'Transfer speed';
  String get endpoint => isZh ? '端点' : 'Endpoint';
  String get connectionType => isZh ? '连接类型' : 'Connection type';
  String get direct => isZh ? '直连' : 'Direct';
  String get directTrial => isZh ? '直连试探' : 'Direct trial';
  String get probing => isZh ? '探测中' : 'probing';
  String get filter => isZh ? '筛选' : 'Filter';

  String get searchDevicesPlaceholder => isZh
      ? '搜索设备名称、虚拟 IP 或 Node ID'
      : 'Search device name, virtual IP, or Node ID';
  String get filterAll => isZh ? '全部' : 'All';
  String get sortByJoinOrder => isZh ? '加入顺序' : 'Join order';
  String get sortByOnlineFirst => isZh ? '在线优先' : 'Online first';
  String get sortRecommended => sortByOnlineFirst;
  String get sortByName => isZh ? '名称' : 'Name';
  String get sortByLatency => isZh ? '本端 RTT' : 'Local RTT';
  String deviceCountSummary(int total, int online) => isZh
      ? '$total 台设备 · $online 在线'
      : total == 1
      ? '1 device · $online online'
      : '$total devices · $online online';
  String get clearSearch => isZh ? '清除搜索' : 'Clear search';
  String get clearFilter => isZh ? '清除筛选' : 'Clear filters';
  String get noPeersTitle => isZh ? '还没有其他设备' : 'No other devices yet';
  String get noPeersBody => isZh
      ? '当其他设备加入 P2WLAN 后，它们会出现在这里。'
      : 'When another device joins P2WLAN, it will appear here.';
  String get noSearchResultsTitle => isZh ? '没有找到设备' : 'No devices found';
  String get noSearchResultsBody => isZh
      ? '检查名称、虚拟 IP 或 Node ID。'
      : 'Check the name, virtual IP, or Node ID.';
  String get noFilterResultsTitle =>
      isZh ? '没有符合当前筛选条件的设备' : 'No devices match this filter';
  String get noFilterResultsBody =>
      isZh ? '清除筛选后即可查看全部设备。' : 'Clear the filter to see all devices.';
  String get sectionConnection => isZh ? '连接' : 'Connection';
  String get sectionNetwork => isZh ? '网络' : 'Network';
  String get sectionDevice => isZh ? '设备' : 'Device';
  String get sectionIssues => isZh ? '问题' : 'Issues';
  String get sectionActions => isZh ? '操作' : 'Actions';
  String get advancedInfo => isZh ? '高级信息' : 'Advanced';
  String get onlineState => isZh ? '在线状态' : 'Online state';
  String get lastSeen => isZh ? '最后在线' : 'Last seen';
  String get pathDecision => isZh ? '路径判定' : 'Path decision';
  String get deviceActions => isZh ? '设备操作' : 'Device actions';
  String get viewDetails => isZh ? '查看详情' : 'View details';
  String get deviceDetails => isZh ? '设备详情' : 'Device details';
  String get connectionInProgressTitle =>
      isZh ? '正在建立可用连接' : 'Establishing a connection';
  String get connectionInProgressBody => isZh
      ? '设备在线，但直连或中继路径尚未确认。P2WLAN 会继续在后台探测。'
      : 'The device is online, but a direct or relay path is not confirmed yet. P2WLAN will keep probing in the background.';
  String get deviceUnavailableTitle =>
      isZh ? '设备暂时不可达' : 'Device is currently unreachable';
  String get deviceUnavailableBody => isZh
      ? '设备可能未运行、网络受限，或刚刚断开连接。'
      : 'The device may be stopped, network-restricted, or recently disconnected.';
  String get connectionNeedsAttentionTitle =>
      isZh ? '连接需要关注' : 'Connection needs attention';
  String get connectionNeedsAttentionBody => isZh
      ? '当前路径出现异常，P2WLAN 会继续尝试恢复连接。'
      : 'The current path reported a problem. P2WLAN will keep trying to recover.';
  String get technicalDetails => isZh ? '技术详情' : 'Technical details';
  String get hideTechnicalDetails => isZh ? '收起技术详情' : 'Hide technical details';
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

  // --- Settings information architecture ---
  String get settingsSectionGeneral => isZh ? '常规' : 'General';
  String get settingsSectionAccountNetwork =>
      isZh ? '账号与网络' : 'Account & Network';
  String get settingsSectionAdvancedNetwork =>
      isZh ? '高级网络' : 'Advanced Network';
  String get settingsSectionDeveloperDiagnostics =>
      isZh ? '开发与诊断' : 'Developer & Diagnostics';
  // --- Settings category / IA ---
  String get settingsCategoryApplication => isZh ? '应用' : 'App';
  String get unsavedChanges => isZh ? '有未保存的更改' : 'Unsaved changes';
  String get udpSubsection => 'UDP';
  String get relaySubsection => 'Relay';

  String get saveChanges => isZh ? '保存更改' : 'Save changes';
  String get saveChangesRestartRequired =>
      isZh ? '保存更改并应用（需重启）' : 'Save changes (restart needed)';
  String get disclosureExpand => isZh ? '展开' : 'Expand';
  String get disclosureCollapse => isZh ? '收起' : 'Collapse';

  // General
  String get deviceNameHelper =>
      isZh ? '留空保存时会使用当前主机名。' : 'If left empty, the current hostname is used.';
  String get closeBehavior => isZh ? '关闭窗口行为' : 'Close window behavior';
  String get closeBehaviorHelper => isZh
      ? '关闭主窗口后，P2WLAN 是否继续保持后台运行。'
      : 'Whether P2WLAN keeps running in the background after the main window closes.';
  String get closeBehaviorKeepRunning =>
      isZh ? '继续在后台运行' : 'Keep running in background';
  String get closeBehaviorStopAndQuit => isZh ? '停止 P2WLAN' : 'Stop P2WLAN';

  // Credential / account
  String get credentialSectionTitle => isZh ? '认证凭据' : 'Authentication';
  String get credentialSaved => isZh ? '已安全保存' : 'Securely saved';
  String get credentialNotSaved => isZh ? '未保存凭据' : 'No credential saved';
  String get credentialManualMode =>
      isZh ? '手动模式无需凭据' : 'Manual mode, no credential needed';
  String get changeCredential => isZh ? '更换凭据' : 'Change credential';
  String get hideCredential => isZh ? '收起' : 'Hide';
  String get credentialChangeHelper => isZh
      ? '输入新的认证 Token 以替换当前凭据；留空保存将保留现有凭据。'
      : 'Enter a new auth token to replace the current credential. Leaving it blank on save keeps the existing credential.';
  String get signOut => isZh ? '退出登录' : 'Sign out';

  // Advanced network
  String get advancedNetworkSubtitle => isZh
      ? 'TUN、MTU、UDP、NAT 穿透与 Relay 参数。'
      : 'TUN, MTU, UDP, NAT traversal, and relay parameters.';
  String get interfaceName => isZh ? '网卡设备名称' : 'Interface name';
  String get interfaceNameHelper =>
      isZh ? defaultTunInterface : defaultTunInterface;
  String get mtu => 'MTU';
  String get mtuHelper => isZh
      ? '建议 1420；Relay 路径异常时可尝试 1280。'
      : '1420 is recommended; try 1280 for relay path issues.';
  String get overlayCidr => 'Overlay CIDR';
  String get overlayCidrHelper =>
      isZh ? defaultOverlayCidr : defaultOverlayCidr;
  String get udpBind => isZh ? 'UDP 监听地址' : 'UDP bind';
  String get udpBindHelper => '0.0.0.0:0';
  String get udpAdvertise => isZh ? '公网 UDP 地址' : 'UDP advertise';
  String get udpAdvertiseHelper => isZh
      ? '云主机固定入口，例如 203.0.113.10:60207。'
      : 'Fixed cloud endpoint such as 203.0.113.10:60207.';
  String get socketPool => isZh ? '增强打洞 socket pool' : 'Socket pool';
  String get socketPoolHelper => isZh
      ? '困难 NAT 下增加受控 UDP 映射，推荐 3。'
      : 'Adds bounded UDP mappings for hard NATs; 3 is recommended.';
  String get socketPoolOff => isZh ? '关闭' : 'Off';
  String get socketPool2 => isZh ? '2 个 Socket' : '2 sockets';
  String get socketPool3 => isZh ? '3 个 Socket' : '3 sockets';
  String get socketPool4 => isZh ? '4 个 Socket' : '4 sockets';
  String get relayCandidates => isZh ? 'Relay 候选' : 'Relay candidates';
  String get relayCandidatesHelper => isZh
      ? '可选，逗号分隔，格式 region@ip:port 或 ip:port。'
      : 'Optional comma-separated region@ip:port or ip:port entries.';
  String get advancedNetworkInactiveHint => isZh
      ? '当前平台未启用本地节点，以下参数暂不适用。'
      : 'This platform does not run a local node; these parameters do not apply.';

  // Developer & diagnostics
  String get developerSectionSubtitle =>
      isZh ? '本地服务与诊断参数。' : 'Local service and diagnostic parameters.';
  String get localService => isZh ? '本地服务' : 'Local service';
  String get daemonRunning => isZh ? '运行中' : 'Running';
  String get daemonStopped => isZh ? '未运行' : 'Not running';
  String get localSettingsFileLabel => isZh ? '配置文件位置' : 'Config file location';
  String get clientBuildIdentity =>
      isZh ? 'Flutter Client 构建身份' : 'Flutter client build identity';
  String get daemonBuildIdentity =>
      isZh ? 'daemon 构建身份' : 'Daemon build identity';
  String get clientLogFileLabel => isZh ? 'Client 启动日志' : 'Client startup log';
  String get daemonLogFileLabel => isZh ? 'daemon 日志' : 'Daemon log';
  String get uploadCurrentSessionLogs =>
      isZh ? '上传本次启动日志' : 'Upload current startup logs';
  String get uploadingLogs => isZh ? '上传中...' : 'Uploading...';
  String get uploadLogsTitle => isZh ? '上传本次启动日志？' : 'Upload startup logs?';
  String get uploadLogsBody => isZh
      ? '只会上传本次启动产生的 daemon 日志和当前启动 trace。日志会先脱敏，但可能包含设备名称、网络地址和连接诊断信息。'
      : 'Only the daemon log and startup trace from this launch will be uploaded. Logs are redacted first, but may contain the device name, network addresses, and connection diagnostics.';
  String get uploadLogsConfirm => isZh ? '确认上传' : 'Upload';
  String logsUploaded(String uploadId) =>
      isZh ? '日志已上传，编号：$uploadId' : 'Logs uploaded. ID: $uploadId';
  String get logsUploadFailed =>
      isZh ? '日志上传失败，请稍后重试。' : 'Log upload failed. Try again later.';
  String get logsUploadRequiresLogin =>
      isZh ? '请先登录后再上传日志。' : 'Sign in before uploading logs.';
  String get buildCommitLabel => isZh ? 'Git commit' : 'Git commit';
  String get buildIdLabel => isZh ? 'Build ID' : 'Build ID';
  String get buildDirtyLabel => isZh ? 'Dirty' : 'Dirty';
  String get buildDiffHashLabel => isZh ? 'Diff hash' : 'Diff hash';
  String get buildProfileLabel => isZh ? '构建配置' : 'Profile';
  String get protocolProfileLabel => isZh ? '配置档' : 'Profile';
  String get statusOk => isZh ? '正常' : 'OK';
  String get statusWarn => isZh ? '警告' : 'WARN';
  String get restartWillApplyLater => isZh
      ? '这些设置将在相关节点下次启动时生效。'
      : 'These settings take effect the next time the relevant node starts.';
  String get settingsSubtitleAccountNetwork => isZh
      ? '登录凭据、控制面与网络标识。'
      : 'Credentials, control plane, and network identity.';

  // --- Login / authentication ---
  String get loginSubtitleDesktop => isZh
      ? '登录后连接这台设备到你的 P2WLAN 网络。'
      : 'Sign in to connect this device to your P2WLAN network.';
  String get loginSubtitleMobile => isZh
      ? '登录后查看和管理你的 P2WLAN 网络与设备。'
      : 'Sign in to view and manage your P2WLAN network and devices.';
  String get email => isZh ? '邮箱' : 'Email';
  String get password => isZh ? '密码' : 'Password';
  String get signIn => isZh ? '登录' : 'Sign in';
  String get signingIn => isZh ? '登录中...' : 'Signing in...';
  String get createAccount => isZh ? '创建账号' : 'Create account';
  String get creatingAccount => isZh ? '创建账号中...' : 'Creating account...';
  String get noAccountYet =>
      isZh ? '没有账号？创建账号' : "Don't have an account? Create one";
  String get alreadyHaveAccount =>
      isZh ? '已有账号？登录' : 'Already have an account? Sign in';
  String get advancedOptions => isZh ? '高级选项' : 'Advanced options';
  String get advancedOptionsSubtitle =>
      isZh ? '自托管服务器、手动 / 离线模式' : 'Self-hosted server, manual / offline mode';
  String get selfHostedServer => isZh ? '自托管服务器' : 'Self-hosted server';
  String get usingCustomServer =>
      isZh ? '正在使用自托管服务器' : 'Using a self-hosted server';
  String get manualOfflineMode => isZh ? '手动 / 离线模式' : 'Manual / offline mode';
  String get manualOfflineModeHelper => isZh
      ? '不连接控制服务器，仅用于本地网络测试和诊断。'
      : 'Does not connect to a control server; for local network testing and diagnostics only.';
  String get continueOffline =>
      isZh ? '继续使用手动 / 离线模式' : 'Continue in manual / offline mode';
  String get showPassword => isZh ? '显示密码' : 'Show password';
  String get hidePassword => isZh ? '隐藏密码' : 'Hide password';
  String get loginErrorEmailRequired => isZh ? '请输入邮箱' : 'Enter your email';
  String get loginErrorPasswordTooShort =>
      isZh ? '密码至少需要 6 个字符' : 'Password must be at least 6 characters';
  String get loginErrorInvalidServerTitle =>
      isZh ? '控制服务器地址无效' : 'Invalid control server address';
  String get loginErrorInvalidServerBody => isZh
      ? '请输入完整的 HTTP 或 HTTPS 地址，例如 https://example.com'
      : 'Enter a complete HTTP or HTTPS URL, for example https://example.com';
  String get loginErrorManualModeTitle =>
      isZh ? '无法进入手动模式' : 'Could not enter manual mode';
  String get loginErrorManualModeBody => isZh
      ? '无法保存本地配置，请重试。'
      : 'Local settings could not be saved. Please try again.';
  String get loginFailedTitle => isZh ? '无法登录' : 'Sign in failed';
  String get loginErrorAuthenticationBody =>
      isZh ? '邮箱或密码不正确。' : 'Incorrect email or password.';
  String get loginErrorAccountExistsBody => isZh
      ? '该邮箱已注册，请直接登录。'
      : 'This email is already registered. Sign in instead.';
  String get loginErrorRegistrationFailedBody =>
      isZh ? '注册失败，请稍后重试。' : 'Registration failed. Please try again.';
  String get loginErrorRateLimitedBody =>
      isZh ? '请求过于频繁，请稍后再试。' : 'Too many attempts. Please try again later.';
  String get loginErrorNetworkTitle =>
      isZh ? '无法连接控制服务器' : 'Cannot reach control server';
  String get loginErrorNetworkBody => isZh
      ? '请检查网络或自托管服务器地址。'
      : 'Check your network or the self-hosted server address.';
  String get loginErrorTimeoutBody => isZh
      ? '连接控制服务器超时，请稍后重试。'
      : 'Connection to the control server timed out. Try again.';
  String get loginErrorServerBody => isZh
      ? '控制服务器返回了错误，请稍后再试或检查服务端。'
      : 'The control server returned an error. Try again later or check the server.';
  String get loginErrorUnknownTitle =>
      isZh ? '登录失败，请重试。' : 'Sign in failed. Please try again.';

  // --- Onboarding ---
  String get onboardingTitle =>
      isZh ? '把这台设备接入 P2WLAN' : 'Connect this device to P2WLAN';
  String get onboardingSubtitle => isZh
      ? '几步完成本地节点设置；中途退出可随时从这里继续。'
      : 'A few steps to set up your local node; you can resume here anytime.';
  String get onboardingStepPermission => isZh ? '权限' : 'Permission';
  String get onboardingStepStart => isZh ? '启动' : 'Start';
  String get onboardingStepVirtualIp => isZh ? '虚拟 IP' : 'Virtual IP';
  String get onboardingStepDiscover => isZh ? '发现设备' : 'Discover';
  String get onboardingStepDone => isZh ? '完成' : 'Done';
  String get onboardingAuthTitle =>
      isZh ? '登录控制面' : 'Sign in to the control plane';
  String get onboardingAuthSubtitle =>
      isZh ? '使用账号登录以加入你的网络。' : 'Use your account to join your network.';
  String get onboardingPermissionTitle =>
      isZh ? '授予本机权限' : 'Grant local permissions';
  String get onboardingPermissionSubtitle => isZh
      ? 'P2WLAN 需要创建虚拟网卡并安装路由，可能需要管理员权限。'
      : 'P2WLAN creates a virtual adapter and installs routes; this may need admin rights.';
  String get onboardingDaemonTitle =>
      isZh ? '启动本地守护进程' : 'Start the local daemon';
  String get onboardingDaemonSubtitle => isZh
      ? '启动 p2wlan-daemon 以建立虚拟网卡与加密会话。'
      : 'Start p2wlan-daemon to create the virtual adapter and secure sessions.';
  String get onboardingVirtualIpTitle =>
      isZh ? '等待分配虚拟 IP' : 'Waiting for a virtual IP';
  String get onboardingVirtualIpSubtitle => isZh
      ? '正在加入网络并获取 10.20.x.x 地址…'
      : 'Joining the network and getting a 10.20.x.x address…';
  String get onboardingDiscoverTitle =>
      isZh ? '发现其他设备' : 'Discover other devices';
  String get onboardingDiscoverSubtitle => isZh
      ? '正在同步节点目录。可以现在完成，之后在"设备"页继续查看。'
      : 'Syncing the node catalog. You can finish now and check "Devices" later.';
  String get onboardingReadyTitle => isZh ? '准备就绪' : 'Ready';
  String get onboardingReadySubtitle =>
      isZh ? '本地节点已配置完成。' : 'Your local node is set up.';
  String get onboardingPermissionSatisfied =>
      isZh ? '权限已满足' : 'Permissions satisfied';
  String get onboardingPermissionNeeded =>
      isZh ? '需要授权' : 'Authorization needed';
  String get onboardingTunAvailable => isZh ? '可创建 TUN' : 'Can create TUN';
  String get onboardingTunRuntimeVerify =>
      isZh ? 'TUN: 运行时验证' : 'TUN: runtime verification';
  String get onboardingTunUnavailable => isZh ? 'TUN: 不可用' : 'TUN: unavailable';
  String get onboardingRoutesAvailable => isZh ? '可修改路由' : 'Can modify routes';
  String get onboardingRoutesRuntimeVerify =>
      isZh ? '路由: 运行时验证' : 'Routes: runtime verification';
  String get onboardingRoutesUnavailable =>
      isZh ? '路由: 不可用' : 'Routes: unavailable';
  String get onboardingGrantContinue => isZh ? '授予并继续' : 'Grant & continue';
  String get onboardingFinish => isZh ? '完成' : 'Finish';
  String get onboardingConnecting => isZh ? '正在连接…' : 'Connecting…';
  String get onboardingSkip => isZh ? '跳过' : 'Skip';
  String get onboardingCompleteFailed => isZh
      ? '无法完成本机设置，请重试。'
      : 'Could not finish local setup. Please try again.';
  String get onboardingStartFailed => isZh
      ? '无法启动 P2WLAN，请检查权限后重试。'
      : 'Could not start P2WLAN. Check permissions and try again.';
  String get windowsUacCancelled => isZh
      ? '已取消 Windows 管理员授权，P2WLAN 未启动。'
      : 'Windows administrator authorization was cancelled. P2WLAN did not start.';
  String get windowsUacLaunchFailed => isZh
      ? 'Windows UAC 启动失败，请在系统提示中允许管理员授权后重试。'
      : 'Windows UAC could not start the daemon. Allow administrator authorization and try again.';
  String get clientDaemonBuildMismatch => isZh
      ? '客户端与 daemon 不是同一次构建，已阻止启动。请重新安装同一个 clean Windows 包。'
      : 'The client and daemon are from different builds, so startup was blocked. Reinstall one clean Windows package.';
  String get windowsPidMarkerFailed => isZh
      ? '无法确认 elevated daemon 的进程身份，已停止启动。'
      : 'The elevated daemon process identity could not be verified, so startup stopped.';
  String get daemonExitedDuringStartup => isZh
      ? 'daemon 在启动完成前退出，请查看启动日志中的阶段和失败代码。'
      : 'The daemon exited during startup. Check the startup log for its stage and failure code.';
  String get daemonBinaryLoadFailed => isZh
      ? 'p2wlan-daemon 或其运行库无法加载，请重新安装完整发布包。'
      : 'p2wlan-daemon or one of its runtimes could not load. Reinstall the complete package.';
  String get daemonAclFailure => isZh
      ? '无法准备 daemon 运行目录权限，请检查本地运行目录后重试。'
      : 'The daemon runtime directory could not be prepared. Check its local permissions and try again.';
  String get daemonTokenAccessFailed => isZh
      ? '无法建立安全的 Windows 启动身份，请重试或重新安装。'
      : 'A secure Windows launch identity could not be established. Try again or reinstall.';
  String get daemonNotElevated => isZh
      ? 'daemon 没有以 Windows 管理员权限运行，请重新授权。'
      : 'The daemon is not running with a Windows administrator token. Authorize it again.';
  String get daemonAuthFailed => isZh
      ? '登录凭据已失效，请重新登录后再启动。'
      : 'The login credential has expired. Sign in again before starting the daemon.';
  String get daemonStartupTimeout => isZh
      ? 'daemon 启动超时，请查看启动日志中的阶段和失败代码。'
      : 'The daemon did not become ready before the startup timeout. Check the startup log.';
  // --- Network & routes (Troubleshooting advanced) ---
  String get startupInterface => isZh ? '启动网卡配置' : 'Startup interface';
  String get startupMtu => isZh ? '启动 MTU 配置' : 'Startup MTU';
  String get virtualAdapter => isZh ? '虚拟网卡' : 'Virtual Adapter';
  String get virtualNetworkUp => isZh ? '正常' : 'UP';
  String get virtualNetworkDown => isZh ? '未运行' : 'DOWN';
  String get routeUnknown => isZh ? '未知（未校验）' : 'Unknown (unverified)';
  String get routeInstalled => isZh ? '已安装' : 'Installed';
  String get routeConflict => isZh ? '冲突' : 'Conflict';
  String get routeMissing => isZh ? '缺失' : 'Missing';
  String get routeDestination => isZh ? '目标网段' : 'Destination';
  String get routeExpectedInterface => isZh ? '期望网卡' : 'Expected interface';
  String get routeActualInterface => isZh ? '系统实际网卡' : 'Actual (system table)';
  String get routeDetail => isZh ? '状态说明' : 'Detail';
  String get routeNotRead => isZh
      ? '尚未从 daemon 读取系统路由表；点击"检查路由"。'
      : 'Not yet read from the daemon; tap "Check routes".';
  String routeAuthoritative(String state) =>
      isZh ? '权威状态：$state。' : 'Authoritative state: $state.';
  String get checkRoutes => isZh ? '检查路由' : 'Check routes';
  String get repairRoutes => isZh ? '修复路由' : 'Repair routes';
  String get noFixNeeded => isZh ? '无需修复' : 'No fix needed';
  String get restartNetworkService =>
      isZh ? '重启网络服务（会短暂断开）' : 'Restart network service (brief disconnect)';
  String tunnelRouteRepaired(String after) => isZh
      ? '路由已就地修复（状态：$after），未重启 daemon。'
      : 'Route repaired in place (state: $after) without restarting the daemon.';
  String get tunnelRouteAlreadyInstalled => isZh
      ? '路由已正确安装，无需修复。'
      : 'Route was already correctly installed; no change needed.';
  String get tunnelRouteRepairFailed =>
      isZh ? '无法修复路由，请重试。' : 'Could not repair routes. Please try again.';
  String get tunnelRestartFailed => isZh
      ? '无法重启网络服务，请重试。'
      : 'Could not restart the network service. Please try again.';
  String get daemonRestartedReinstall => isZh
      ? '已通过重启 daemon 触发 Overlay 路由重装。'
      : 'Daemon restarted to reinstall overlay routes.';

  // --- Nodes ---
  String nodeSynced(String name, String virtualIp) => isZh
      ? '本机节点已同步：$name / $virtualIp。重启 P2WLAN 后 IP 生效。'
      : 'This device synced: $name / $virtualIp. Restart P2WLAN to apply IP changes.';
  String nodeSaved(String name, String virtualIp) => isZh
      ? '本机节点已保存：$name / $virtualIp。启动后生效。'
      : 'This device saved: $name / $virtualIp. Applies on next start.';
  String deviceRemoved(String name) =>
      isZh ? '设备已移除：$name' : 'Device removed: $name';
  String deviceNameSynced(String name) =>
      isZh ? '设备名称已同步：$name' : 'Device name synced: $name';
  String get removeDeviceConfirmation => isZh
      ? '该设备会从控制面移除，之后需要重新登录/注册才能加入网络。'
      : 'This removes the device from the control plane. It must sign in or register again to rejoin.';
  String get deviceNameRequired =>
      isZh ? '设备名称不能为空' : 'Device name is required';
  String get editThisDevice => isZh ? '编辑本机' : 'Edit this device';
  String get requestedVirtualIp => isZh ? '期望虚拟 IP' : 'Requested virtual IP';
  String get requestedVirtualIpHelper => isZh
      ? '留空由控制面自动分配；修改后重启 P2WLAN 生效。'
      : 'Leave blank for automatic assignment; restart P2WLAN after changing it.';
  String get virtualIpFormatHint => isZh
      ? '虚拟 IP 格式不正确，例如 10.20.0.42'
      : 'Virtual IP must look like 10.20.0.42';
  String get version => isZh ? '版本' : 'Version';
  String get thisDeviceTitle => isZh ? '本机' : 'This device';
  String get controlSyncReady => isZh ? '控制面同步就绪' : 'Control sync ready';
  String get savedLocally => isZh ? '本地保存' : 'Saved locally';
  String get directTypePublic => isZh ? '公网直连' : 'Public direct';
  String get directTypeLan => isZh ? '局域网直连' : 'LAN direct';
  String get directTypeOverlay => isZh ? 'Overlay 直连' : 'Overlay direct';
  String get removeDeviceOfflineHint => isZh
      ? '如果只是临时离线，不需要移除；再次上线后会排到在线设备末尾。'
      : 'If it is only temporarily offline, leave it. When it returns, it moves to the end of the online devices.';

  // --- Settings ---
  String get controlServerHelper => isZh
      ? '用户注册、设备认证和节点目录同步地址。'
      : 'Used for account auth, device registration, and peer catalog sync.';
  String get networkIdHelper =>
      isZh ? '加入的专用虚拟内网标识。' : 'Virtual network identifier to join.';
  String get requestedVirtualIpHelperSettings => isZh
      ? '可选；留空由控制面自动分配，例如 10.20.0.42。保存后重启 P2WLAN 生效。'
      : 'Optional; leave blank for control-plane assignment, e.g. 10.20.0.42. Restart P2WLAN after saving.';
  String get localServiceSubtitle => isZh
      ? '诊断端点对应的本地 daemon。'
      : 'Local daemon behind the diagnostics endpoint.';
  String get settingsSaveFailed =>
      isZh ? '无法保存配置，请重试。' : 'Could not save settings. Please try again.';

  // --- Settings leave guard ---
  String get discardSettingsTitle =>
      isZh ? '放弃未保存的更改？' : 'Discard unsaved changes?';
  String get discardSettingsBody =>
      isZh ? '你有尚未保存的设置。' : 'You have unsaved settings.';
  String get continueEditing => isZh ? '继续编辑' : 'Continue editing';
  String get discardChanges => isZh ? '放弃更改' : 'Discard changes';
  String get deviceSaveFailed =>
      isZh ? '无法保存本机节点，请重试。' : 'Could not save this device. Please try again.';
  String get deviceRenameFailed =>
      isZh ? '无法重命名设备，请重试。' : 'Could not rename the device. Please try again.';
  String get deviceRemoveFailed =>
      isZh ? '无法移除设备，请重试。' : 'Could not remove the device. Please try again.';

  // --- Diagnostics ---
  String get logExcerptCopied => isZh ? '日志片段已复制' : 'Log excerpt copied';

  // --- Permissions presentation ---
  String permActionElevationRequired() => isZh
      ? '需要管理员授权启动 TUN；首次输入后密码会加密保存在本地配置文件中。'
      : 'Administrator authorization is required for the TUN; after the first entry, the password is encrypted in the local configuration file.';
  String permActionWindowsUac() => isZh
      ? '启动本地网络服务需要 Windows 管理员授权。点击“授权并继续”后，请在系统 UAC 窗口中确认。P2WLAN 不会读取或保存 Windows 管理员密码。'
      : 'Starting the local network service needs Windows administrator authorization. Click “Grant & continue”, then confirm the system UAC prompt. P2WLAN never reads or saves your Windows administrator password.';
  String permActionTunRuntimeVerification() => isZh
      ? '已获得管理员权限；macOS utun 创建需要 daemon 运行时验证。'
      : 'Elevated privileges are active; macOS utun creation is verified at daemon runtime.';
  String permActionTunDeviceMissing() => isZh
      ? '当前权限已满足，但缺少 /dev/net/tun，无法创建 Linux TUN。'
      : 'Permissions are satisfied, but /dev/net/tun is missing so a Linux TUN cannot be created.';
  String permActionReady() => isZh
      ? '权限已满足，daemon 可以创建 TUN 并维护路由。'
      : 'Permissions are satisfied; the daemon can create the TUN and maintain routes.';
  String permActionWintunMissing() => isZh
      ? '请把 wintun.dll 放到客户端/daemon 同级目录，或设置 P2WLAN_WINTUN_DLL。'
      : 'Place wintun.dll next to the client/daemon, or set P2WLAN_WINTUN_DLL.';
  String permActionPlatformUnsupported() => isZh
      ? '此平台暂不支持本地 TUN 控制，请在 macOS、Linux 或 Windows 上使用。'
      : 'Local TUN control is not supported on this platform; use macOS, Linux, or Windows.';
  String permActionGeneric(String platform) => isZh
      ? '$platform 平台需要进一步检查权限。'
      : 'Additional permission checks are required on $platform.';
  String get permCheckTitleGeneric => isZh ? '权限检查' : 'Permission check';
  String get permCheckEuid => isZh ? '有效用户权限' : 'Effective user permissions';
  String get permCheckTunNode => isZh ? 'TUN 设备节点' : 'TUN device node';
  String get permCheckDevNetTun =>
      isZh ? '/dev/net/tun 设备' : '/dev/net/tun device';
  String get permCheckDaemonCap => isZh ? 'daemon 能力' : 'daemon capability';
  String get permCheckAdmin => isZh ? '管理员权限' : 'Administrator rights';
  String get permCheckWintun => isZh ? 'Wintun 运行库' : 'Wintun runtime';
  String get permCheckPlatform => isZh ? '桌面平台' : 'Desktop platform';
  String permCheckEuidPass() =>
      isZh ? '已以管理员/root 身份运行。' : 'Running with elevated privileges.';
  String permCheckEuidFail() =>
      isZh ? '需要管理员权限。' : 'Elevated privileges are required.';
  String permCheckEuidWarn() => isZh ? '权限有限。' : 'Limited privileges.';
  String permCheckTunNodePass() =>
      isZh ? 'TUN 设备节点可访问。' : 'TUN device node is available.';
  String permCheckTunNodeWarn() => isZh
      ? 'macOS 通常动态创建 utun，无需静态节点。'
      : 'macOS usually creates utun dynamically; no static node needed.';
  String permCheckDevNetTunPass() =>
      isZh ? '/dev/net/tun 可访问。' : '/dev/net/tun is available.';
  String permCheckDevNetTunFail() => isZh
      ? '缺少 /dev/net/tun，无法创建 TUN。'
      : '/dev/net/tun is missing; cannot create a TUN.';
  String permCheckDaemonCapPass() =>
      isZh ? 'daemon 具备 CAP_NET_ADMIN。' : 'daemon has CAP_NET_ADMIN.';
  String permCheckDaemonCapWarn() =>
      isZh ? '未检测到 CAP_NET_ADMIN。' : 'CAP_NET_ADMIN was not detected.';
  String permCheckAdminPass() =>
      isZh ? '已具备管理员权限。' : 'Running with administrator rights.';
  String permCheckAdminFail() =>
      isZh ? '需要管理员权限。' : 'Administrator rights are required.';
  String permCheckWintunPass() =>
      isZh ? '已找到 wintun.dll。' : 'wintun.dll found.';
  String permCheckWintunFail() =>
      isZh ? '缺少 wintun.dll。' : 'wintun.dll is missing.';
  String permCheckPlatformFail() =>
      isZh ? '请使用 macOS、Linux 或 Windows。' : 'Use macOS, Linux, or Windows.';
  String permCheckStatusPass() => isZh ? '已通过' : 'Pass';
  String permCheckStatusFail() => isZh ? '未通过' : 'Fail';
  String permCheckStatusWarn() => isZh ? '需确认' : 'Review';

  String sectionLabel(String sectionName) {
    return switch (sectionName) {
      'home' => home,
      'devices' => devices,
      'troubleshooting' => troubleshooting,
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
      NatTraversalType.fullCone =>
        isZh ? '全锥形 NAT（Full Cone）' : 'Full Cone NAT',
      NatTraversalType.restrictedCone =>
        isZh ? '受限锥形 NAT（Restricted Cone）' : 'Restricted Cone NAT',
      NatTraversalType.portRestrictedCone =>
        isZh ? '端口受限锥形 NAT（Port-Restricted Cone）' : 'Port-Restricted Cone NAT',
      NatTraversalType.symmetric =>
        isZh ? '对称型 NAT（Symmetric）' : 'Symmetric NAT',
      NatTraversalType.openInternet => isZh ? '公网直连' : 'Open Internet',
      NatTraversalType.udpBlocked => isZh ? 'UDP 受阻' : 'UDP blocked',
      NatTraversalType.unknown => isZh ? '未确认' : 'Unknown',
    };
  }

  /// Compact label for dense surfaces such as the Home metrics row. The full
  /// classification remains available through [natTraversalTypeLabel] (and
  /// the metric tooltip), while this version stays readable on phones.
  String natTraversalTypeCompactLabel(NatTraversalType type) {
    return switch (type) {
      NatTraversalType.fullCone => isZh ? '全锥形' : 'Full Cone',
      NatTraversalType.restrictedCone => isZh ? '受限锥形' : 'Restricted Cone',
      NatTraversalType.portRestrictedCone =>
        isZh ? '端口受限锥形' : 'Port-Restricted Cone',
      NatTraversalType.symmetric => isZh ? '对称型' : 'Symmetric',
      NatTraversalType.openInternet => isZh ? '公网直连' : 'Open',
      NatTraversalType.udpBlocked => isZh ? 'UDP 受阻' : 'UDP blocked',
      NatTraversalType.unknown => isZh ? '未确认' : 'Unconfirmed',
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
      NatTraversalType.fullCone => isZh ? '全锥形' : 'Full Cone',
      NatTraversalType.restrictedCone => isZh ? '受限锥形' : 'Restricted Cone',
      NatTraversalType.portRestrictedCone =>
        isZh ? '端口受限锥形' : 'Port-Restricted Cone',
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
