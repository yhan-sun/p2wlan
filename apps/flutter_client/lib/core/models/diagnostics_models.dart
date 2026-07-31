import 'dart:convert';
import 'dart:io';

const defaultDiagnosticsUrl = 'http://127.0.0.1:39277/status';
const legacyControlServer = 'https://control.p2wlan.io';
const defaultControlServer = String.fromEnvironment(
  'P2WLAN_DEFAULT_CONTROL_SERVER',
  defaultValue: 'http://47.109.40.237:18080',
);
const defaultNetworkId = 'default';
const defaultLanguageCode = 'en';
const defaultOverlayCidr = '10.20.0.0/16';
const defaultMtu = 1420;
const defaultUdpBind = '0.0.0.0:0';
const defaultSocketPool = '3';
const defaultCloseBehavior = 'keep-running';

String get defaultTunInterface => Platform.isWindows ? 'p2wlan' : 'p2wlan0';

typedef JsonMap = Map<String, dynamic>;

enum AppThemeMode {
  system('system'),
  light('light'),
  dark('dark');

  const AppThemeMode(this.code);
  final String code;

  static AppThemeMode fromCode(String? code) {
    final normalized = (code ?? 'system').trim().toLowerCase();
    return switch (normalized) {
      'light' => light,
      'dark' => dark,
      _ => system,
    };
  }
}

enum AppLanguage {
  english('en'),
  simplifiedChinese('zh-Hans');

  const AppLanguage(this.code);

  final String code;

  static AppLanguage fromCode(String? code) {
    final normalized = (code ?? defaultLanguageCode)
        .trim()
        .replaceAll('_', '-')
        .toLowerCase();
    return switch (normalized) {
      'zh' || 'zh-cn' || 'zh-hans' || 'zh-hans-cn' => simplifiedChinese,
      _ => english,
    };
  }
}

class AppSettings {
  const AppSettings({
    this.diagnosticsUrl = defaultDiagnosticsUrl,
    this.controlServer = defaultControlServer,
    this.authToken = '',
    this.networkId = defaultNetworkId,
    this.virtualIp = '',
    this.deviceName = '',
    this.manualMode = false,
    this.overlayCidr = defaultOverlayCidr,
    this.tunInterface = '',
    this.mtu = defaultMtu,
    this.udpBind = defaultUdpBind,
    this.udpAdvertise = '',
    this.socketPool = defaultSocketPool,
    this.relayServers = '',
    this.closeBehavior = defaultCloseBehavior,
    this.languageCode = defaultLanguageCode,
    this.themeMode = 'system',
  });

  final String diagnosticsUrl;
  final String controlServer;
  final String authToken;
  final String networkId;
  final String virtualIp;
  final String deviceName;
  final bool manualMode;
  final String overlayCidr;
  final String tunInterface;
  final int mtu;
  final String udpBind;
  final String udpAdvertise;
  final String socketPool;
  final String relayServers;
  final String closeBehavior;
  final String languageCode;
  final String themeMode;

  String get effectiveTunInterface {
    final trimmed = tunInterface.trim();
    return trimmed.isEmpty ? defaultTunInterface : trimmed;
  }

  AppSettings copyWith({
    String? diagnosticsUrl,
    String? controlServer,
    String? authToken,
    String? networkId,
    String? virtualIp,
    String? deviceName,
    bool? manualMode,
    String? overlayCidr,
    String? tunInterface,
    int? mtu,
    String? udpBind,
    String? udpAdvertise,
    String? socketPool,
    String? relayServers,
    String? closeBehavior,
    String? languageCode,
    String? themeMode,
  }) {
    return AppSettings(
      diagnosticsUrl: diagnosticsUrl ?? this.diagnosticsUrl,
      controlServer: controlServer ?? this.controlServer,
      authToken: authToken ?? this.authToken,
      networkId: networkId ?? this.networkId,
      virtualIp: virtualIp ?? this.virtualIp,
      deviceName: deviceName ?? this.deviceName,
      manualMode: manualMode ?? this.manualMode,
      overlayCidr: overlayCidr ?? this.overlayCidr,
      tunInterface: tunInterface ?? this.tunInterface,
      mtu: mtu ?? this.mtu,
      udpBind: udpBind ?? this.udpBind,
      udpAdvertise: udpAdvertise ?? this.udpAdvertise,
      socketPool: socketPool ?? this.socketPool,
      relayServers: relayServers ?? this.relayServers,
      closeBehavior: _normalizeCloseBehavior(
        closeBehavior ?? this.closeBehavior,
      ),
      languageCode: languageCode == null
          ? this.languageCode
          : AppLanguage.fromCode(languageCode).code,
      themeMode: themeMode == null
          ? this.themeMode
          : AppThemeMode.fromCode(themeMode).code,
    );
  }

  factory AppSettings.fromJson(JsonMap json) {
    return AppSettings(
      diagnosticsUrl: _string(json['diagnosticsUrl'], defaultDiagnosticsUrl),
      controlServer: _string(json['controlServer'], defaultControlServer),
      authToken: _string(json['authToken']),
      networkId: _string(json['networkId'], defaultNetworkId),
      virtualIp: _string(json['virtualIp']),
      deviceName: _string(json['deviceName']),
      manualMode: _bool(json['manualMode']),
      overlayCidr: _string(json['overlayCidr'], defaultOverlayCidr),
      tunInterface: _string(json['tunInterface'], defaultTunInterface),
      mtu: _int(json['mtu'], defaultMtu),
      udpBind: _string(json['udpBind'], defaultUdpBind),
      udpAdvertise: _string(json['udpAdvertise']),
      socketPool: _normalizeSocketPool(
        _string(json['socketPool'], defaultSocketPool),
      ),
      relayServers: _string(json['relayServers']),
      closeBehavior: _normalizeCloseBehavior(
        _string(json['closeBehavior'], defaultCloseBehavior),
      ),
      languageCode: AppLanguage.fromCode(_string(json['languageCode'])).code,
      themeMode: AppThemeMode.fromCode(_string(json['themeMode'])).code,
    );
  }

  JsonMap toJson() => {
    'diagnosticsUrl': diagnosticsUrl,
    'controlServer': controlServer,
    'authToken': authToken,
    'networkId': networkId,
    'virtualIp': virtualIp,
    'deviceName': deviceName,
    'manualMode': manualMode,
    'overlayCidr': overlayCidr,
    'tunInterface': effectiveTunInterface,
    'mtu': mtu,
    'udpBind': udpBind,
    'udpAdvertise': udpAdvertise,
    'socketPool': _normalizeSocketPool(socketPool),
    'relayServers': relayServers,
    'closeBehavior': _normalizeCloseBehavior(closeBehavior),
    'languageCode': languageCode,
    'themeMode': themeMode,
  };
}

String _normalizeCloseBehavior(String value) {
  final normalized = value.trim();
  if (normalized == 'stop-and-quit' || normalized == 'keep-running') {
    return normalized;
  }
  return defaultCloseBehavior;
}

String _normalizeSocketPool(String value) {
  final normalized = value.trim().toLowerCase();
  if (normalized == 'auto' ||
      normalized == 'on' ||
      normalized == 'true' ||
      normalized == 'yes') {
    return defaultSocketPool;
  }
  if (normalized == 'off' ||
      normalized == 'false' ||
      normalized == 'no' ||
      normalized == 'none') {
    return 'off';
  }
  return normalized.isEmpty ? defaultSocketPool : normalized;
}

class DiagnosticsSnapshot {
  DiagnosticsSnapshot({
    required this.raw,
    required this.version,
    required this.processId,
    required this.nodeId,
    required this.virtualIp,
    required this.networkId,
    required this.udpLocalAddr,
    required this.udpSocketCount,
    required this.udpSocketPoolActive,
    required this.localCandidates,
    required this.relayServers,
    required this.relayConnected,
    required this.relaySelection,
    required this.peers,
    required this.stats,
    required this.health,
  });

  final JsonMap raw;
  final String version;
  final int? processId;
  final String nodeId;
  final String virtualIp;
  final String networkId;
  final String? udpLocalAddr;
  final int udpSocketCount;
  final bool udpSocketPoolActive;
  final List<String> localCandidates;
  final List<String> relayServers;
  final bool relayConnected;
  final RelaySelectionSnapshot relaySelection;
  final List<PeerSnapshot> peers;
  final PeerManagerStatsSnapshot stats;
  final HealthSnapshot health;

  factory DiagnosticsSnapshot.fromJson(JsonMap json) {
    return DiagnosticsSnapshot(
      raw: json,
      version: _string(json['version']),
      processId: _intOrNull(json['process_id']),
      nodeId: _string(json['node_id']),
      virtualIp: _string(json['virtual_ip']),
      networkId: _string(json['network_id']),
      udpLocalAddr: _nullableString(json['udp_local_addr']),
      udpSocketCount: _int(json['udp_socket_count']),
      udpSocketPoolActive: _bool(json['udp_socket_pool_active']),
      localCandidates: _stringList(json['local_candidates']),
      relayServers: _stringList(json['relay_servers']),
      relayConnected: _bool(json['relay_connected']),
      relaySelection: RelaySelectionSnapshot.fromJson(
        _map(json['relay_selection']),
      ),
      peers: [
        for (final item in _list(json['peers']))
          PeerSnapshot.fromJson(_map(item)),
      ],
      stats: PeerManagerStatsSnapshot.fromJson(_map(json['stats'])),
      health: HealthSnapshot.fromJson(_map(json['health'])),
    );
  }

  String get prettyJson {
    const encoder = JsonEncoder.withIndent('  ');
    return encoder.convert(raw);
  }
}

class HealthSnapshot {
  HealthSnapshot({
    required this.status,
    required this.reason,
    required this.controlConnected,
    required this.lastControlSuccessSecsAgo,
    required this.reauthRequired,
    required this.criticalTasks,
  });

  final String status;
  final String? reason;
  final bool controlConnected;
  final int? lastControlSuccessSecsAgo;
  final bool reauthRequired;
  final List<TaskStatusSnapshot> criticalTasks;

  factory HealthSnapshot.fromJson(JsonMap json) {
    return HealthSnapshot(
      status: _string(json['status'], 'unknown'),
      reason: _nullableString(json['reason']),
      controlConnected: _bool(json['control_connected']),
      lastControlSuccessSecsAgo: _intOrNull(
        json['last_control_success_secs_ago'],
      ),
      reauthRequired: _bool(json['reauth_required']),
      criticalTasks: [
        for (final item in _list(json['critical_tasks']))
          TaskStatusSnapshot.fromJson(_map(item)),
      ],
    );
  }
}

class TaskStatusSnapshot {
  TaskStatusSnapshot({
    required this.name,
    required this.critical,
    required this.running,
    required this.finished,
    required this.error,
  });

  final String name;
  final bool critical;
  final bool running;
  final bool finished;
  final String? error;

  factory TaskStatusSnapshot.fromJson(JsonMap json) {
    return TaskStatusSnapshot(
      name: _string(json['name']),
      critical: _bool(json['critical']),
      running: _bool(json['running']),
      finished: _bool(json['finished']),
      error: _nullableString(json['error']),
    );
  }
}

class RelaySelectionSnapshot {
  RelaySelectionSnapshot({
    required this.selectedRegion,
    required this.selectedEndpoint,
    required this.selectedConnectLatencyMs,
    required this.selectedLastPongRttMs,
    required this.selectedRttEwmaMs,
    required this.lastError,
  });

  final String? selectedRegion;
  final String? selectedEndpoint;
  final int? selectedConnectLatencyMs;
  final int? selectedLastPongRttMs;
  final int? selectedRttEwmaMs;
  final String? lastError;

  int? get latencyMs =>
      selectedRttEwmaMs ?? selectedLastPongRttMs ?? selectedConnectLatencyMs;

  factory RelaySelectionSnapshot.fromJson(JsonMap json) {
    return RelaySelectionSnapshot(
      selectedRegion: _nullableString(json['selected_region']),
      selectedEndpoint: _nullableString(json['selected_endpoint']),
      selectedConnectLatencyMs: _intOrNull(json['selected_connect_latency_ms']),
      selectedLastPongRttMs: _intOrNull(json['selected_last_pong_rtt_ms']),
      selectedRttEwmaMs: _intOrNull(json['selected_rtt_ewma_ms']),
      lastError: _nullableString(json['last_error']),
    );
  }
}

class PeerManagerStatsSnapshot {
  PeerManagerStatsSnapshot({
    required this.totalPeers,
    required this.directConnections,
    required this.relayConnections,
    required this.totalBytesSent,
    required this.totalBytesReceived,
  });

  final int totalPeers;
  final int directConnections;
  final int relayConnections;
  final int totalBytesSent;
  final int totalBytesReceived;

  factory PeerManagerStatsSnapshot.fromJson(JsonMap json) {
    return PeerManagerStatsSnapshot(
      totalPeers: _int(json['total_peers']),
      directConnections: _int(json['direct_connections']),
      relayConnections: _int(json['relay_connections']),
      totalBytesSent: _int(json['total_bytes_sent']),
      totalBytesReceived: _int(json['total_bytes_received']),
    );
  }
}

class PeerSnapshot {
  PeerSnapshot({
    required this.nodeId,
    required this.deviceName,
    required this.appVersion,
    required this.virtualIp,
    required this.endpoint,
    required this.natType,
    required this.online,
    required this.lastSeen,
    required this.state,
    required this.activePath,
    required this.directType,
    required this.isRelay,
    required this.bytesSent,
    required this.bytesReceived,
    required this.relayServer,
    required this.warning,
    required this.connectedForMs,
    required this.direct,
    required this.relay,
    required this.currentPathSelection,
  });

  final String nodeId;
  final String deviceName;
  final String appVersion;
  final String virtualIp;
  final String? endpoint;
  final String natType;
  final bool online;
  final int lastSeen;
  final String state;
  final String? activePath;
  final String directType;
  final bool isRelay;
  final int bytesSent;
  final int bytesReceived;
  final String? relayServer;
  final String? warning;
  final int? connectedForMs;
  final PathHealthSnapshot direct;
  final PathHealthSnapshot relay;
  final PathSelectionSnapshot? currentPathSelection;

  factory PeerSnapshot.fromJson(JsonMap json) {
    final selectionJson = _mapOrNull(json['current_path_selection']);
    return PeerSnapshot(
      nodeId: _string(json['node_id']),
      deviceName: _string(json['device_name']),
      appVersion: _string(json['app_version']),
      virtualIp: _string(json['virtual_ip']),
      endpoint: _nullableString(json['endpoint']),
      natType: _string(json['nat_type'], 'unknown'),
      online: _bool(json['online'], true),
      lastSeen: _int(json['last_seen']),
      state: _string(json['state'], 'unknown'),
      activePath: _nullableString(json['active_path']),
      directType: _string(json['direct_type'], 'unknown'),
      isRelay: _bool(json['is_relay']),
      bytesSent: _int(json['bytes_sent']),
      bytesReceived: _int(json['bytes_received']),
      relayServer: _nullableString(json['relay_server']),
      warning: _nullableString(json['warning']),
      connectedForMs: _intOrNull(json['connected_for_ms']),
      direct: PathHealthSnapshot.fromJson(_map(json['direct'])),
      relay: PathHealthSnapshot.fromJson(_map(json['relay'])),
      currentPathSelection: selectionJson == null
          ? null
          : PathSelectionSnapshot.fromJson(selectionJson),
    );
  }

  String get displayName {
    final trimmed = deviceName.trim();
    if (trimmed.isNotEmpty) return trimmed;
    return nodeId.length <= 12 ? nodeId : nodeId.substring(0, 12);
  }

  String get path {
    if (!online) return 'offline';
    if (activePath != null && activePath!.isNotEmpty) return activePath!;
    final selected = currentPathSelection?.path;
    if (selected == 'direct') {
      return currentPathSelection?.directConfirmed == true
          ? 'direct'
          : 'direct_trial';
    }
    if (selected == 'relay' && _hasFreshRelayConfirmation) return 'relay';
    if (state == 'direct') return 'direct';
    if (state == 'relay' || isRelay) return 'relay';
    if (state == 'fallback_to_relay' ||
        state == 'hole_punching' ||
        state == 'connecting') {
      return 'probing';
    }
    return 'offline';
  }

  String get connectionType {
    if (!online) return 'offline';
    if (path == 'direct') {
      return directType == 'unknown' ? 'direct' : directType;
    }
    if (path == 'relay') return 'relay';
    if (path == 'direct_trial' || path == 'probing') return 'probing';
    return 'offline';
  }

  int? get latencyMs {
    if (!online) return null;
    if (path == 'direct') return direct.displayLatencyMs;
    if (path == 'relay') return relay.displayLatencyMs;
    if (path == 'direct_trial') {
      return direct.displayLatencyMs ?? relay.displayLatencyMs;
    }
    return direct.displayLatencyMs ?? relay.displayLatencyMs;
  }

  DateTime? get lastSeenAt {
    if (lastSeen <= 0) return null;
    final timestampMs = lastSeen < 10000000000 ? lastSeen * 1000 : lastSeen;
    return DateTime.fromMillisecondsSinceEpoch(timestampMs);
  }

  int get sortTimestampMs {
    final seen = lastSeenAt?.millisecondsSinceEpoch;
    if (seen != null) return seen;
    if (connectedForMs != null) {
      return DateTime.now().millisecondsSinceEpoch - connectedForMs!;
    }
    return 0;
  }

  bool get _hasFreshRelayConfirmation {
    final age = relay.lastSuccessAgeMs;
    return age != null && age <= 15000 && relay.consecutiveFailures == 0;
  }

  String? get lastError {
    return warning ?? direct.lastError ?? relay.lastError;
  }
}

class PathHealthSnapshot {
  PathHealthSnapshot({
    required this.lastSuccessAgeMs,
    required this.lastFailureAgeMs,
    required this.consecutiveFailures,
    required this.lastError,
    required this.latencyMs,
    required this.rttEwmaMs,
  });

  final int? lastSuccessAgeMs;
  final int? lastFailureAgeMs;
  final int consecutiveFailures;
  final String? lastError;
  final int? latencyMs;
  final int? rttEwmaMs;

  int? get displayLatencyMs => rttEwmaMs ?? latencyMs;

  factory PathHealthSnapshot.fromJson(JsonMap json) {
    return PathHealthSnapshot(
      lastSuccessAgeMs: _intOrNull(json['last_success_age_ms']),
      lastFailureAgeMs: _intOrNull(json['last_failure_age_ms']),
      consecutiveFailures: _int(json['consecutive_failures']),
      lastError: _nullableString(json['last_error']),
      latencyMs: _intOrNull(json['latency_ms']),
      rttEwmaMs: _intOrNull(json['rtt_ewma_ms']),
    );
  }
}

class PathSelectionSnapshot {
  PathSelectionSnapshot({
    required this.path,
    required this.reasonCode,
    required this.reason,
    required this.directConfirmed,
    required this.relayHedged,
  });

  final String? path;
  final String reasonCode;
  final String reason;
  final bool directConfirmed;
  final bool relayHedged;

  factory PathSelectionSnapshot.fromJson(JsonMap json) {
    return PathSelectionSnapshot(
      path: _nullableString(json['path']),
      reasonCode: _string(json['reason_code']),
      reason: _string(json['reason']),
      directConfirmed: _bool(json['direct_confirmed']),
      relayHedged: _bool(json['relay_hedged']),
    );
  }
}

String _string(dynamic value, [String fallback = '']) {
  if (value == null) return fallback;
  return value.toString();
}

String? _nullableString(dynamic value) {
  if (value == null) return null;
  final text = value.toString();
  return text.isEmpty ? null : text;
}

int _int(dynamic value, [int fallback = 0]) {
  return _intOrNull(value) ?? fallback;
}

int? _intOrNull(dynamic value) {
  if (value is int) return value;
  if (value is num) return value.round();
  if (value is String) return int.tryParse(value);
  return null;
}

bool _bool(dynamic value, [bool fallback = false]) {
  if (value is bool) return value;
  if (value is String) return value.toLowerCase() == 'true';
  if (value is num) return value != 0;
  return fallback;
}

JsonMap _map(dynamic value) {
  if (value is Map) return Map<String, dynamic>.from(value);
  return {};
}

JsonMap? _mapOrNull(dynamic value) {
  if (value is Map) return Map<String, dynamic>.from(value);
  return null;
}

List<dynamic> _list(dynamic value) {
  if (value is List) return value;
  return const [];
}

List<String> _stringList(dynamic value) {
  return _list(value).map((item) => item.toString()).toList(growable: false);
}
