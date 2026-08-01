part of '../diagnostics_models.dart';

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
