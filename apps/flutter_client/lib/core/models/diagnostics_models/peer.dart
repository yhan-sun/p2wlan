part of '../diagnostics_models.dart';

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
    if (warning case final warning?) return warning;
    return switch (path) {
      'direct' => direct.visibleLastError,
      'relay' => relay.visibleLastError ?? direct.visibleLastError,
      _ => direct.visibleLastError ?? relay.visibleLastError,
    };
  }
}

class PathHealthSnapshot {
  PathHealthSnapshot({
    required this.lastSuccessAgeMs,
    required this.lastFailureAgeMs,
    required this.consecutiveFailures,
    required this.lastError,
    required this.lastErrorCode,
    required this.latencyMs,
    required this.rttEwmaMs,
  });

  final int? lastSuccessAgeMs;
  final int? lastFailureAgeMs;
  final int consecutiveFailures;
  final String? lastError;
  final String? lastErrorCode;
  final int? latencyMs;
  final int? rttEwmaMs;

  int? get displayLatencyMs => rttEwmaMs ?? latencyMs;

  String? get visibleLastError {
    if (_isNetworkGenerationRefresh(lastErrorCode, lastError)) return null;
    return lastError;
  }

  factory PathHealthSnapshot.fromJson(JsonMap json) {
    return PathHealthSnapshot(
      lastSuccessAgeMs: _intOrNull(json['last_success_age_ms']),
      lastFailureAgeMs: _intOrNull(json['last_failure_age_ms']),
      consecutiveFailures: _int(json['consecutive_failures']),
      lastError: _nullableString(json['last_error']),
      lastErrorCode: _nullableString(json['last_error_code']),
      latencyMs: _intOrNull(json['latency_ms']),
      rttEwmaMs: _intOrNull(json['rtt_ewma_ms']),
    );
  }
}

bool _isNetworkGenerationRefresh(String? code, String? reason) {
  const networkGenerationChanged = 'network_generation_changed';
  final normalizedCode = code?.trim();
  final normalizedReason = reason?.trim();
  return normalizedCode == networkGenerationChanged ||
      normalizedReason == networkGenerationChanged ||
      normalizedReason?.startsWith('$networkGenerationChanged:') == true;
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
