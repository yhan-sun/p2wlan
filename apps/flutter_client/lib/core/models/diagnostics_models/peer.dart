part of '../diagnostics_models.dart';

// The daemon's default Direct/Relay data-plane keepalive cadence is 25s. A
// verified RTT is displayable for three probe intervals; after that the UI
// must fail closed instead of presenting a historical number as live.
const int _rttFreshnessWindowMs = 3 * 25 * 1000;

class PeerSnapshot {
  PeerSnapshot({
    required this.nodeId,
    required this.deviceName,
    this.platform = '',
    required this.appVersion,
    required this.virtualIp,
    required this.endpoint,
    required this.natType,
    required this.online,
    required this.lastSeen,
    required this.remoteRelayLatencyMs,
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
    required this.relayConfirmedEndpoint,
    required this.relayConfirmedGeneration,
    required this.pathObservability,
  });

  final String nodeId;
  final String deviceName;

  /// Platform reported by newer daemons/control-plane snapshots. Older
  /// snapshots omit it and the UI falls back to a conservative name heuristic.
  final String platform;
  final String appVersion;
  final String virtualIp;
  final String? endpoint;
  final String natType;
  final bool online;
  final int lastSeen;

  /// RTT from the remote peer to that peer's selected relay. This is topology
  /// diagnostics only and must never be rendered as this client's peer RTT.
  final int? remoteRelayLatencyMs;
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

  /// Relay endpoint whose ingress carried the confirming forced-relay probe
  /// ACK (daemon `relay_confirmed_endpoint`).  Present ONLY after a matching
  /// encrypted relay probe ACK — never from a TCP/TLS connect, a queued
  /// registration, or a candidate RTT.
  final String? relayConfirmedEndpoint;

  /// Network generation of the relay probe ACK confirmation.
  final int? relayConfirmedGeneration;

  final PathObservabilitySnapshot pathObservability;

  factory PeerSnapshot.fromJson(JsonMap json) {
    final selectionJson = _mapOrNull(json['current_path_selection']);
    return PeerSnapshot(
      nodeId: _string(json['node_id']),
      deviceName: _string(json['device_name']),
      platform: _string(
        json['platform'] ?? json['device_platform'] ?? json['os'],
      ),
      appVersion: _string(json['app_version']),
      virtualIp: _string(json['virtual_ip']),
      endpoint: _nullableString(json['endpoint']),
      natType: _string(json['nat_type'], 'unknown'),
      // Lifecycle evidence is fail-closed. A missing field from a partial or
      // mixed-version snapshot must not make a stale peer appear connected.
      online: _bool(json['online'], false),
      lastSeen: _int(json['last_seen']),
      remoteRelayLatencyMs: _intOrNull(json['remote_relay_latency_ms']),
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
      relayConfirmedEndpoint: _nullableString(json['relay_confirmed_endpoint']),
      relayConfirmedGeneration: _intOrNull(json['relay_confirmed_generation']),
      pathObservability: _pathObservabilityOrEmpty(json['path_observability']),
    );
  }

  String get displayName {
    final trimmed = deviceName.trim();
    if (trimmed.isNotEmpty) return trimmed;
    return nodeId.length <= 12 ? nodeId : nodeId.substring(0, 12);
  }

  String get path {
    if (!online) return 'offline';
    // A daemon state/selection is not a usable path until the corresponding
    // encrypted evidence is present. Fail closed so a relay reconnect or a
    // candidate probe cannot be rendered as an established connection.
    if (activePath == 'relay' && _hasRelayConfirmation) return 'relay';
    if (activePath == 'direct' && state == 'direct') return 'direct';
    // Keep the confirmed relay active while Direct is only a background trial.
    // A selector snapshot may already say `direct` before the encrypted Direct
    // ACK is committed to `active_path`; it must not make the UI hide the
    // verified relay in that interval.
    if (_hasRelayConfirmation &&
        (state == 'relay' || isRelay || activePath == 'relay')) {
      return 'relay';
    }
    final selected = currentPathSelection?.path;
    if (selected == 'direct') {
      return currentPathSelection?.directConfirmed == true
          ? 'direct'
          : 'direct_trial';
    }
    if (selected == 'relay' && _hasRelayConfirmation) return 'relay';
    // The daemon may retain `state == direct` as background encrypted proof
    // while relay-first promotion is still waiting for the same-generation
    // relay ACK.  Without an active path, this is probing—not a usable Direct
    // connection and not a latency sample.
    if (state == 'direct') return 'probing';
    if (state == 'relay' || isRelay || activePath == 'relay') return 'probing';
    if (state == 'fallback_to_relay' ||
        state == 'hole_punching' ||
        state == 'connecting') {
      return 'probing';
    }
    // Roster presence and path usability are separate facts. An online peer
    // with no verified path is still online; it is probing until encrypted
    // Direct/Relay evidence arrives.
    return 'probing';
  }

  String get connectionType {
    if (!online) return 'offline';
    if (path == 'direct') {
      return directType == 'unknown' ? 'direct' : directType;
    }
    if (path == 'relay') return 'relay';
    if (path == 'direct_trial' || path == 'probing') return 'probing';
    return 'probing';
  }

  int? get latencyMs {
    // A latency is only meaningful for a VERIFIED usable path.  A candidate
    // probe's RTT (e.g. the 8ms UDP punch) proves nothing about the data
    // path: it must never be displayed or counted as the connection latency.
    if (!online) return null;
    if (path == 'direct') {
      return isDirectVerified ? direct.displayLatencyMs : null;
    }
    if (path == 'relay') {
      // `remoteRelayLatencyMs` is the remote daemon's RTT to its own relay,
      // not this daemon's end-to-end RTT to the peer.  Only the locally timed
      // and verified relay path sample is a displayable peer latency.
      return isRelayVerified ? relay.displayLatencyMs : null;
    }
    return null;
  }

  /// Candidate-probe RTT (UDP punch / STUN-style measurement).  This is NOT a
  /// connection latency: the peer's data path is not verified until
  /// [path] is `direct` or `relay`.  Used ONLY for the "探测中" label.
  int? get probeLatencyMs {
    if (!online) return null;
    if (path == 'direct_trial') return direct.displayLatencyMs;
    if (path == 'probing' &&
        currentPathSelection?.path == 'direct' &&
        currentPathSelection?.directConfirmed != true) {
      return direct.displayLatencyMs;
    }
    return null;
  }

  /// Whether the relay path to this peer is VERIFIED by a matching encrypted
  /// relay probe ACK (`relay_confirmed_endpoint` — daemon authority).  A
  /// transport connect, a queued registration, or a candidate RTT never sets
  /// this.
  bool get isRelayVerified => path == 'relay' && _hasRelayConfirmation;

  /// Whether the direct path to this peer is VERIFIED by a matching encrypted
  /// direct validation exchange (daemon `active_path == direct` requires the
  /// validation ACK).  Candidate probing never sets this.
  bool get isDirectVerified => path == 'direct' && state == 'direct';

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

  bool get _hasRelayConfirmation =>
      relayConfirmedEndpoint != null &&
      relayConfirmedEndpoint!.isNotEmpty &&
      relayConfirmedGeneration != null;

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

  /// The UI shows the smoothed RTT for this verified path. The raw sample is
  /// only a compatibility fallback for older daemons. Once the daemon reports
  /// that the last sample is older than the freshness window, fail closed and
  /// render `--` rather than a stale latency.
  ///
  /// This is the encrypted overlay/data-path RTT, not an ICMP echo measurement.
  int? get displayLatencyMs {
    if (lastSuccessAgeMs != null && lastSuccessAgeMs! > _rttFreshnessWindowMs) {
      return null;
    }
    return rttEwmaMs ?? latencyMs;
  }

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
