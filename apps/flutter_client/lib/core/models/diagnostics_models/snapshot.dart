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
    required this.natProfile,
    required this.relayServers,
    required this.relayConnected,
    required this.relaySelection,
    required this.peers,
    required this.stats,
    required this.health,
    this.contractVersion = 0,
    this.revision = 0,
    this.capturedRevision = 0,
    this.capturedAtMs = 0,
    this.peerSnapshotStale = false,
    this.peerSnapshotAgeMs = 0,
    this.peerSnapshotShape = '',
    this.networkGeneration = 0,
    this.uptimeMs = 0,
    this.readyPhase = 'unknown',
  });

  final JsonMap raw;
  final int contractVersion;
  final String version;
  final int? processId;
  final String nodeId;
  final String virtualIp;
  final String networkId;

  /// Monotonic daemon status revision. Clients compare to their last-seen
  /// value to decide whether a full snapshot refetch is needed.
  final int revision;

  /// Revision and capture metadata for the peer portion of this exact
  /// snapshot. A stale/cache fallback must never masquerade as a newly fetched
  /// peer catalog merely because the HTTP request returned 200.
  final int capturedRevision;
  final int capturedAtMs;
  final bool peerSnapshotStale;
  final int peerSnapshotAgeMs;
  final String peerSnapshotShape;
  final int networkGeneration;
  final int uptimeMs;

  /// Authoritative daemon readiness phase (e.g. `connected_direct`,
  /// `connected_relay`, `discovering_peers`, `error`). Render this instead of
  /// inferring connectivity from `virtualIp` presence.
  final String readyPhase;
  final String? udpLocalAddr;
  final int udpSocketCount;
  final bool udpSocketPoolActive;
  final List<String> localCandidates;
  final NatProfileSnapshot? natProfile;
  final List<String> relayServers;
  final bool relayConnected;
  final RelaySelectionSnapshot relaySelection;
  final List<PeerSnapshot> peers;
  final PeerManagerStatsSnapshot stats;
  final HealthSnapshot health;

  factory DiagnosticsSnapshot.fromJson(JsonMap json) {
    return DiagnosticsSnapshot(
      raw: json,
      contractVersion: _contractVersion(json),
      version: _string(json['version']),
      processId: _intOrNull(json['process_id']),
      nodeId: _string(json['node_id']),
      virtualIp: _string(json['virtual_ip']),
      networkId: _string(json['network_id']),
      udpLocalAddr: _nullableString(json['udp_local_addr']),
      udpSocketCount: _int(json['udp_socket_count']),
      udpSocketPoolActive: _bool(json['udp_socket_pool_active']),
      localCandidates: _stringList(json['local_candidates']),
      natProfile: _natProfileOrNull(json['nat_profile']),
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
      revision: _int(json['revision'], 0),
      capturedRevision: _int(
        json['captured_revision'],
        _int(json['revision'], 0),
      ),
      capturedAtMs: _int(json['captured_at_ms']),
      peerSnapshotStale: _bool(json['peer_snapshot_stale']),
      peerSnapshotAgeMs: _int(json['peer_snapshot_age_ms']),
      peerSnapshotShape: _string(json['peer_snapshot_shape']),
      networkGeneration: _int(json['network_generation']),
      uptimeMs: _int(json['uptime_ms']),
      readyPhase: _string(json['ready_phase'], 'unknown'),
    );
  }

  String get prettyJson {
    const encoder = JsonEncoder.withIndent('  ');
    return encoder.convert(raw);
  }
}

NatProfileSnapshot? _natProfileOrNull(dynamic value) {
  final json = _mapOrNull(value);
  return json == null ? null : NatProfileSnapshot.fromJson(json);
}

enum NatTraversalType {
  fullCone,
  restrictedCone,
  portRestrictedCone,
  symmetric,
  openInternet,
  udpBlocked,
  unknown,
}

class NatTypeProbability {
  const NatTypeProbability({required this.type, required this.probability});

  final NatTraversalType type;
  final double probability;
}

class NatProfileSnapshot {
  NatProfileSnapshot({
    required this.mappingBehavior,
    required this.filteringBehavior,
    required this.publicEndpoint,
    required this.confidence,
    required this.udpBlocked,
    required this.typeProbabilities,
  });

  final String mappingBehavior;
  final String filteringBehavior;
  final String? publicEndpoint;
  final int? confidence;
  final bool udpBlocked;
  final List<NatTypeProbability> typeProbabilities;

  factory NatProfileSnapshot.fromJson(JsonMap json) {
    final mappingBehavior = _string(json['mapping_behavior'], 'unknown');
    final filteringBehavior = _string(json['filtering_behavior'], 'unknown');
    final confidence = _intOrNull(json['confidence']);
    final udpBlocked = _bool(json['udp_blocked']);
    return NatProfileSnapshot(
      mappingBehavior: mappingBehavior,
      filteringBehavior: filteringBehavior,
      publicEndpoint: _nullableString(json['public_endpoint']),
      confidence: confidence,
      udpBlocked: udpBlocked,
      typeProbabilities: _natTypeProbabilities(
        json: json,
        mappingBehavior: mappingBehavior,
        filteringBehavior: filteringBehavior,
        confidence: confidence,
        udpBlocked: udpBlocked,
      ),
    );
  }

  NatTraversalType get traversalType {
    final mapping = mappingBehavior.toLowerCase();
    final filtering = filteringBehavior.toLowerCase();

    if (udpBlocked || mapping == 'udp_blocked' || filtering == 'udp_blocked') {
      return NatTraversalType.udpBlocked;
    }
    if (mapping == 'open_internet') {
      return NatTraversalType.openInternet;
    }
    if (mapping == 'address_or_port_dependent') {
      return NatTraversalType.symmetric;
    }
    if (mapping != 'endpoint_independent') {
      return NatTraversalType.unknown;
    }

    return switch (filtering) {
      'endpoint_independent' ||
      'likely_endpoint_independent' => NatTraversalType.fullCone,
      'address_dependent' => NatTraversalType.restrictedCone,
      'address_or_port_dependent' => NatTraversalType.portRestrictedCone,
      _ => NatTraversalType.unknown,
    };
  }

  /// The type that should be rendered in compact user-facing surfaces.
  ///
  /// A stable endpoint-independent mapping is enough to prove that the NAT
  /// is a cone NAT, but the exact filtering subtype requires an RFC 5780
  /// CHANGE-REQUEST-capable STUN server. Most public STUN services ignore
  /// that attribute, so the daemon correctly leaves filtering as `unknown`.
  /// The classic STUN fallback is Port-Restricted Cone, the most conservative
  /// usable subtype for a user-facing summary. Keep [traversalType] exact for
  /// diagnostics and use this getter only for the compact UI.
  NatTraversalType get displayTraversalType {
    final mapping = mappingBehavior.toLowerCase();
    final filtering = filteringBehavior.toLowerCase();
    if (traversalType == NatTraversalType.unknown &&
        mapping == 'endpoint_independent' &&
        filtering == 'unknown') {
      return NatTraversalType.portRestrictedCone;
    }
    return traversalType;
  }

  /// Whether [displayTraversalType] is a conservative fallback rather than
  /// a subtype proved by an active filtering probe.
  bool get displayTypeIsConservativeFallback =>
      traversalType == NatTraversalType.unknown &&
      displayTraversalType == NatTraversalType.portRestrictedCone;

  double get probabilityTotal {
    return typeProbabilities.fold<double>(
      0,
      (sum, item) => sum + item.probability,
    );
  }

  List<NatTypeProbability> get maxTypeProbabilities {
    if (typeProbabilities.isEmpty) return const [];
    final maxProbability = typeProbabilities
        .map((item) => item.probability)
        .reduce((a, b) => a > b ? a : b);
    return [
      for (final item in typeProbabilities)
        if ((item.probability - maxProbability).abs() < 0.05) item,
    ];
  }
}

const _fourNatTraversalTypes = [
  NatTraversalType.fullCone,
  NatTraversalType.restrictedCone,
  NatTraversalType.portRestrictedCone,
  NatTraversalType.symmetric,
];

List<NatTypeProbability> _natTypeProbabilities({
  required JsonMap json,
  required String mappingBehavior,
  required String filteringBehavior,
  required int? confidence,
  required bool udpBlocked,
}) {
  final explicit = _explicitNatTypeProbabilities(
    json['type_probabilities'] ??
        json['nat_type_probabilities'] ??
        json['probabilities'],
  );
  if (explicit.isNotEmpty) return _normalizeNatTypeProbabilities(explicit);
  return _inferNatTypeProbabilities(
    mappingBehavior: mappingBehavior,
    filteringBehavior: filteringBehavior,
    confidence: confidence,
    udpBlocked: udpBlocked,
  );
}

List<NatTypeProbability> _explicitNatTypeProbabilities(dynamic value) {
  final items = <NatTypeProbability>[];
  if (value is Map) {
    for (final entry in value.entries) {
      final type = _natTypeFromProbabilityKey(entry.key.toString());
      final probability = _doubleOrNull(entry.value);
      if (type != null && probability != null) {
        items.add(NatTypeProbability(type: type, probability: probability));
      }
    }
  } else if (value is List) {
    for (final item in value) {
      final json = _map(item);
      final type = _natTypeFromProbabilityKey(
        _string(json['type'] ?? json['name'] ?? json['key']),
      );
      final probability = _doubleOrNull(
        json['probability'] ?? json['confidence'] ?? json['value'],
      );
      if (type != null && probability != null) {
        items.add(NatTypeProbability(type: type, probability: probability));
      }
    }
  }
  return items;
}

NatTraversalType? _natTypeFromProbabilityKey(String value) {
  final normalized = value.trim().toLowerCase().replaceAll(
    RegExp(r'[\s-]+'),
    '_',
  );
  return switch (normalized) {
    'full_cone' || 'fullcone' => NatTraversalType.fullCone,
    'restricted_cone' || 'restricted' => NatTraversalType.restrictedCone,
    'port_restricted_cone' ||
    'port_restricted' ||
    'portrestricted' => NatTraversalType.portRestrictedCone,
    'symmetric' || 'symmetric_nat' => NatTraversalType.symmetric,
    _ => null,
  };
}

List<NatTypeProbability> _inferNatTypeProbabilities({
  required String mappingBehavior,
  required String filteringBehavior,
  required int? confidence,
  required bool udpBlocked,
}) {
  final mapping = mappingBehavior.toLowerCase();
  final filtering = filteringBehavior.toLowerCase();
  if (udpBlocked || mapping == 'udp_blocked' || filtering == 'udp_blocked') {
    return const [];
  }
  if (mapping == 'open_internet') {
    return const [];
  }

  final signal = ((confidence ?? 70).clamp(1, 100)).toDouble();
  if (mapping == 'address_or_port_dependent') {
    return _probabilityForSingleType(NatTraversalType.symmetric, signal);
  }
  if (mapping == 'endpoint_independent') {
    final selected = switch (filtering) {
      'endpoint_independent' ||
      'likely_endpoint_independent' => NatTraversalType.fullCone,
      'address_dependent' => NatTraversalType.restrictedCone,
      'address_or_port_dependent' => NatTraversalType.portRestrictedCone,
      _ => null,
    };
    if (selected != null) return _probabilityForSingleType(selected, signal);
    final coneProbability = signal / 3;
    return _normalizeNatTypeProbabilities([
      NatTypeProbability(
        type: NatTraversalType.fullCone,
        probability: coneProbability,
      ),
      NatTypeProbability(
        type: NatTraversalType.restrictedCone,
        probability: coneProbability,
      ),
      NatTypeProbability(
        type: NatTraversalType.portRestrictedCone,
        probability: coneProbability,
      ),
      NatTypeProbability(
        type: NatTraversalType.symmetric,
        probability: 100 - signal,
      ),
    ]);
  }
  return const [
    NatTypeProbability(type: NatTraversalType.fullCone, probability: 25),
    NatTypeProbability(type: NatTraversalType.restrictedCone, probability: 25),
    NatTypeProbability(
      type: NatTraversalType.portRestrictedCone,
      probability: 25,
    ),
    NatTypeProbability(type: NatTraversalType.symmetric, probability: 25),
  ];
}

List<NatTypeProbability> _probabilityForSingleType(
  NatTraversalType selected,
  double confidence,
) {
  final remainder = 100 - confidence;
  final otherProbability = remainder / (_fourNatTraversalTypes.length - 1);
  return [
    for (final type in _fourNatTraversalTypes)
      NatTypeProbability(
        type: type,
        probability: type == selected ? confidence : otherProbability,
      ),
  ];
}

List<NatTypeProbability> _normalizeNatTypeProbabilities(
  List<NatTypeProbability> values,
) {
  final byType = {for (final type in _fourNatTraversalTypes) type: 0.0};
  for (final value in values) {
    if (!byType.containsKey(value.type)) continue;
    byType[value.type] = byType[value.type]! + value.probability;
  }
  final rawTotal = byType.values.fold<double>(0, (sum, value) => sum + value);
  if (rawTotal <= 0) return const [];
  final scale = rawTotal <= 1.0001 ? 100 : 100 / rawTotal;
  return [
    for (final type in _fourNatTraversalTypes)
      NatTypeProbability(type: type, probability: byType[type]! * scale),
  ];
}

class HealthSnapshot {
  HealthSnapshot({
    required this.status,
    required this.reason,
    required this.controlConnected,
    required this.controlApiReachable,
    required this.deviceLeaseHealthy,
    required this.lastControlSuccessSecsAgo,
    required this.lastDeviceLeaseSuccessSecsAgo,
    required this.reauthRequired,
    required this.criticalTasks,
  });

  final String status;
  final String? reason;

  /// Composite truth used by older clients: both the control API and the
  /// server-side device lease must be healthy.
  final bool controlConnected;

  /// Whether ordinary authenticated control API requests are succeeding.
  final bool controlApiReachable;

  /// Whether heartbeat/endpoint updates are keeping this device's online
  /// lease alive on the control server.
  final bool deviceLeaseHealthy;
  final int? lastControlSuccessSecsAgo;
  final int? lastDeviceLeaseSuccessSecsAgo;
  final bool reauthRequired;
  final List<TaskStatusSnapshot> criticalTasks;

  factory HealthSnapshot.fromJson(JsonMap json) {
    final controlConnected = _bool(json['control_connected']);
    return HealthSnapshot(
      status: _string(json['status'], 'unknown'),
      reason: _nullableString(json['reason']),
      controlConnected: controlConnected,
      // Keep compatibility with pre-split daemons without creating a false
      // contradiction in the same UI snapshot.
      controlApiReachable: json.containsKey('control_api_reachable')
          ? _bool(json['control_api_reachable'])
          : controlConnected,
      deviceLeaseHealthy: json.containsKey('device_lease_healthy')
          ? _bool(json['device_lease_healthy'])
          : controlConnected,
      lastControlSuccessSecsAgo: _intOrNull(
        json['last_control_success_secs_ago'],
      ),
      lastDeviceLeaseSuccessSecsAgo: _intOrNull(
        json['last_device_lease_success_secs_ago'],
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
