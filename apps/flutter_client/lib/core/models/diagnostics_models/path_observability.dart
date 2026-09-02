part of '../diagnostics_models.dart';

PathObservabilitySnapshot _pathObservabilityOrEmpty(dynamic value) {
  final json = _mapOrNull(value);
  return json == null
      ? PathObservabilitySnapshot.empty()
      : PathObservabilitySnapshot.fromJson(json);
}

/// Versioned, additive path-transition diagnostics. Older daemons omit this
/// object; callers then receive [PathObservabilitySnapshot.empty].
class PathObservabilitySnapshot {
  PathObservabilitySnapshot({
    required this.schemaVersion,
    required this.networkEpoch,
    required this.lifecycle,
    required this.currentPath,
    required this.previousPath,
    required this.transitionReason,
    required this.pathAgeMs,
    required this.pathStateRevision,
    required this.directState,
    required this.relayState,
    required this.recoveryState,
    required this.directHealth,
    required this.relayHealth,
    required this.latestHandshake,
    required this.latestValidation,
    required this.candidatePunch,
    required this.selectedPathMtu,
    required this.selectedUdpDatagramSize,
    required this.metrics,
    required this.transitions,
  });

  factory PathObservabilitySnapshot.empty() => PathObservabilitySnapshot(
    schemaVersion: 0,
    networkEpoch: null,
    lifecycle: 'unknown',
    currentPath: null,
    previousPath: null,
    transitionReason: 'unavailable',
    pathAgeMs: 0,
    pathStateRevision: 0,
    directState: 'unknown',
    relayState: 'unknown',
    recoveryState: 'unknown',
    directHealth: PathHealthSnapshot.fromJson(const {}),
    relayHealth: PathHealthSnapshot.fromJson(const {}),
    latestHandshake: PathHandshakeSnapshot.empty(),
    latestValidation: PathValidationSnapshot.empty(),
    candidatePunch: CandidatePunchSummarySnapshot.empty(),
    selectedPathMtu: null,
    selectedUdpDatagramSize: null,
    metrics: PathObservabilityMetricsSnapshot.empty(),
    transitions: const [],
  );

  factory PathObservabilitySnapshot.fromJson(JsonMap json) {
    final epochJson = _mapOrNull(json['network_epoch']);
    return PathObservabilitySnapshot(
      schemaVersion: _int(json['schema_version']),
      networkEpoch: epochJson == null
          ? null
          : PathEpochSnapshot.fromJson(epochJson),
      lifecycle: _string(json['lifecycle'], 'unknown'),
      currentPath: _nullableString(json['current_path']),
      previousPath: _nullableString(json['previous_path']),
      transitionReason: _string(json['transition_reason'], 'unknown'),
      pathAgeMs: _int(json['path_age_ms']),
      pathStateRevision: _int(json['path_state_revision']),
      directState: _string(json['direct_state'], 'unknown'),
      relayState: _string(json['relay_state'], 'unknown'),
      recoveryState: _string(json['recovery_state'], 'unknown'),
      directHealth: PathHealthSnapshot.fromJson(_map(json['direct_health'])),
      relayHealth: PathHealthSnapshot.fromJson(_map(json['relay_health'])),
      latestHandshake: PathHandshakeSnapshot.fromJson(
        _map(json['latest_handshake']),
      ),
      latestValidation: PathValidationSnapshot.fromJson(
        _map(json['latest_validation']),
      ),
      candidatePunch: CandidatePunchSummarySnapshot.fromJson(
        _map(json['candidate_punch']),
      ),
      selectedPathMtu: _intOrNull(json['selected_path_mtu']),
      selectedUdpDatagramSize: _intOrNull(json['selected_udp_datagram_size']),
      metrics: PathObservabilityMetricsSnapshot.fromJson(_map(json['metrics'])),
      transitions: [
        for (final item in _list(json['transitions']))
          PathTransitionSnapshot.fromJson(_map(item)),
      ],
    );
  }

  final int schemaVersion;
  final PathEpochSnapshot? networkEpoch;
  final String lifecycle;
  final String? currentPath;
  final String? previousPath;
  final String transitionReason;
  final int pathAgeMs;
  final int pathStateRevision;
  final String directState;
  final String relayState;
  final String recoveryState;
  final PathHealthSnapshot directHealth;
  final PathHealthSnapshot relayHealth;
  final PathHandshakeSnapshot latestHandshake;
  final PathValidationSnapshot latestValidation;
  final CandidatePunchSummarySnapshot candidatePunch;
  final int? selectedPathMtu;
  final int? selectedUdpDatagramSize;
  final PathObservabilityMetricsSnapshot metrics;
  final List<PathTransitionSnapshot> transitions;
}

class PathEpochSnapshot {
  PathEpochSnapshot({
    required this.networkGeneration,
    required this.peerSessionGeneration,
    required this.remoteCandidateEpoch,
  });

  factory PathEpochSnapshot.fromJson(JsonMap json) => PathEpochSnapshot(
    networkGeneration: _int(json['network_generation']),
    peerSessionGeneration: _int(json['peer_session_generation']),
    remoteCandidateEpoch: _int(json['remote_candidate_epoch']),
  );

  final int networkGeneration;
  final int peerSessionGeneration;
  final int remoteCandidateEpoch;
}

class PathTransitionSnapshot {
  PathTransitionSnapshot({
    required this.ageMs,
    required this.revision,
    required this.eventKind,
    required this.decision,
    required this.reasonCode,
    required this.epoch,
    required this.previousPath,
    required this.currentPath,
  });

  factory PathTransitionSnapshot.fromJson(JsonMap json) {
    final epochJson = _mapOrNull(json['epoch']);
    return PathTransitionSnapshot(
      ageMs: _int(json['age_ms']),
      revision: _int(json['revision']),
      eventKind: _string(json['event_kind']),
      decision: _string(json['decision']),
      reasonCode: _string(json['reason_code']),
      epoch: epochJson == null ? null : PathEpochSnapshot.fromJson(epochJson),
      previousPath: _nullableString(json['previous_path']),
      currentPath: _nullableString(json['current_path']),
    );
  }

  final int ageMs;
  final int revision;
  final String eventKind;
  final String decision;
  final String reasonCode;
  final PathEpochSnapshot? epoch;
  final String? previousPath;
  final String? currentPath;
}

class PathHandshakeSnapshot {
  PathHandshakeSnapshot({
    required this.latestStage,
    required this.latestAgeMs,
    required this.networkGeneration,
  });

  factory PathHandshakeSnapshot.empty() => PathHandshakeSnapshot(
    latestStage: null,
    latestAgeMs: null,
    networkGeneration: null,
  );

  factory PathHandshakeSnapshot.fromJson(JsonMap json) => PathHandshakeSnapshot(
    latestStage: _nullableString(json['latest_stage']),
    latestAgeMs: _intOrNull(json['latest_age_ms']),
    networkGeneration: _intOrNull(json['network_generation']),
  );

  final String? latestStage;
  final int? latestAgeMs;
  final int? networkGeneration;
}

class PathValidationSnapshot {
  PathValidationSnapshot({
    required this.latestStage,
    required this.latestAgeMs,
    required this.validationRttMs,
    required this.ackEndpointAuthenticated,
  });

  factory PathValidationSnapshot.empty() => PathValidationSnapshot(
    latestStage: null,
    latestAgeMs: null,
    validationRttMs: null,
    ackEndpointAuthenticated: null,
  );

  factory PathValidationSnapshot.fromJson(JsonMap json) =>
      PathValidationSnapshot(
        latestStage: _nullableString(json['latest_stage']),
        latestAgeMs: _intOrNull(json['latest_age_ms']),
        validationRttMs: _intOrNull(json['validation_rtt_ms']),
        ackEndpointAuthenticated: json.containsKey('ack_endpoint_authenticated')
            ? _bool(json['ack_endpoint_authenticated'])
            : null,
      );

  final String? latestStage;
  final int? latestAgeMs;
  final int? validationRttMs;
  final bool? ackEndpointAuthenticated;
}

class CandidatePunchSummarySnapshot {
  CandidatePunchSummarySnapshot({
    required this.candidatePairCount,
    required this.signaledCandidateCount,
    required this.latestCandidateCount,
    required this.latestSentProbes,
    required this.latestUniqueTargetPorts,
    required this.latestRepeatedTargetPorts,
  });

  factory CandidatePunchSummarySnapshot.empty() =>
      CandidatePunchSummarySnapshot(
        candidatePairCount: 0,
        signaledCandidateCount: 0,
        latestCandidateCount: null,
        latestSentProbes: null,
        latestUniqueTargetPorts: null,
        latestRepeatedTargetPorts: null,
      );

  factory CandidatePunchSummarySnapshot.fromJson(JsonMap json) =>
      CandidatePunchSummarySnapshot(
        candidatePairCount: _int(json['candidate_pair_count']),
        signaledCandidateCount: _int(json['signaled_candidate_count']),
        latestCandidateCount: _intOrNull(json['latest_candidate_count']),
        latestSentProbes: _intOrNull(json['latest_sent_probes']),
        latestUniqueTargetPorts: _intOrNull(json['latest_unique_target_ports']),
        latestRepeatedTargetPorts: _intOrNull(
          json['latest_repeated_target_ports'],
        ),
      );

  final int candidatePairCount;
  final int signaledCandidateCount;
  final int? latestCandidateCount;
  final int? latestSentProbes;
  final int? latestUniqueTargetPorts;
  final int? latestRepeatedTargetPorts;
}

class PathLatencyHistogramSnapshot {
  PathLatencyHistogramSnapshot({
    required this.boundsMs,
    required this.buckets,
    required this.count,
    required this.sumMs,
    required this.maxMs,
  });

  factory PathLatencyHistogramSnapshot.empty() => PathLatencyHistogramSnapshot(
    boundsMs: const [50, 100, 250, 500, 1000, 3000, 10000, 30000],
    buckets: const [0, 0, 0, 0, 0, 0, 0, 0, 0],
    count: 0,
    sumMs: 0,
    maxMs: null,
  );

  factory PathLatencyHistogramSnapshot.fromJson(JsonMap json) =>
      PathLatencyHistogramSnapshot(
        boundsMs: [for (final value in _list(json['bounds_ms'])) _int(value)],
        buckets: [for (final value in _list(json['buckets'])) _int(value)],
        count: _int(json['count']),
        sumMs: _int(json['sum_ms']),
        maxMs: _intOrNull(json['max_ms']),
      );

  final List<int> boundsMs;
  final List<int> buckets;
  final int count;
  final int sumMs;
  final int? maxMs;
}

class PathObservabilityMetricsSnapshot {
  PathObservabilityMetricsSnapshot({
    required this.acceptedTransitions,
    required this.acceptedObservations,
    required this.duplicateEvents,
    required this.rejectedTransitions,
    required this.pathChanges,
    required this.directAttempts,
    required this.directRetries,
    required this.directValidations,
    required this.directSuccesses,
    required this.directFailures,
    required this.validationFailures,
    required this.relayConfirmations,
    required this.relayFallbacks,
    required this.relayFailures,
    required this.candidateRefreshes,
    required this.controlReconnects,
    required this.networkGenerationChanges,
    required this.lifecycleResets,
    required this.dplpmtudChanges,
    required this.activeTasks,
    required this.activeSockets,
    required this.droppedTransitionEvents,
    required this.directTimeToConnectMs,
  });

  factory PathObservabilityMetricsSnapshot.empty() =>
      PathObservabilityMetricsSnapshot.fromJson(const {});

  factory PathObservabilityMetricsSnapshot.fromJson(JsonMap json) {
    final histogram = _mapOrNull(json['direct_time_to_connect_ms']);
    return PathObservabilityMetricsSnapshot(
      acceptedTransitions: _int(json['accepted_transitions']),
      acceptedObservations: _int(json['accepted_observations']),
      duplicateEvents: _int(json['duplicate_events']),
      rejectedTransitions: _int(json['rejected_transitions']),
      pathChanges: _int(json['path_changes']),
      directAttempts: _int(json['direct_attempts']),
      directRetries: _int(json['direct_retries']),
      directValidations: _int(json['direct_validations']),
      directSuccesses: _int(json['direct_successes']),
      directFailures: _int(json['direct_failures']),
      validationFailures: _int(json['validation_failures']),
      relayConfirmations: _int(json['relay_confirmations']),
      relayFallbacks: _int(json['relay_fallbacks']),
      relayFailures: _int(json['relay_failures']),
      candidateRefreshes: _int(json['candidate_refreshes']),
      controlReconnects: _int(json['control_reconnects']),
      networkGenerationChanges: _int(json['network_generation_changes']),
      lifecycleResets: _int(json['lifecycle_resets']),
      dplpmtudChanges: _int(json['dplpmtud_changes']),
      activeTasks: _int(json['active_tasks']),
      activeSockets: _int(json['active_sockets']),
      droppedTransitionEvents: _int(json['dropped_transition_events']),
      directTimeToConnectMs: histogram == null
          ? PathLatencyHistogramSnapshot.empty()
          : PathLatencyHistogramSnapshot.fromJson(histogram),
    );
  }

  final int acceptedTransitions;
  final int acceptedObservations;
  final int duplicateEvents;
  final int rejectedTransitions;
  final int pathChanges;
  final int directAttempts;
  final int directRetries;
  final int directValidations;
  final int directSuccesses;
  final int directFailures;
  final int validationFailures;
  final int relayConfirmations;
  final int relayFallbacks;
  final int relayFailures;
  final int candidateRefreshes;
  final int controlReconnects;
  final int networkGenerationChanges;
  final int lifecycleResets;
  final int dplpmtudChanges;
  final int activeTasks;
  final int activeSockets;
  final int droppedTransitionEvents;
  final PathLatencyHistogramSnapshot directTimeToConnectMs;
}
