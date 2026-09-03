import 'dart:collection';

/// The platform-neutral lifecycle vocabulary shared by Flutter and the
/// checked-in mobile lifecycle contract. Network generations and path
/// decisions remain daemon-owned.
enum MobileLifecycleEvent {
  appBackgrounded('app_backgrounded'),
  appResumed('app_resumed'),
  physicalNetworkChanged('physical_network_changed'),
  vpnPermissionRequestStarted('vpn_permission_request_started'),
  vpnPermissionRevoked('vpn_permission_revoked'),
  vpnPermissionGranted('vpn_permission_granted'),
  vpnStartRequested('vpn_start_requested'),
  explicitStopRequested('explicit_stop_requested'),
  activityRecreated('activity_recreated'),
  serviceRecreated('service_recreated'),
  bridgeAttached('bridge_attached'),
  bridgeDetached('bridge_detached'),
  nativeRuntimeStarted('native_runtime_started'),
  nativeRuntimeStopped('native_runtime_stopped'),
  nativeMonitorCallback('native_monitor_callback'),
  automaticRestartScheduled('automatic_restart_scheduled'),
  automaticRestartRejected('automatic_restart_rejected'),
  controlDisconnected('control_disconnected'),
  controlReconnected('control_reconnected'),
  candidateRefreshStarted('candidate_refresh_started'),
  relayRetained('relay_retained'),
  directReconfirmed('direct_reconfirmed');

  const MobileLifecycleEvent(this.wireName);

  final String wireName;
}

enum MobileLifecycleOutcome {
  applied('applied'),
  duplicate('duplicate'),
  staleRejected('stale_rejected'),
  superseded('superseded'),
  failed('failed');

  const MobileLifecycleOutcome(this.wireName);

  final String wireName;
}

/// Identity fields are optional because each layer owns only the fields it
/// can authoritatively advance.
class MobileLifecycleIdentity {
  const MobileLifecycleIdentity({
    this.appEpoch = 0,
    this.eventLoopGeneration = 0,
    this.daemonProcessId,
    this.daemonRevision = 0,
    this.permissionRequestId,
    this.activityIncarnation,
    this.engineIncarnation,
    this.serviceIncarnation,
    this.automaticRestartGeneration,
    this.bridgeIncarnation,
    this.networkGeneration,
    this.candidateEpoch,
    this.socketPublicationGeneration,
    this.controlConnectionGeneration,
    this.peerSessionGeneration,
    this.relayConnectionId,
    this.directValidationOwner,
    this.traceId,
  });

  final int appEpoch;
  final int eventLoopGeneration;
  final int? daemonProcessId;
  final int daemonRevision;
  final int? permissionRequestId;
  final int? activityIncarnation;
  final int? engineIncarnation;
  final int? serviceIncarnation;
  final int? automaticRestartGeneration;
  final int? bridgeIncarnation;
  final int? networkGeneration;
  final int? candidateEpoch;
  final int? socketPublicationGeneration;
  final int? controlConnectionGeneration;
  final int? peerSessionGeneration;
  final int? relayConnectionId;
  final String? directValidationOwner;
  final String? traceId;

  MobileLifecycleIdentity copyWith({
    int? appEpoch,
    int? eventLoopGeneration,
    int? daemonProcessId,
    bool clearDaemonProcessId = false,
    int? daemonRevision,
    int? permissionRequestId,
    int? activityIncarnation,
    int? engineIncarnation,
    int? serviceIncarnation,
    int? automaticRestartGeneration,
    int? bridgeIncarnation,
    int? networkGeneration,
    int? candidateEpoch,
    int? socketPublicationGeneration,
    int? controlConnectionGeneration,
    int? peerSessionGeneration,
    int? relayConnectionId,
    String? directValidationOwner,
    String? traceId,
  }) {
    return MobileLifecycleIdentity(
      appEpoch: appEpoch ?? this.appEpoch,
      eventLoopGeneration: eventLoopGeneration ?? this.eventLoopGeneration,
      daemonProcessId: clearDaemonProcessId
          ? null
          : daemonProcessId ?? this.daemonProcessId,
      daemonRevision: daemonRevision ?? this.daemonRevision,
      permissionRequestId: permissionRequestId ?? this.permissionRequestId,
      activityIncarnation: activityIncarnation ?? this.activityIncarnation,
      engineIncarnation: engineIncarnation ?? this.engineIncarnation,
      serviceIncarnation: serviceIncarnation ?? this.serviceIncarnation,
      automaticRestartGeneration:
          automaticRestartGeneration ?? this.automaticRestartGeneration,
      bridgeIncarnation: bridgeIncarnation ?? this.bridgeIncarnation,
      networkGeneration: networkGeneration ?? this.networkGeneration,
      candidateEpoch: candidateEpoch ?? this.candidateEpoch,
      socketPublicationGeneration:
          socketPublicationGeneration ?? this.socketPublicationGeneration,
      controlConnectionGeneration:
          controlConnectionGeneration ?? this.controlConnectionGeneration,
      peerSessionGeneration:
          peerSessionGeneration ?? this.peerSessionGeneration,
      relayConnectionId: relayConnectionId ?? this.relayConnectionId,
      directValidationOwner:
          directValidationOwner ?? this.directValidationOwner,
      traceId: traceId ?? this.traceId,
    );
  }

  Map<String, Object> toJson() {
    final fields = <String, Object>{
      'app_epoch': appEpoch,
      'event_loop_generation': eventLoopGeneration,
      'daemon_revision': daemonRevision,
    };
    void add(String key, Object? value) {
      if (value != null) fields[key] = value;
    }

    add('daemon_process_id', daemonProcessId);
    add('permission_request_id', permissionRequestId);
    add('activity_incarnation', activityIncarnation);
    add('engine_incarnation', engineIncarnation);
    add('service_incarnation', serviceIncarnation);
    add('automatic_restart_generation', automaticRestartGeneration);
    add('bridge_incarnation', bridgeIncarnation);
    add('network_generation', networkGeneration);
    add('candidate_epoch', candidateEpoch);
    add('socket_publication_generation', socketPublicationGeneration);
    add('control_connection_generation', controlConnectionGeneration);
    add('peer_session_generation', peerSessionGeneration);
    add('relay_connection_id', relayConnectionId);
    add('direct_validation_owner', directValidationOwner);
    add('trace_id', traceId);
    return UnmodifiableMapView(fields);
  }
}

class MobileLifecycleTransition {
  const MobileLifecycleTransition({
    required this.event,
    required this.outcome,
    required this.oldIdentity,
    required this.newIdentity,
  });

  final MobileLifecycleEvent event;
  final MobileLifecycleOutcome outcome;
  final MobileLifecycleIdentity oldIdentity;
  final MobileLifecycleIdentity newIdentity;
}

/// Coordinates app, diagnostics, permission and bridge identity at the
/// Flutter boundary without duplicating the daemon's path state machine.
class MobileLifecycleCoordinator {
  MobileLifecycleCoordinator()
    : _identity = const MobileLifecycleIdentity(),
      _foreground = true;

  MobileLifecycleIdentity _identity;
  bool _foreground;
  bool _disposed = false;
  bool _permissionRevoked = false;
  bool _permissionPending = false;
  final _retiredDaemonProcessIds = <int>{};
  MobileLifecycleTransition? _lastTransition;

  MobileLifecycleIdentity get identity => _identity;
  int get appEpoch => _identity.appEpoch;
  int get eventLoopGeneration => _identity.eventLoopGeneration;
  bool get isForeground => _foreground;
  bool get isDisposed => _disposed;
  MobileLifecycleTransition? get lastTransition => _lastTransition;

  MobileLifecycleTransition onAppBackgrounded() {
    if (_disposed) return _failed(MobileLifecycleEvent.appBackgrounded);
    if (!_foreground) return _duplicate(MobileLifecycleEvent.appBackgrounded);
    _foreground = false;
    return _advance(
      MobileLifecycleEvent.appBackgrounded,
      appEpoch: _identity.appEpoch + 1,
      eventLoopGeneration: _identity.eventLoopGeneration + 1,
    );
  }

  MobileLifecycleTransition onAppResumed() {
    if (_disposed) return _failed(MobileLifecycleEvent.appResumed);
    if (_foreground) return _duplicate(MobileLifecycleEvent.appResumed);
    _foreground = true;
    return _advance(
      MobileLifecycleEvent.appResumed,
      appEpoch: _identity.appEpoch + 1,
      eventLoopGeneration: _identity.eventLoopGeneration + 1,
    );
  }

  MobileLifecycleTransition beginPermissionRequest() {
    if (_disposed) {
      return _failed(MobileLifecycleEvent.vpnPermissionRequestStarted);
    }
    if (_permissionPending) {
      return _failed(MobileLifecycleEvent.vpnPermissionRequestStarted);
    }
    final nextRequest = (_identity.permissionRequestId ?? 0) + 1;
    _permissionRevoked = false;
    _permissionPending = true;
    return _advance(
      MobileLifecycleEvent.vpnPermissionRequestStarted,
      permissionRequestId: nextRequest,
      appEpoch: _identity.appEpoch + 1,
      eventLoopGeneration: _identity.eventLoopGeneration + 1,
    );
  }

  MobileLifecycleTransition onPermissionRevoked() {
    if (_disposed) return _failed(MobileLifecycleEvent.vpnPermissionRevoked);
    if (_permissionRevoked) {
      return _duplicate(MobileLifecycleEvent.vpnPermissionRevoked);
    }
    _permissionRevoked = true;
    _permissionPending = false;
    return _advance(
      MobileLifecycleEvent.vpnPermissionRevoked,
      appEpoch: _identity.appEpoch + 1,
      eventLoopGeneration: _identity.eventLoopGeneration + 1,
    );
  }

  MobileLifecycleTransition completePermissionRequest({
    required int requestId,
    required bool granted,
  }) {
    final event = granted
        ? MobileLifecycleEvent.vpnPermissionGranted
        : MobileLifecycleEvent.vpnPermissionRevoked;
    if (_disposed) return _failed(event);
    if (_permissionRevoked ||
        !_permissionPending ||
        requestId != _identity.permissionRequestId) {
      return _record(
        MobileLifecycleTransition(
          event: event,
          outcome: MobileLifecycleOutcome.staleRejected,
          oldIdentity: _identity,
          newIdentity: _identity,
        ),
      );
    }
    _permissionPending = false;
    if (!granted) return onPermissionRevoked();
    return _advance(
      event,
      appEpoch: _identity.appEpoch + 1,
      eventLoopGeneration: _identity.eventLoopGeneration + 1,
    );
  }

  MobileLifecycleTransition invalidateDiagnostics() {
    if (_disposed) return _failed(MobileLifecycleEvent.bridgeDetached);
    return _advance(
      MobileLifecycleEvent.bridgeDetached,
      appEpoch: _identity.appEpoch + 1,
      eventLoopGeneration: _identity.eventLoopGeneration + 1,
    );
  }

  MobileLifecycleTransition observeDaemon({
    required int? processId,
    required int revision,
  }) {
    if (_disposed) return _failed(MobileLifecycleEvent.nativeRuntimeStarted);
    final old = _identity;
    final sameProcess = old.daemonProcessId == processId;
    if (sameProcess && revision < old.daemonRevision) {
      return _record(
        MobileLifecycleTransition(
          event: MobileLifecycleEvent.nativeRuntimeStarted,
          outcome: MobileLifecycleOutcome.staleRejected,
          oldIdentity: old,
          newIdentity: old,
        ),
      );
    }
    if (sameProcess && revision == old.daemonRevision) {
      return _duplicate(MobileLifecycleEvent.nativeRuntimeStarted);
    }
    if (!sameProcess &&
        processId != null &&
        _retiredDaemonProcessIds.contains(processId)) {
      return _record(
        MobileLifecycleTransition(
          event: MobileLifecycleEvent.nativeRuntimeStarted,
          outcome: MobileLifecycleOutcome.staleRejected,
          oldIdentity: old,
          newIdentity: old,
        ),
      );
    }
    if (!sameProcess && old.daemonProcessId != null) {
      _retiredDaemonProcessIds.add(old.daemonProcessId!);
    }
    final daemonReplaced =
        old.daemonProcessId != null && old.daemonProcessId != processId;
    return _advance(
      MobileLifecycleEvent.nativeRuntimeStarted,
      eventLoopGeneration: daemonReplaced ? old.eventLoopGeneration + 1 : null,
      daemonProcessId: processId,
      clearDaemonProcessId: processId == null && old.daemonProcessId != null,
      daemonRevision: revision,
    );
  }

  MobileLifecycleTransition observeBridge(int? bridgeIncarnation) {
    if (_disposed) return _failed(MobileLifecycleEvent.bridgeAttached);
    if (bridgeIncarnation == null) {
      return _failed(MobileLifecycleEvent.bridgeAttached);
    }
    if (_identity.bridgeIncarnation == bridgeIncarnation) {
      return _duplicate(MobileLifecycleEvent.bridgeAttached);
    }
    if (_identity.bridgeIncarnation != null &&
        bridgeIncarnation < _identity.bridgeIncarnation!) {
      return _record(
        MobileLifecycleTransition(
          event: MobileLifecycleEvent.bridgeAttached,
          outcome: MobileLifecycleOutcome.staleRejected,
          oldIdentity: _identity,
          newIdentity: _identity,
        ),
      );
    }
    return _advance(
      MobileLifecycleEvent.bridgeAttached,
      bridgeIncarnation: bridgeIncarnation,
      appEpoch: _identity.appEpoch + 1,
      eventLoopGeneration: _identity.eventLoopGeneration + 1,
    );
  }

  bool acceptsEventLoop({required int appEpoch, required int generation}) {
    return !_disposed &&
        _foreground &&
        _identity.appEpoch == appEpoch &&
        _identity.eventLoopGeneration == generation;
  }

  bool acceptsAppEpoch(int appEpoch) =>
      !_disposed && _identity.appEpoch == appEpoch;

  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _identity = _identity.copyWith(
      appEpoch: _identity.appEpoch + 1,
      eventLoopGeneration: _identity.eventLoopGeneration + 1,
    );
  }

  MobileLifecycleTransition _advance(
    MobileLifecycleEvent event, {
    int? appEpoch,
    int? eventLoopGeneration,
    int? daemonProcessId,
    bool clearDaemonProcessId = false,
    int? daemonRevision,
    int? permissionRequestId,
    int? bridgeIncarnation,
  }) {
    final old = _identity;
    _identity = _identity.copyWith(
      appEpoch: appEpoch,
      eventLoopGeneration: eventLoopGeneration,
      daemonProcessId: daemonProcessId,
      clearDaemonProcessId: clearDaemonProcessId,
      daemonRevision: daemonRevision,
      permissionRequestId: permissionRequestId,
      bridgeIncarnation: bridgeIncarnation,
    );
    return _record(
      MobileLifecycleTransition(
        event: event,
        outcome: MobileLifecycleOutcome.applied,
        oldIdentity: old,
        newIdentity: _identity,
      ),
    );
  }

  MobileLifecycleTransition _duplicate(MobileLifecycleEvent event) {
    return _record(
      MobileLifecycleTransition(
        event: event,
        outcome: MobileLifecycleOutcome.duplicate,
        oldIdentity: _identity,
        newIdentity: _identity,
      ),
    );
  }

  MobileLifecycleTransition _failed(MobileLifecycleEvent event) {
    return _record(
      MobileLifecycleTransition(
        event: event,
        outcome: MobileLifecycleOutcome.failed,
        oldIdentity: _identity,
        newIdentity: _identity,
      ),
    );
  }

  MobileLifecycleTransition _record(MobileLifecycleTransition transition) {
    _lastTransition = transition;
    return transition;
  }
}
