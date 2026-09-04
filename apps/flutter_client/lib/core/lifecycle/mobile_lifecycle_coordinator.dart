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
    this.daemonRuntimeIncarnation,
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

  /// Native bridge/runtime incarnation. This is stronger than PID/revision
  /// when Android restarts the embedded daemon in the same process.
  final int? daemonRuntimeIncarnation;
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
    int? daemonRuntimeIncarnation,
    bool clearDaemonRuntimeIncarnation = false,
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
      daemonRuntimeIncarnation: clearDaemonRuntimeIncarnation
          ? null
          : daemonRuntimeIncarnation ?? this.daemonRuntimeIncarnation,
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
    add('runtime_incarnation', daemonRuntimeIncarnation);
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
  final _retiredDaemonRuntimeIncarnations = <int>{};
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
    return invalidateEventLoop(event: MobileLifecycleEvent.appBackgrounded);
  }

  MobileLifecycleTransition onAppResumed() {
    if (_disposed) return _failed(MobileLifecycleEvent.appResumed);
    if (_foreground) return _duplicate(MobileLifecycleEvent.appResumed);
    _foreground = true;
    return invalidateEventLoop(event: MobileLifecycleEvent.appResumed);
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
    return invalidateEventLoop(
      event: MobileLifecycleEvent.vpnPermissionRequestStarted,
      advanceAppEpoch: true,
      permissionRequestId: nextRequest,
    );
  }

  MobileLifecycleTransition onPermissionRevoked() {
    if (_disposed) return _failed(MobileLifecycleEvent.vpnPermissionRevoked);
    if (_permissionRevoked) {
      return _duplicate(MobileLifecycleEvent.vpnPermissionRevoked);
    }
    _permissionRevoked = true;
    _permissionPending = false;
    return invalidateEventLoop(
      event: MobileLifecycleEvent.vpnPermissionRevoked,
      advanceAppEpoch: true,
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
    return invalidateEventLoop(event: event, advanceAppEpoch: true);
  }

  MobileLifecycleTransition invalidateDiagnostics() {
    return invalidateEventLoop(event: MobileLifecycleEvent.bridgeDetached);
  }

  /// Invalidate work tied to the current event-loop generation. StatusStore
  /// uses this same API for settings/URL changes and auto-refresh disable;
  /// lifecycle transitions below use the same primitive as well. Keeping the
  /// counter here makes the coordinator the single event-loop authority.
  MobileLifecycleTransition invalidateEventLoop({
    MobileLifecycleEvent event = MobileLifecycleEvent.bridgeDetached,
    bool advanceAppEpoch = true,
    int? daemonProcessId,
    bool clearDaemonProcessId = false,
    int? daemonRuntimeIncarnation,
    bool clearDaemonRuntimeIncarnation = false,
    int? daemonRevision,
    int? permissionRequestId,
    int? bridgeIncarnation,
  }) {
    if (_disposed) return _failed(event);
    return _advance(
      event,
      appEpoch: advanceAppEpoch ? _identity.appEpoch + 1 : null,
      eventLoopGeneration: _identity.eventLoopGeneration + 1,
      daemonProcessId: daemonProcessId,
      clearDaemonProcessId: clearDaemonProcessId,
      daemonRuntimeIncarnation: daemonRuntimeIncarnation,
      clearDaemonRuntimeIncarnation: clearDaemonRuntimeIncarnation,
      daemonRevision: daemonRevision,
      permissionRequestId: permissionRequestId,
      bridgeIncarnation: bridgeIncarnation,
    );
  }

  MobileLifecycleTransition observeDaemon({
    required int? processId,
    int? runtimeIncarnation,
    required int revision,
  }) {
    if (_disposed) return _failed(MobileLifecycleEvent.nativeRuntimeStarted);
    final old = _identity;
    final sameProcess = old.daemonProcessId == processId;
    final oldRuntime = old.daemonRuntimeIncarnation;
    final runtimeChanged = oldRuntime != runtimeIncarnation;

    // Android can replace the embedded Rust runtime without replacing the
    // hosting process. The runtime incarnation is therefore the first
    // identity fence: a newer bridge may legitimately start with a lower
    // revision and uptime, while a late response from the retired bridge is
    // stale even if its PID and revision look newer.
    if (oldRuntime != null && runtimeIncarnation == null) {
      return _record(
        MobileLifecycleTransition(
          event: MobileLifecycleEvent.nativeRuntimeStarted,
          outcome: MobileLifecycleOutcome.staleRejected,
          oldIdentity: old,
          newIdentity: old,
        ),
      );
    }
    if (runtimeIncarnation != null &&
        _retiredDaemonRuntimeIncarnations.contains(runtimeIncarnation)) {
      return _record(
        MobileLifecycleTransition(
          event: MobileLifecycleEvent.nativeRuntimeStarted,
          outcome: MobileLifecycleOutcome.staleRejected,
          oldIdentity: old,
          newIdentity: old,
        ),
      );
    }
    if (oldRuntime != null &&
        runtimeIncarnation != null &&
        runtimeIncarnation < oldRuntime) {
      return _record(
        MobileLifecycleTransition(
          event: MobileLifecycleEvent.nativeRuntimeStarted,
          outcome: MobileLifecycleOutcome.staleRejected,
          oldIdentity: old,
          newIdentity: old,
        ),
      );
    }
    if (!runtimeChanged && sameProcess && revision < old.daemonRevision) {
      return _record(
        MobileLifecycleTransition(
          event: MobileLifecycleEvent.nativeRuntimeStarted,
          outcome: MobileLifecycleOutcome.staleRejected,
          oldIdentity: old,
          newIdentity: old,
        ),
      );
    }
    if (!runtimeChanged && sameProcess && revision == old.daemonRevision) {
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
    if (oldRuntime != null && runtimeChanged) {
      _retiredDaemonRuntimeIncarnations.add(oldRuntime);
    }
    final daemonReplaced =
        (old.daemonProcessId != null && old.daemonProcessId != processId) ||
        runtimeChanged;
    if (daemonReplaced) {
      return invalidateEventLoop(
        event: MobileLifecycleEvent.nativeRuntimeStarted,
        advanceAppEpoch: false,
        daemonProcessId: processId,
        clearDaemonProcessId: processId == null && old.daemonProcessId != null,
        daemonRuntimeIncarnation: runtimeIncarnation,
        clearDaemonRuntimeIncarnation:
            runtimeIncarnation == null && oldRuntime != null,
        daemonRevision: revision,
      );
    }
    return _advance(
      MobileLifecycleEvent.nativeRuntimeStarted,
      daemonProcessId: processId,
      clearDaemonProcessId: processId == null && old.daemonProcessId != null,
      daemonRuntimeIncarnation: runtimeIncarnation,
      clearDaemonRuntimeIncarnation:
          runtimeIncarnation == null && oldRuntime != null,
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
    return invalidateEventLoop(
      event: MobileLifecycleEvent.bridgeAttached,
      advanceAppEpoch: true,
      bridgeIncarnation: bridgeIncarnation,
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
    // Invalidate first so every in-flight operation observes the same
    // generation fence; only then make future transitions fail closed.
    invalidateEventLoop(event: MobileLifecycleEvent.bridgeDetached);
    _disposed = true;
  }

  MobileLifecycleTransition _advance(
    MobileLifecycleEvent event, {
    int? appEpoch,
    int? eventLoopGeneration,
    int? daemonProcessId,
    bool clearDaemonProcessId = false,
    int? daemonRuntimeIncarnation,
    bool clearDaemonRuntimeIncarnation = false,
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
      daemonRuntimeIncarnation: daemonRuntimeIncarnation,
      clearDaemonRuntimeIncarnation: clearDaemonRuntimeIncarnation,
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
