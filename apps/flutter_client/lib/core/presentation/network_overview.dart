import 'dart:convert';

import '../models/diagnostics_models.dart';
import '../rooms/parallel_rooms.dart';
import '../rooms/room_profiles.dart';
import '../state/status_store.dart';

enum NetworkDisplayState {
  stopped,
  starting,
  running,
  attention,
  stale,
  unavailable,
  stopping,
  failed,
}

/// A synchronous, read-only projection of the existing runtime owners. It does
/// not poll, retain state, or authorize commands. Room actions must return to
/// ParallelRooms via the room ID; primary diagnostics actions stay primary.
class NetworkOverview {
  NetworkOverview._(this.scopes);

  factory NetworkOverview.read(StatusStore store) {
    final settings = store.settingsStore.settings;
    final primary = store.snapshot;
    final primaryStale =
        store.snapshotStale ||
        (primary != null &&
            (primary.peerSnapshotStale ||
                primary.capturedRevision != primary.revision));
    // If two owners temporarily report the same room during migration, a
    // fresh parallel catalog takes precedence over a cached primary catalog.
    // Do not relabel cached state as current or attach its rates to the room.
    final preferParallelDuplicate =
        primary != null &&
        primaryStale &&
        store.parallelRooms.sessions.values.any(
          (entry) =>
              entry.plan.room.id == primary.networkId &&
              accountSessionKey(entry.plan.settings) ==
                  accountSessionKey(settings) &&
              (_roomState(entry) == NetworkDisplayState.running ||
                  _roomState(entry) == NetworkDisplayState.attention),
        );
    final primaryState = store.daemonStarting
        ? NetworkDisplayState.starting
        : primaryStale
        ? NetworkDisplayState.stale
        : primary != null
        ? (primary.health.status.toLowerCase() == 'healthy'
              ? NetworkDisplayState.running
              : NetworkDisplayState.attention)
        : store.healthReachable
        ? NetworkDisplayState.unavailable
        : NetworkDisplayState.stopped;
    return NetworkOverview._(
      List.unmodifiable([
        if (!preferParallelDuplicate)
          NetworkScopeSnapshot(
            id: primaryScopeId,
            roomId: isRoomNetwork(settings.networkId)
                ? settings.networkId
                : null,
            name: null,
            profileId: null,
            ownerRevision: store.sessionRevision,
            snapshot: primary,
            state: primaryState,
            peers: store.stablePeerOrder(primary?.peers ?? const []),
            transferRates: primaryStale
                ? const {}
                : store.peerTransferRatesBytesPerSecond,
          ),
        for (final entry in store.parallelRooms.sessions.values)
          if (accountSessionKey(entry.plan.settings) ==
                  accountSessionKey(settings) &&
              (primary == null ||
                  entry.plan.room.id != primary.networkId ||
                  preferParallelDuplicate))
            NetworkScopeSnapshot(
              id: 'room:${entry.plan.room.id}',
              roomId: entry.plan.room.id,
              name: entry.plan.room.name,
              profileId: entry.plan.profileId,
              ownerRevision: entry.revision,
              snapshot: entry.snapshot,
              state: _roomState(entry),
              // Keep each room's catalog order, with online devices first. Never
              // feed room peers into the primary StatusStore lifecycle indexes.
              peers: [
                ...?entry.snapshot?.peers.where((peer) => peer.online),
                ...?entry.snapshot?.peers.where((peer) => !peer.online),
              ],
              // ParallelRooms does not own sampled transfer rates. Primary rates
              // keyed only by node ID must never be reused for another room.
              transferRates: const {},
            ),
      ]),
    );
  }

  static const primaryScopeId = 'primary';
  final List<NetworkScopeSnapshot> scopes;
  Iterable<NetworkScopeSnapshot> get rooms =>
      scopes.where((scope) => !scope.isPrimary);
  bool get hasRooms => rooms.isNotEmpty;
  int get runningRooms => rooms.where((scope) => scope.isRunning).length;
  bool get needsAttention => scopes.any(
    (scope) => switch (scope.state) {
      NetworkDisplayState.attention ||
      NetworkDisplayState.stale ||
      NetworkDisplayState.unavailable ||
      NetworkDisplayState.failed => true,
      _ => false,
    },
  );
  bool get isStarting =>
      scopes.any((scope) => scope.state == NetworkDisplayState.starting);
  bool get hasRunningNetwork => scopes.any((scope) => scope.isRunning);
  List<NetworkPeerSnapshot> get peers => [
    for (final scope in scopes) ...scope.peers,
  ];
  int get onlineCount => peers.where((item) => item.online).length;
  int get availableCount => peers.where((item) => item.available).length;

  List<NetworkScopeSnapshot> selected(String? scopeId) => scopeId == null
      ? scopes
      : [
          for (final scope in scopes)
            if (scope.id == scopeId) scope,
        ];
}

class NetworkScopeSnapshot {
  NetworkScopeSnapshot({
    required this.id,
    required this.roomId,
    required this.name,
    required this.profileId,
    required this.ownerRevision,
    required this.snapshot,
    required this.state,
    required List<PeerSnapshot> peers,
    required Map<String, int> transferRates,
  }) : peers = List.unmodifiable([
         for (final peer in peers)
           NetworkPeerSnapshot(
             scopeId: id,
             roomId: roomId,
             roomName: name,
             profileId: profileId,
             ownerRevision: ownerRevision,
             snapshotRevision: snapshot?.revision ?? 0,
             networkGeneration: snapshot?.networkGeneration ?? 0,
             runtimeIncarnation: snapshot?.runtimeIncarnation,
             processId: snapshot?.processId,
             peer: peer,
             current:
                 state == NetworkDisplayState.running ||
                 state == NetworkDisplayState.attention,
             transferBytesPerSecond: transferRates[peer.nodeId],
           ),
       ]);

  final String id;
  final String? roomId;
  final String? name;
  final String? profileId;
  final int ownerRevision;
  final DiagnosticsSnapshot? snapshot;
  final NetworkDisplayState state;
  final List<NetworkPeerSnapshot> peers;
  bool get isPrimary => id == NetworkOverview.primaryScopeId;
  bool get isRunning =>
      state == NetworkDisplayState.running ||
      state == NetworkDisplayState.attention;
}

class NetworkPeerSnapshot {
  const NetworkPeerSnapshot({
    required this.scopeId,
    required this.roomId,
    required this.roomName,
    required this.profileId,
    required this.ownerRevision,
    required this.snapshotRevision,
    required this.networkGeneration,
    required this.runtimeIncarnation,
    required this.processId,
    required this.peer,
    required this.current,
    required this.transferBytesPerSecond,
  });

  final String scopeId;
  final String? roomId;
  final String? roomName;
  final String? profileId;
  final int ownerRevision;
  final int snapshotRevision;
  final int networkGeneration;
  final int? runtimeIncarnation;
  final int? processId;
  final PeerSnapshot peer;
  final bool current;
  final int? transferBytesPerSecond;
  String get identity => jsonEncode([scopeId, peer.nodeId]);
  bool get isPrimary => scopeId == NetworkOverview.primaryScopeId;
  bool get online => current && peer.online && peer.path != 'offline';
  bool get available =>
      online && (peer.isDirectVerified || peer.isRelayVerified);
}

NetworkDisplayState _roomState(ParallelRoomSession entry) =>
    switch (entry.phase) {
      RoomConnectionPhase.starting => NetworkDisplayState.starting,
      RoomConnectionPhase.stopping => NetworkDisplayState.stopping,
      RoomConnectionPhase.failed => NetworkDisplayState.failed,
      RoomConnectionPhase.unavailable => NetworkDisplayState.unavailable,
      RoomConnectionPhase.running =>
        entry.snapshot == null
            ? NetworkDisplayState.unavailable
            : entry.snapshot!.peerSnapshotStale ||
                  entry.snapshot!.capturedRevision != entry.snapshot!.revision
            ? NetworkDisplayState.stale
            : entry.snapshot!.health.status.toLowerCase() == 'healthy'
            ? NetworkDisplayState.running
            : NetworkDisplayState.attention,
    };
