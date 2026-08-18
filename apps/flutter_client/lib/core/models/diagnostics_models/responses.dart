part of '../diagnostics_models.dart';

const supportedDiagnosticsContractVersion = 1;

class UnsupportedDiagnosticsContractException implements Exception {
  const UnsupportedDiagnosticsContractException(this.version);

  final int version;

  @override
  String toString() =>
      'Unsupported diagnostics contractVersion=$version; supported=$supportedDiagnosticsContractVersion';
}

int _contractVersion(JsonMap json) {
  final raw = json['contractVersion'] ?? json['contract_version'];
  if (raw == null) return 0;
  if (raw is! num || raw.toInt() != raw) {
    throw const FormatException(
      'Diagnostics contractVersion must be an integer',
    );
  }
  final version = raw.toInt();
  if (version > supportedDiagnosticsContractVersion) {
    throw UnsupportedDiagnosticsContractException(version);
  }
  if (version < 0) {
    throw const FormatException(
      'Diagnostics contractVersion cannot be negative',
    );
  }
  return version;
}

void _require(JsonMap json, Iterable<String> keys, String responseName) {
  for (final key in keys) {
    if (!json.containsKey(key)) {
      throw FormatException('$responseName is missing required field $key');
    }
  }
}

class StatusResponse {
  const StatusResponse({required this.contractVersion, required this.snapshot});

  final int contractVersion;
  final DiagnosticsSnapshot snapshot;

  factory StatusResponse.fromJson(JsonMap json) {
    final version = _contractVersion(json);
    _require(json, const [
      'node_id',
      'virtual_ip',
      'peers',
      'stats',
      'health',
    ], 'StatusResponse');
    return StatusResponse(
      contractVersion: version,
      snapshot: DiagnosticsSnapshot.fromJson(json),
    );
  }
}

class DiagnosticEvent {
  const DiagnosticEvent({
    required this.seq,
    required this.event,
    required this.atMs,
    this.path,
    this.reasonCode,
    this.peerId,
  });

  final int seq;
  final String event;
  final int atMs;
  final String? path;
  final String? reasonCode;
  final String? peerId;

  factory DiagnosticEvent.fromJson(JsonMap json) {
    _require(json, const ['seq', 'event', 'at_ms'], 'DiagnosticEvent');
    return DiagnosticEvent(
      seq: _requiredInt(json['seq'], 'DiagnosticEvent.seq'),
      event: _requiredString(json['event'], 'DiagnosticEvent.event'),
      atMs: _requiredInt(json['at_ms'], 'DiagnosticEvent.at_ms'),
      path: _nullableString(json['path']),
      reasonCode: _nullableString(json['reason_code']),
      peerId: _nullableString(json['peer_id']),
    );
  }
}

class EventsResponse {
  const EventsResponse({
    required this.contractVersion,
    required this.revision,
    required this.events,
  });

  final int contractVersion;
  final int revision;
  final List<DiagnosticEvent> events;

  factory EventsResponse.fromJson(JsonMap json) {
    final version = _contractVersion(json);
    _require(json, const ['revision', 'events'], 'EventsResponse');
    final rawEvents = json['events'];
    if (rawEvents is! List) {
      throw const FormatException('EventsResponse.events must be an array');
    }
    return EventsResponse(
      contractVersion: version,
      revision: _requiredInt(json['revision'], 'EventsResponse.revision'),
      events: [
        for (final item in rawEvents)
          DiagnosticEvent.fromJson(_requiredMap(item, 'EventsResponse.events')),
      ],
    );
  }
}

class RouteEntryResponse {
  const RouteEntryResponse({
    required this.cidr,
    required this.expectedInterface,
    required this.actualInterface,
    required this.state,
    required this.owned,
  });

  final String cidr;
  final String expectedInterface;
  final String? actualInterface;
  final String state;
  final bool owned;

  factory RouteEntryResponse.fromJson(JsonMap json) {
    _require(json, const [
      'cidr',
      'expected_interface',
      'actual_interface',
      'state',
      'owned',
    ], 'RouteEntryResponse');
    return RouteEntryResponse(
      cidr: _requiredString(json['cidr'], 'RouteEntryResponse.cidr'),
      expectedInterface: _requiredString(
        json['expected_interface'],
        'RouteEntryResponse.expected_interface',
      ),
      actualInterface: _nullableString(json['actual_interface']),
      state: _requiredString(json['state'], 'RouteEntryResponse.state'),
      owned: _requiredBool(json['owned'], 'RouteEntryResponse.owned'),
    );
  }
}

class RoutesResponse {
  const RoutesResponse({
    required this.contractVersion,
    required this.interfaceName,
    required this.mtu,
    required this.healthy,
    required this.conflictCount,
    required this.entries,
  });

  final int contractVersion;
  final String interfaceName;
  final int mtu;
  final bool healthy;
  final int conflictCount;
  final List<RouteEntryResponse> entries;

  factory RoutesResponse.fromJson(JsonMap json) {
    final version = _contractVersion(json);
    _require(json, const [
      'interface',
      'mtu',
      'healthy',
      'conflictCount',
      'entries',
    ], 'RoutesResponse');
    final entries = json['entries'];
    if (entries is! List) {
      throw const FormatException('RoutesResponse.entries must be an array');
    }
    return RoutesResponse(
      contractVersion: version,
      interfaceName: _requiredString(
        json['interface'],
        'RoutesResponse.interface',
      ),
      mtu: _requiredInt(json['mtu'], 'RoutesResponse.mtu'),
      healthy: _requiredBool(json['healthy'], 'RoutesResponse.healthy'),
      conflictCount: _requiredInt(
        json['conflictCount'],
        'RoutesResponse.conflictCount',
      ),
      entries: [
        for (final item in entries)
          RouteEntryResponse.fromJson(
            _requiredMap(item, 'RoutesResponse.entries'),
          ),
      ],
    );
  }

  JsonMap toJson() => {
    'contractVersion': contractVersion,
    'interface': interfaceName,
    'mtu': mtu,
    'healthy': healthy,
    'conflictCount': conflictCount,
    'entries': [
      for (final entry in entries)
        {
          'cidr': entry.cidr,
          'expected_interface': entry.expectedInterface,
          'actual_interface': entry.actualInterface,
          'state': entry.state,
          'owned': entry.owned,
        },
    ],
  };
}

class RouteRepairResponse {
  const RouteRepairResponse({
    required this.contractVersion,
    required this.cidr,
    required this.changed,
    required this.attempted,
    required this.before,
    required this.after,
    required this.reason,
    required this.restartedDaemon,
  });

  final int contractVersion;
  final String cidr;
  final bool changed;
  final bool attempted;
  final String before;
  final String after;
  final String reason;
  final bool restartedDaemon;

  factory RouteRepairResponse.fromJson(JsonMap json) {
    final version = _contractVersion(json);
    _require(json, const [
      'cidr',
      'changed',
      'attempted',
      'before',
      'after',
      'reason',
      'restartedDaemon',
    ], 'RouteRepairResponse');
    return RouteRepairResponse(
      contractVersion: version,
      cidr: _requiredString(json['cidr'], 'RouteRepairResponse.cidr'),
      changed: _requiredBool(json['changed'], 'RouteRepairResponse.changed'),
      attempted: _requiredBool(
        json['attempted'],
        'RouteRepairResponse.attempted',
      ),
      before: _requiredString(json['before'], 'RouteRepairResponse.before'),
      after: _requiredString(json['after'], 'RouteRepairResponse.after'),
      reason: _requiredString(json['reason'], 'RouteRepairResponse.reason'),
      restartedDaemon: _requiredBool(
        json['restartedDaemon'],
        'RouteRepairResponse.restartedDaemon',
      ),
    );
  }

  JsonMap toJson() => {
    'contractVersion': contractVersion,
    'cidr': cidr,
    'changed': changed,
    'attempted': attempted,
    'before': before,
    'after': after,
    'reason': reason,
    'restartedDaemon': restartedDaemon,
  };
}

class PeersPageResponse {
  const PeersPageResponse({
    required this.contractVersion,
    required this.peers,
    required this.total,
    required this.cursor,
    required this.nextCursor,
  });

  final int contractVersion;
  final List<PeerSnapshot> peers;
  final int total;
  final String? cursor;
  final String? nextCursor;

  factory PeersPageResponse.fromJson(JsonMap json) {
    final version = _contractVersion(json);
    _require(json, const [
      'peers',
      'total',
      'cursor',
      'next_cursor',
    ], 'PeersPageResponse');
    final peers = json['peers'];
    if (peers is! List) {
      throw const FormatException('PeersPageResponse.peers must be an array');
    }
    return PeersPageResponse(
      contractVersion: version,
      peers: [
        for (final item in peers)
          PeerSnapshot.fromJson(_requiredMap(item, 'PeersPageResponse.peers')),
      ],
      total: _requiredInt(json['total'], 'PeersPageResponse.total'),
      cursor: _nullableString(json['cursor']),
      nextCursor: _nullableString(json['next_cursor']),
    );
  }
}

class PermissionPreflightResponse {
  const PermissionPreflightResponse({
    required this.contractVersion,
    required this.state,
    required this.canCreateTun,
    required this.canModifyRoutes,
    required this.elevationSupported,
    required this.reasonCode,
    required this.message,
  });

  final int contractVersion;
  final String state;
  final bool? canCreateTun;
  final bool? canModifyRoutes;
  final bool elevationSupported;
  final String reasonCode;
  final String message;

  factory PermissionPreflightResponse.fromJson(JsonMap json) {
    final version = _contractVersion(json);
    _require(json, const [
      'state',
      'canCreateTun',
      'canModifyRoutes',
      'elevationSupported',
      'reasonCode',
      'message',
    ], 'PermissionPreflightResponse');
    return PermissionPreflightResponse(
      contractVersion: version,
      state: _requiredString(
        json['state'],
        'PermissionPreflightResponse.state',
      ),
      canCreateTun: _nullableBool(json['canCreateTun']),
      canModifyRoutes: _nullableBool(json['canModifyRoutes']),
      elevationSupported: _requiredBool(
        json['elevationSupported'],
        'PermissionPreflightResponse.elevationSupported',
      ),
      reasonCode: _requiredString(
        json['reasonCode'],
        'PermissionPreflightResponse.reasonCode',
      ),
      message: _requiredString(
        json['message'],
        'PermissionPreflightResponse.message',
      ),
    );
  }
}

int _requiredInt(dynamic value, String field) {
  if (value is num && value.toInt() == value) return value.toInt();
  throw FormatException('$field must be an integer');
}

bool _requiredBool(dynamic value, String field) {
  if (value is bool) return value;
  throw FormatException('$field must be a boolean');
}

bool? _nullableBool(dynamic value) {
  if (value == null) return null;
  if (value is bool) return value;
  throw const FormatException('nullable boolean field has an invalid value');
}

String _requiredString(dynamic value, String field) {
  if (value is String) return value;
  throw FormatException('$field must be a string');
}

JsonMap _requiredMap(dynamic value, String field) {
  if (value is Map<String, dynamic>) return value;
  throw FormatException('$field must contain JSON objects');
}
