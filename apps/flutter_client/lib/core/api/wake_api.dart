import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../rooms/room_api.dart';

class WakeAgent {
  const WakeAgent(this.id, this.name);
  final String id;
  final String name;
}

enum WakeAvailability { online, ready, missingMac, missingAgent }

class WakeStatus {
  const WakeStatus({
    required this.online,
    required this.hasMac,
    required this.agents,
    this.preferredAgentId,
  });

  final bool online;
  final bool hasMac;
  final List<WakeAgent> agents;
  final String? preferredAgentId;

  WakeAvailability get availability => online
      ? WakeAvailability.online
      : !hasMac
      ? WakeAvailability.missingMac
      : agents.isEmpty
      ? WakeAvailability.missingAgent
      : WakeAvailability.ready;
}

enum WakeJobState { queued, claimed, sent, failed, expired }

class WakeJob {
  const WakeJob(this.id, this.state, this.reason, {this.agentId});

  factory WakeJob.fromJson(Map<String, dynamic> json) {
    final id = _string(json['id']);
    final state = WakeJobState.values.asNameMap()[json['state']];
    if (id.isEmpty || state == null) {
      throw const WakeApiException('invalid_response');
    }
    final agent = _string(json['agent_device_id']);
    return WakeJob(
      id,
      state,
      _string(json['reason']),
      agentId: agent.isEmpty ? null : agent,
    );
  }

  final String id;
  final WakeJobState state;
  final String reason;
  final String? agentId;
}

class WakeTarget {
  const WakeTarget.device(this.id, this.name) : manual = false, enabled = true;
  const WakeTarget.manual(this.id, this.name, this.enabled) : manual = true;

  final String id;
  final String name;
  final bool manual;
  final bool enabled;

  List<String> get wakePath => [
    manual ? 'wake-targets' : 'devices',
    id,
    'wake',
  ];
}

class WakeApiException implements Exception {
  const WakeApiException(this.code, {this.agents});

  final String code;
  final List<WakeAgent>? agents;

  @override
  String toString() => code;
}

/// Authenticated Control API for wake orchestration. Each open surface owns a
/// client so closing it or switching account cancels pending requests.
class WakeApi {
  WakeApi({required this._server, required this._token, HttpClient? client})
    : _client = client ?? HttpClient() {
    _client.connectionTimeout = _timeout;
  }

  static const _timeout = Duration(seconds: 6);
  static const _maxResponseBytes = 1024 * 1024;
  final String _server;
  final String _token;
  final HttpClient _client;

  Future<WakeStatus> status(WakeTarget target) async {
    final json = await _request('GET', target.wakePath);
    if (json['online'] is! bool || json['has_mac'] is! bool) {
      throw const WakeApiException('invalid_response');
    }
    return WakeStatus(
      online: json['online'] == true,
      hasMac: json['has_mac'] == true,
      agents: _agents(json['agents']),
      preferredAgentId: _string(json['preferred_agent_device_id']),
    );
  }

  Future<WakeJob> trigger(WakeTarget target, {String? agentId}) async =>
      WakeJob.fromJson(
        await _request(
          'POST',
          target.wakePath,
          payload: {'agent_device_id': ?agentId},
        ),
      );

  Future<WakeJob> job(String id) async =>
      WakeJob.fromJson(await _request('GET', ['wake', 'jobs', id]));

  Future<List<WakeTarget>> devices(String networkId) async {
    final json = await _request(
      'GET',
      ['nodes'],
      query: {'network_id': networkId},
    );
    return [
      for (final row in _objects(json['nodes']))
        if (_string(row['id']).isNotEmpty)
          WakeTarget.device(_string(row['id']), _string(row['device_name'])),
    ];
  }

  Future<List<WakeTarget>> manualTargets(String networkId) async {
    final json = await _request('GET', ['networks', networkId, 'wake-targets']);
    return [
      for (final row in _objects(json['targets']))
        if (_string(row['id']).isNotEmpty)
          WakeTarget.manual(
            _string(row['id']),
            _string(row['name']),
            row['enabled'] != false,
          ),
    ];
  }

  Future<void> saveManualTarget(
    String networkId, {
    String? targetId,
    required String name,
    String? mac,
    bool? enabled,
  }) async {
    await _request(
      targetId == null ? 'POST' : 'PATCH',
      targetId == null
          ? ['networks', networkId, 'wake-targets']
          : ['wake-targets', targetId],
      payload: {'name': name, 'mac': ?mac, 'enabled': ?enabled},
    );
  }

  Future<void> removeManualTarget(String id) async {
    await _request('DELETE', ['wake-targets', id]);
  }

  Future<Map<String, dynamic>> _request(
    String method,
    List<String> path, {
    Map<String, Object?>? payload,
    Map<String, String>? query,
  }) async {
    if (_token.trim().isEmpty) throw const WakeApiException('auth_expired');
    final Uri server;
    try {
      server = Uri.parse(roomControlServer(_server));
    } on RoomException {
      throw const WakeApiException('unreachable');
    }
    if (server.scheme != 'https') {
      throw const WakeApiException('https_required');
    }
    final uri = server.replace(
      pathSegments: [
        ...server.pathSegments.where((segment) => segment.isNotEmpty),
        'api',
        'v1',
        ...path,
      ],
      queryParameters: query,
    );
    HttpClientRequest? request;
    var timedOut = false;
    final timer = Timer(_timeout, () {
      timedOut = true;
      request?.abort();
    });
    try {
      return await (() async {
        final active = request = await _client.openUrl(method, uri);
        if (timedOut) {
          active.abort();
          throw const WakeApiException('unreachable');
        }
        active.followRedirects = false;
        active.headers.set(
          HttpHeaders.authorizationHeader,
          'Bearer ${_token.trim()}',
        );
        active.headers.set(HttpHeaders.acceptHeader, 'application/json');
        if (payload != null) {
          active.headers.contentType = ContentType.json;
          active.write(jsonEncode(payload));
        }
        final response = await active.close();
        final body = <int>[];
        await for (final chunk in response) {
          if (body.length + chunk.length > _maxResponseBytes) {
            active.abort();
            throw const WakeApiException('invalid_response');
          }
          body.addAll(chunk);
        }
        final successful =
            response.statusCode >= 200 && response.statusCode < 300;
        Map<String, dynamic> json = const {};
        try {
          final raw = utf8.decode(body).trim();
          if (raw.isNotEmpty) {
            final decoded = jsonDecode(raw);
            if (decoded is! Map<String, dynamic>) throw const FormatException();
            json = decoded;
          }
        } on FormatException {
          if (successful) throw const WakeApiException('invalid_response');
        }
        if (successful) return json;
        final candidateCode = _string(json['error_code']);
        final rawCode = RegExp(r'^[a-z_]{1,64}$').hasMatch(candidateCode)
            ? candidateCode
            : '';
        final code = switch (response.statusCode) {
          401 => 'auth_expired',
          404 when rawCode.isEmpty => 'unsupported',
          _ when rawCode.isNotEmpty => rawCode,
          _ => 'request_failed',
        };
        throw WakeApiException(
          code,
          agents: json.containsKey('agents') ? _agents(json['agents']) : null,
        );
      })().timeout(_timeout);
    } on WakeApiException {
      rethrow;
    } catch (_) {
      throw const WakeApiException('unreachable');
    } finally {
      timer.cancel();
    }
  }

  void close() => _client.close(force: true);
}

String _string(Object? value) => value is String ? value : '';

Iterable<Map<String, dynamic>> _objects(Object? value) =>
    value is List ? value.whereType<Map<String, dynamic>>() : const [];

List<WakeAgent> _agents(Object? value) => [
  for (final row in _objects(value))
    if (_string(row['id']).isNotEmpty)
      WakeAgent(_string(row['id']), _string(row['name'])),
];
