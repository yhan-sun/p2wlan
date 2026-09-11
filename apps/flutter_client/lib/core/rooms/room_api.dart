import 'dart:async';
import 'dart:convert';
import 'dart:io';

class RoomException implements Exception {
  const RoomException(this.message, {this.code});
  final String? code;
  final String message;
  @override
  String toString() => message;
}

class RoomConnectionStopped extends RoomException {
  const RoomConnectionStopped(super.message);
}

String roomControlServer(String value) {
  final uri = Uri.tryParse(value.trim());
  if (uri == null ||
      !const ['http', 'https'].contains(uri.scheme) ||
      uri.host.isEmpty ||
      uri.userInfo.isNotEmpty ||
      uri.hasQuery ||
      uri.hasFragment) {
    throw const RoomException('控制服务器地址无效');
  }
  return uri.replace(path: uri.path.replaceAll(RegExp(r'/+$'), '')).toString();
}

class FriendRoom {
  const FriendRoom({
    required this.id,
    required this.code,
    required this.name,
    required this.cidr,
    required this.ownerId,
    required this.role,
    required this.locked,
    this.ownerUsername = '',
    this.deviceControls = false,
    this.memberCount,
    this.onlineMemberCount,
    this.ownerDeviceIps = const [],
  });
  factory FriendRoom.fromJson(Map<String, dynamic> json) {
    final id = json['id'] as String? ?? '';
    final code = json['room_code'] as String? ?? '';
    final cidr = json['cidr'] as String? ?? '';
    if (!RegExp(r'^room-[a-f0-9]{32}$').hasMatch(id) ||
        !RegExp(r'^[0-9]{8}$').hasMatch(code) ||
        !validRoomCidr(cidr)) {
      throw const RoomException('服务器返回了无效的房间信息，请升级服务器');
    }
    return FriendRoom(
      id: id,
      code: code,
      name: json['name'] as String? ?? '',
      cidr: cidr,
      ownerId: json['owner_id'] as String? ?? '',
      role: json['role'] as String? ?? 'member',
      locked: json['join_locked'] == true,
      ownerUsername: json['owner_username'] as String? ?? '',
      deviceControls: json['device_controls_version'] == 1,
      memberCount: (json['member_count'] as num?)?.toInt(),
      onlineMemberCount: (json['online_member_count'] as num?)?.toInt(),
      ownerDeviceIps: (json['owner_device_ips'] as List? ?? [])
          .whereType<String>()
          .toList(),
    );
  }
  final String id;
  final String code;
  final String name;
  final String cidr;
  final String ownerId;
  final String role;
  final bool locked;
  final String ownerUsername;
  final bool deviceControls;
  final int? memberCount;
  final int? onlineMemberCount;
  final List<String> ownerDeviceIps;
  bool get isOwner => role == 'owner';
}

bool validRoomCidr(String cidr) {
  final parts = cidr.split('/');
  if (parts.length != 2 || parts[1] != '24') return false;
  final address = InternetAddress.tryParse(parts[0]);
  if (address == null || address.type != InternetAddressType.IPv4) return false;
  final bytes = address.rawAddress;
  return bytes[0] == 10 &&
      bytes[1] == 21 &&
      bytes[3] == 0 &&
      '${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}' == parts[0];
}

bool validRoomIp(String ip, String cidr) {
  if (!validRoomCidr(cidr)) return false;
  final address = InternetAddress.tryParse(ip);
  if (address == null ||
      address.type != InternetAddressType.IPv4 ||
      '${address.rawAddress[0]}.${address.rawAddress[1]}.${address.rawAddress[2]}.${address.rawAddress[3]}' !=
          ip) {
    return false;
  }
  final bytes = address.rawAddress;
  final subnet = InternetAddress(cidr.split('/').first).rawAddress;
  return bytes[0] == subnet[0] &&
      bytes[1] == subnet[1] &&
      bytes[2] == subnet[2] &&
      bytes[3] > 0 &&
      bytes[3] < 255;
}

class RoomInvitation {
  const RoomInvitation(this.server, this.code, this.token);
  factory RoomInvitation.parse(String text, String currentServer) {
    if (text.length > 4096) throw const RoomException('邀请链接过长');
    final uri = Uri.tryParse(text.trim());
    if (uri == null ||
        uri.scheme != 'p2wlan' ||
        uri.host != 'join' ||
        uri.userInfo.isNotEmpty ||
        uri.hasPort ||
        uri.path.isNotEmpty) {
      throw const RoomException('请输入完整的 P2WLAN 房间邀请链接');
    }
    final query = uri.queryParametersAll;
    final fragment = Uri.splitQueryString(uri.fragment);
    if (query.length != 2 ||
        query['server']?.length != 1 ||
        query['room']?.length != 1 ||
        fragment.length != 1 ||
        !fragment.containsKey('invite') ||
        uri.fragment.split('&').length != 1) {
      throw const RoomException('邀请链接格式无效');
    }
    final server = roomControlServer(query['server']!.single);
    if (server != roomControlServer(currentServer)) {
      throw const RoomException('邀请来自其他控制服务器。请先在设置中确认并登录该服务器，当前登录凭证不会被发送过去。');
    }
    final code = query['room']!.single;
    final token = fragment['invite']!;
    if (!RegExp(r'^[0-9]{8}$').hasMatch(code) ||
        !RegExp(r'^[a-f0-9]{64}$').hasMatch(token)) {
      throw const RoomException('邀请链接中的房间号或凭证无效');
    }
    return RoomInvitation(server, code, token);
  }
  final String server;
  final String code;
  final String token;
  Uri toUri() => Uri(
    scheme: 'p2wlan',
    host: 'join',
    queryParameters: {'server': roomControlServer(server), 'room': code},
    fragment: Uri(queryParameters: {'invite': token}).query,
  );
  @override
  String toString() => 'RoomInvitation(room: $code, credential: [REDACTED])';
}

class RoomRoster {
  RoomRoster.fromJson(Map<String, dynamic> json)
    : room = FriendRoom.fromJson(_object(json['room'])),
      members = _objects(json['members']),
      devices = _objects(json['devices']),
      deviceApprovalRequired = json['device_approval_required'] == true,
      deviceAccess = _objects(json['device_access']),
      bannedUserIds = (json['banned_user_ids'] as List? ?? const [])
          .whereType<String>()
          .toList(growable: false);
  final FriendRoom room;
  final List<Map<String, dynamic>> members;
  final List<Map<String, dynamic>> devices;
  final List<String> bannedUserIds;
  final bool deviceApprovalRequired;
  final List<Map<String, dynamic>> deviceAccess;
}

Map<String, dynamic> _object(Object? value) {
  if (value is! Map<String, dynamic>) {
    throw const RoomException('服务器响应格式无效');
  }
  return value;
}

List<Map<String, dynamic>> _objects(Object? value) =>
    (value as List? ?? const []).map(_object).toList(growable: false);

class RoomApi {
  RoomApi({
    required String server,
    required this.token,
    HttpClient? client,
    this.requestTimeout = const Duration(seconds: 12),
  }) : server = roomControlServer(server),
       _client = client ?? HttpClient() {
    _client.connectionTimeout = const Duration(seconds: 8);
  }
  final String server;
  final String token;
  final HttpClient _client;
  final Duration requestTimeout;
  String userId = '';

  Future<Map<String, dynamic>> request(
    String method,
    List<String> segments, [
    Map<String, dynamic>? payload,
  ]) async {
    if (token.trim().isEmpty) throw const RoomException('请先登录');
    HttpClientRequest? active;
    var expired = false;
    final timer = Timer(requestTimeout, () {
      expired = true;
      active?.abort(const RoomException('房间服务请求超时，请刷新后确认操作结果'));
    });
    try {
      return await _request(method, segments, payload, (request) {
        active = request;
        if (expired) {
          request.abort();
          throw TimeoutException('room request expired');
        }
      }).timeout(requestTimeout);
    } on RoomException {
      rethrow;
    } on TimeoutException {
      throw const RoomException('房间服务请求超时，请刷新后确认操作结果');
    } catch (_) {
      throw const RoomException('无法访问房间服务，请检查网络和服务器版本');
    } finally {
      timer.cancel();
    }
  }

  Future<Map<String, dynamic>> _request(
    String method,
    List<String> segments,
    Map<String, dynamic>? payload,
    void Function(HttpClientRequest) onOpened,
  ) async {
    final path = segments.map(Uri.encodeComponent).join('/');
    final req = await _client.openUrl(
      method,
      Uri.parse('$server/api/v1/rooms${path.isEmpty ? '' : '/$path'}'),
    );
    onOpened(req);
    req.followRedirects = false;
    req.headers.set(HttpHeaders.authorizationHeader, 'Bearer $token');
    req.headers.set(HttpHeaders.acceptHeader, 'application/json');
    if (payload != null) {
      req.headers.contentType = ContentType.json;
      req.write(jsonEncode(payload));
    }
    final response = await req.close();
    final bytes = <int>[];
    await for (final chunk in response) {
      if (bytes.length + chunk.length > 1024 * 1024) {
        req.abort();
        throw const RoomException('房间服务响应超过大小限制');
      }
      bytes.addAll(chunk);
    }
    Map<String, dynamic> json = const {};
    try {
      json = _object(jsonDecode(utf8.decode(bytes)));
    } catch (_) {
      if (response.statusCode >= 200 && response.statusCode < 300) rethrow;
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw RoomException(
        switch (json['error_code']) {
          'room_device_blocked' => '此设备已被禁止连接该房间，请解除限制后重试',
          'room_device_pending' => '此设备正在等待房主审批，请批准后在本机重新连接',
          'room_device_paused' => '此设备已被远程断开，请在本机手动连接',
          'room_exists' => '每个账号最多创建一个房间',
          'room_join' => '无法加入：房间号、密码或邀请无效，房间已锁定，或账号已被封禁',
          'room_access' => '无权操作该房间，或你已不再是成员',
          'room_invalid' => '输入无效，请检查名称、密码、IP 或邀请设置',
          'room_ip_conflict' => '该 IP 无法分配，请检查网段或选择未占用的地址',
          'room_device_state_conflict' => '此设备状态已变化，申请可能已被处理，请查看最新状态',
          'room_invite_limit' => '有效邀请已达上限，请先撤销不再使用的邀请',
          'room_conflict' => '操作与当前房间状态冲突，请刷新后重试',
          'room_exhausted' => '服务器没有可用子网或房间 IP，请联系管理员',
          'room_rate_limit' => '加入尝试过于频繁，请一分钟后重试',
          _ when response.statusCode == 401 => '登录状态已失效，请重新登录',
          _ when response.statusCode == 404 || response.statusCode == 426 =>
            '当前服务器不支持好友房间，请升级服务器',
          _ => '房间操作失败，请刷新后确认状态',
        },
        code:
            json['error_code'] as String? ??
            (response.statusCode == 401 ? 'auth_expired' : null),
      );
    }
    return json;
  }

  Future<List<FriendRoom>> list() async {
    final json = await request('GET', []);
    if (json['room_protocol_version'] != 1) {
      throw const RoomException('当前服务器不支持此版本的好友房间');
    }
    userId = json['user_id'] as String? ?? '';
    return _objects(json['rooms']).map(FriendRoom.fromJson).toList();
  }

  Future<FriendRoom> create(String name, String password) async =>
      FriendRoom.fromJson(
        _object(
          (await request('POST', [], {
            'name': name,
            'password': password,
          }))['room'],
        ),
      );
  Future<FriendRoom> join(
    String code, {
    String? password,
    String? invitation,
  }) async => FriendRoom.fromJson(
    _object(
      (await request(
        'POST',
        ['join'],
        {'room_code': code, 'password': ?password, 'invite_token': ?invitation},
      ))['room'],
    ),
  );
  Future<RoomRoster> roster(String room) async =>
      RoomRoster.fromJson(await request('GET', [room]));
  void close() => _client.close(force: true);
}
