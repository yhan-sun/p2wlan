import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../models/diagnostics_models.dart';
import 'room_api.dart';

bool isRoomNetwork(String id) => RegExp(r'^room-[a-f0-9]{32}$').hasMatch(id);

String roomProfileId(AppSettings settings) {
  if (!isRoomNetwork(settings.networkId)) {
    throw const RoomException('房间网络标识无效');
  }
  return managedNetworkProfileId(settings);
}

String managedNetworkProfileId(AppSettings settings) {
  final token = settings.authToken.split('.');
  try {
    if (token.length != 3) throw const FormatException();
    final payload = jsonDecode(
      utf8.decode(base64Url.decode(base64Url.normalize(token[1]))),
    );
    final account = payload is Map ? payload['user_id'] : null;
    if (account is! String || account.isEmpty || account.length > 256) {
      throw const FormatException();
    }
    return sha256
        .convert(
          utf8.encode(
            jsonEncode([
              roomControlServer(settings.controlServer),
              account,
              settings.networkId,
            ]),
          ),
        )
        .toString();
  } catch (_) {
    throw const RoomException('无法确认当前账号，请重新登录后连接');
  }
}

File networkConfigFile(File legacy, AppSettings settings) {
  if (settings.authToken.trim().isEmpty) return legacy;
  final scope = isRoomNetwork(settings.networkId) ? 'rooms' : 'accounts';
  return File(
    [
      legacy.parent.path,
      scope,
      managedNetworkProfileId(settings),
      'p2wlan-config.json',
    ].join(Platform.pathSeparator),
  );
}

String accountSessionKey(AppSettings settings) =>
    jsonEncode([settings.controlServer, settings.authToken]);

AppSettings selectRoomSettings(AppSettings current, FriendRoom room) {
  if (!isRoomNetwork(room.id) || !validRoomCidr(room.cidr)) {
    throw const RoomException('房间网络信息无效');
  }
  final inRoom = isRoomNetwork(current.networkId);
  return current.copyWith(
    personalNetworkId: inRoom ? current.personalNetworkId : current.networkId,
    personalOverlayCidr: inRoom
        ? current.personalOverlayCidr
        : current.overlayCidr,
    personalVirtualIp: inRoom ? current.personalVirtualIp : current.virtualIp,
    networkId: room.id,
    overlayCidr: room.cidr,
    virtualIp: '',
  );
}

AppSettings personalNetworkSettings(AppSettings current) {
  return current.copyWith(
    networkId: isRoomNetwork(current.personalNetworkId)
        ? defaultNetworkId
        : current.personalNetworkId,
    overlayCidr: current.personalOverlayCidr,
    virtualIp: current.personalVirtualIp,
  );
}
