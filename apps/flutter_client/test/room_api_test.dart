import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/rooms/room_api.dart';
import 'package:p2wlan_flutter_client/core/rooms/room_profiles.dart';
import 'package:p2wlan_flutter_client/core/security/redactor.dart';

const roomId = 'room-0123456789abcdef0123456789abcdef';
const otherRoomId = 'room-fedcba9876543210fedcba9876543210';
const invitationToken =
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
Map<String, dynamic> roomJson({String role = 'owner'}) => {
  'id': roomId,
  'room_code': '12345678',
  'name': '朋友的房间',
  'cidr': '10.21.1.0/24',
  'owner_id': 'owner',
  'role': role,
  'join_locked': false,
};
String accountToken(String account, {int revision = 1}) =>
    'header.${base64Url.encode(utf8.encode(jsonEncode({'user_id': account, 'revision': revision}))).replaceAll('=', '')}.signature';

void main() {
  test(
    'invitation round trip keeps secret in fragment, not password or logs',
    () {
      final invitation = RoomInvitation(
        'https://control.example',
        '12345678',
        invitationToken,
      );
      final uri = invitation.toUri();
      expect(uri.query, isNot(contains(invitationToken)));
      expect(uri.fragment, contains(invitationToken));
      final parsed = RoomInvitation.parse(
        uri.toString(),
        'https://control.example/',
      );
      expect(parsed.code, '12345678');
      expect(parsed.token, invitationToken);
      expect(parsed.toString(), isNot(contains(invitationToken)));
      expect(redactSensitive(uri.toString()), isNot(contains(invitationToken)));
    },
  );

  test('invitation rejects cross origin, ambiguous and malformed links', () {
    final valid = RoomInvitation(
      'https://control.example',
      '12345678',
      invitationToken,
    ).toUri();
    for (final text in [
      valid
          .replace(
            queryParameters: {
              'server': 'https://evil.example',
              'room': '12345678',
            },
          )
          .toString(),
      valid
          .replace(query: '${valid.query}&server=https%3A%2F%2Fcontrol.example')
          .toString(),
      valid
          .replace(fragment: '${valid.fragment}&invite=$invitationToken')
          .toString(),
      valid.replace(scheme: 'https').toString(),
      valid.replace(userInfo: 'attacker').toString(),
      valid.replace(path: '/redirect').toString(),
      valid.replace(port: 443).toString(),
      valid.replace(fragment: 'invite=short').toString(),
      valid
          .replace(
            queryParameters: {
              'server': 'https://control.example/path',
              'room': '12345678',
            },
          )
          .toString(),
    ]) {
      expect(
        () => RoomInvitation.parse(text, 'https://control.example'),
        throwsA(isA<RoomException>()),
      );
    }
  });

  test(
    'subnet and address validation rejects public, IPv6 and reserved hosts',
    () {
      expect(validRoomCidr('10.21.1.0/24'), isTrue);
      for (final cidr in [
        '20.21.1.0/24',
        '10.20.1.0/24',
        '10.21.1.1/24',
        '10.21.1.0/16',
        '::1/24',
      ]) {
        expect(validRoomCidr(cidr), isFalse);
      }
      for (final ip in [
        '10.21.1.0',
        '10.21.1.255',
        '10.21.2.2',
        '10.20.1.2',
        '010.21.1.2',
        '::1',
      ]) {
        expect(validRoomIp(ip, '10.21.1.0/24'), isFalse);
      }
      expect(validRoomIp('10.21.1.1', '10.21.1.0/24'), isTrue);
      expect(validRoomIp('10.21.1.254', '10.21.1.0/24'), isTrue);
    },
  );

  test(
    'room profile stable across JWT refresh but isolated per user server room',
    () {
      final settings = AppSettings(
        controlServer: 'https://control.example',
        networkId: roomId,
        authToken: accountToken('owner'),
      );
      final profile = roomProfileId(settings);
      expect(profile, matches(RegExp(r'^[a-f0-9]{64}$')));
      expect(
        roomProfileId(
          settings.copyWith(authToken: accountToken('owner', revision: 2)),
        ),
        profile,
      );
      expect(
        roomProfileId(settings.copyWith(authToken: accountToken('member'))),
        isNot(profile),
      );
      expect(
        roomProfileId(
          settings.copyWith(controlServer: 'https://other.example'),
        ),
        isNot(profile),
      );
      expect(
        roomProfileId(settings.copyWith(networkId: otherRoomId)),
        isNot(profile),
      );
      for (final token in ['', 'opaque', 'header.bad.signature', 'a.e30.b']) {
        expect(
          () => roomProfileId(settings.copyWith(authToken: token)),
          throwsA(isA<RoomException>()),
        );
      }
    },
  );

  test(
    'switching several rooms and reloading preserves exact personal network',
    () {
      final personal = AppSettings(
        controlServer: 'https://control.example',
        authToken: accountToken('owner'),
        networkId: 'personal-net',
        overlayCidr: '10.20.0.0/16',
        virtualIp: '10.20.0.8',
        manualMode: true,
      );
      final first = selectRoomSettings(
        personal,
        FriendRoom.fromJson(roomJson()),
      );
      expect(first.virtualIp, isEmpty);
      expect(first.manualMode, isFalse);
      final second = selectRoomSettings(
        first.copyWith(virtualIp: '10.21.1.8'),
        FriendRoom.fromJson({
          ...roomJson(),
          'id': otherRoomId,
          'cidr': '10.21.2.0/24',
        }),
      );
      final restored = personalNetworkSettings(
        AppSettings.fromJson(second.toJson()),
      );
      expect(restored.networkId, personal.networkId);
      expect(restored.virtualIp, personal.virtualIp);
      expect(restored.overlayCidr, personal.overlayCidr);
      expect(restored.manualMode, personal.manualMode);
    },
  );

  group('real HTTP boundary', () {
    late HttpServer server;
    late RoomApi api;
    late String address;
    setUp(() async {
      server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      address = 'http://127.0.0.1:${server.port}';
      api = RoomApi(server: address, token: 'secret-account-token');
    });
    tearDown(() async {
      api.close();
      await server.close(force: true);
    });

    test(
      'conflict errors retain operation-specific codes and safe messages',
      () async {
        var code = 'room_device_state_conflict';
        var status = 409;
        server.listen((request) async {
          await request.drain<void>();
          request.response.statusCode = status;
          request.response.headers.contentType = ContentType.json;
          request.response.write(jsonEncode({'error_code': code}));
          await request.response.close();
        });
        for (final value in [
          'room_device_state_conflict',
          'room_invite_limit',
          'room_conflict',
        ]) {
          code = value;
          await expectLater(
            api.request('POST', [roomId, 'invites']),
            throwsA(
              isA<RoomException>()
                  .having((e) => e.code, 'code', value)
                  .having((e) => e.message, 'message', isNot(contains('IP'))),
            ),
          );
        }
        code = 'room_ip_conflict';
        await expectLater(
          api.request('PATCH', [roomId, 'devices', 'device']),
          throwsA(
            isA<RoomException>().having(
              (e) => e.message,
              'message',
              contains('IP'),
            ),
          ),
        );
        status = 401;
        code = '';
        await expectLater(
          api.list(),
          throwsA(
            isA<RoomException>().having(
              (e) => e.message,
              'message',
              contains('登录'),
            ),
          ),
        );
      },
    );

    test(
      'create and join use only explicit account credentials and body secrets',
      () async {
        final requests = <Map<String, dynamic>>[];
        server.listen((request) async {
          expect(
            request.headers.value(HttpHeaders.authorizationHeader),
            'Bearer secret-account-token',
          );
          expect(request.uri.query, isEmpty);
          requests.add(
            jsonDecode(await utf8.decoder.bind(request).join())
                as Map<String, dynamic>,
          );
          request.response.headers.contentType = ContentType.json;
          request.response.write(jsonEncode({'room': roomJson()}));
          await request.response.close();
        });
        await api.create('room', 'password123');
        await api.join('12345678', invitation: invitationToken);
        expect(requests.first, {'name': 'room', 'password': 'password123'});
        expect(requests.last, {
          'room_code': '12345678',
          'invite_token': invitationToken,
        });
        expect(requests.last, isNot(contains('owner_id')));
      },
    );

    test(
      'redirect cannot forward account or invitation to another origin',
      () async {
        final other = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        var forwarded = 0;
        other.listen((request) async {
          forwarded++;
          await request.response.close();
        });
        addTearDown(() => other.close(force: true));
        server.listen((request) async {
          await request.drain<void>();
          request.response.statusCode = 307;
          request.response.headers.set(
            HttpHeaders.locationHeader,
            'http://127.0.0.1:${other.port}/steal',
          );
          await request.response.close();
        });
        await expectLater(
          api.join('12345678', invitation: invitationToken),
          throwsA(isA<RoomException>()),
        );
        expect(forwarded, 0);
      },
    );

    test(
      'old protocol and arbitrary server error content fail safely',
      () async {
        var calls = 0;
        server.listen((request) async {
          calls++;
          request.response.headers.contentType = ContentType.json;
          if (calls == 1) {
            request.response.write(
              jsonEncode({'rooms': [], 'user_id': 'owner'}),
            );
          } else {
            request.response.statusCode = 403;
            request.response.write(
              jsonEncode({
                'error': 'secret-account-token $invitationToken',
                'error_code': 'room_access',
              }),
            );
          }
          await request.response.close();
        });
        await expectLater(api.list(), throwsA(isA<RoomException>()));
        try {
          await api.roster(roomId);
          fail('expected access failure');
        } on RoomException catch (error) {
          expect(error.toString(), isNot(contains('secret-account-token')));
          expect(error.toString(), isNot(contains(invitationToken)));
        }
      },
    );
  });
}
