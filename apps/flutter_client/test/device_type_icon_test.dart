import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/shared/widgets/device_type_icon.dart';

void main() {
  final fixture = jsonDecode(
    File('test/fixtures/status_connected.json').readAsStringSync(),
  ) as Map<String, dynamic>;
  final peers = fixture['peers'] as List<dynamic>;

  PeerSnapshot peer({String? name, String? platform}) {
    final raw = Map<String, dynamic>.from(peers.first as Map);
    if (name != null) raw['device_name'] = name;
    if (platform != null) raw['platform'] = platform;
    return PeerSnapshot.fromJson(raw);
  }

  test('prefers an explicit platform and falls back to phone name markers', () {
    final android = peer(platform: 'android');
    expect(android.platform, 'android');
    expect(peerDeviceKind(android), PeerDeviceKind.phone);
    expect(peerDeviceIcon(android), Icons.smartphone_rounded);

    final onePlus = peer(name: 'OnePlus PKX110');
    expect(peerDeviceKind(onePlus), PeerDeviceKind.phone);
    expect(peerDeviceIcon(onePlus), Icons.smartphone_rounded);
  });

  test('unknown and desktop platforms use the computer glyph', () {
    expect(peerDeviceIcon(peer(platform: 'macos')), Icons.laptop_mac_rounded);
    expect(peerDeviceIcon(peer(name: 'Office NAS')), Icons.laptop_mac_rounded);
  });
}
