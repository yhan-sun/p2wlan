import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import '../../core/models/diagnostics_models.dart';

/// The small leading glyph used by both Home's preview and the Devices list.
///
/// The daemon did not include a platform in older status snapshots, so this
/// intentionally prefers an explicit platform and only then uses recognizable
/// product-name markers. Unknown names remain computers rather than pretending
/// that the heuristic knows more than it does.
enum PeerDeviceKind { computer, phone }

PeerDeviceKind peerDeviceKind(PeerSnapshot peer) {
  final platform = peer.platform.trim().toLowerCase();
  if (_mobilePlatformMarkers.any(platform.contains)) {
    return PeerDeviceKind.phone;
  }
  if (_computerPlatformMarkers.any(platform.contains)) {
    return PeerDeviceKind.computer;
  }

  final name = peer.displayName.trim().toLowerCase();
  if (_mobileNameMarkers.any(name.contains)) return PeerDeviceKind.phone;
  return PeerDeviceKind.computer;
}

IconData peerDeviceIcon(PeerSnapshot peer) {
  return switch (peerDeviceKind(peer)) {
    PeerDeviceKind.phone => Icons.smartphone_rounded,
    PeerDeviceKind.computer => Icons.laptop_mac_rounded,
  };
}

IconData localDeviceIcon() {
  return switch (defaultTargetPlatform) {
    TargetPlatform.android ||
    TargetPlatform.iOS ||
    TargetPlatform.fuchsia => Icons.smartphone_rounded,
    _ => Icons.laptop_mac_rounded,
  };
}

const _mobilePlatformMarkers = <String>{
  'android',
  'ios',
  'iphone',
  'ipad',
  'mobile',
  'phone',
};

const _computerPlatformMarkers = <String>{
  'windows',
  'macos',
  'mac',
  'linux',
  'desktop',
  'computer',
};

const _mobileNameMarkers = <String>{
  'android',
  'iphone',
  'ipad',
  'phone',
  'mobile',
  'oneplus',
  'xiaomi',
  'redmi',
  'huawei',
  'honor',
  'oppo',
  'vivo',
  'pixel',
  'samsung',
  'galaxy',
  'poco',
  '小米',
  '红米',
  '华为',
  '荣耀',
  '手机',
};
