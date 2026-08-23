import 'dart:io';

import 'package:flutter/services.dart';

/// Small Android-only bridge for values that Flutter cannot resolve from its
/// own process environment. The application support directory is deliberately
/// supplied by Android's Context so it survives app updates and is shared with
/// the native VPN service's existing `filesDir/p2wlan` configuration area.
const _androidPlatformChannel = MethodChannel('p2wlan/platform');

String? _cachedApplicationSupportDirectoryPath;

/// The native VPN service and Flutter use the same private directory on
/// Android.  Keep the resolved value available to synchronous display-only
/// getters after the asynchronous bridge has been initialized by SettingsStore.
String? get cachedApplicationSupportDirectoryPath =>
    _cachedApplicationSupportDirectoryPath;

Future<Directory?> resolveApplicationSupportDirectory() async {
  if (!Platform.isAndroid) return null;

  final path = await _androidPlatformChannel.invokeMethod<String>(
    'applicationSupportDirectory',
  );
  final trimmed = path?.trim() ?? '';
  if (trimmed.isEmpty) {
    throw StateError('Android application support directory is unavailable.');
  }
  _cachedApplicationSupportDirectoryPath = trimmed;
  return Directory(trimmed);
}

Future<String?> resolveAndroidDeviceName() async {
  if (!Platform.isAndroid) return null;
  try {
    final value = await _androidPlatformChannel.invokeMethod<String>(
      'deviceName',
    );
    final trimmed = value?.trim() ?? '';
    return trimmed.isEmpty ? null : trimmed;
  } catch (_) {
    // Device naming is a convenience. A bridge failure must not prevent an
    // existing configuration from loading or a user from logging in.
    return null;
  }
}
