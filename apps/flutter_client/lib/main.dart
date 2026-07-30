import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import 'app/p2wlan_app.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final enableFlutterTray = _enableFlutterTray;
  if (_supportsDesktopHost) {
    await windowManager.ensureInitialized();
    if (enableFlutterTray) {
      await windowManager.setPreventClose(true);
    }
  }
  runApp(P2WlanApp(enableDesktopTray: enableFlutterTray));
}

bool get _supportsDesktopHost {
  return !kIsWeb &&
      (Platform.isMacOS || Platform.isLinux || Platform.isWindows);
}

bool get _enableFlutterTray {
  if (!_supportsDesktopHost) return false;
  final value = Platform.environment['P2WLAN_ENABLE_FLUTTER_TRAY']
      ?.trim()
      .toLowerCase();
  if (value == null || value.isEmpty) return true;
  return value != '0' && value != 'false' && value != 'no';
}
