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
    await _configureDesktopWindowChrome();
    if (enableFlutterTray) {
      await windowManager.setPreventClose(true);
    }
  }
  runApp(P2WlanApp(enableDesktopTray: enableFlutterTray));
}

Future<void> _configureDesktopWindowChrome() async {
  if (Platform.isMacOS) {
    await windowManager.setTitleBarStyle(
      TitleBarStyle.hidden,
      windowButtonVisibility: true,
    );
  } else if (Platform.isWindows) {
    await windowManager.setTitle('P2WLAN');
    await windowManager.setTitleBarStyle(
      TitleBarStyle.normal,
      windowButtonVisibility: true,
    );
    await windowManager.setResizable(true);
    await windowManager.setMinimizable(true);
    await windowManager.setMaximizable(true);
  }
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
  if (value == null || value.isEmpty) return false;
  return value != '0' && value != 'false' && value != 'no';
}
