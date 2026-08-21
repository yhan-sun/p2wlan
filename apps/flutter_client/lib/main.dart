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
  runApp(
    P2WlanApp(
      enableDesktopTray: enableFlutterTray,
      enableDesktopTaskbarStatus: _supportsDesktopHost && !enableFlutterTray,
    ),
  );
}

Future<void> _configureDesktopWindowChrome() async {
  // Keep the main Flutter window discoverable on every desktop platform.
  // The tray controller may temporarily hide it when the user chooses a
  // background/tray close behavior.
  await windowManager.setSkipTaskbar(false);
  await windowManager.setTitle('P2WLAN');

  if (Platform.isMacOS) {
    await windowManager.setTitleBarStyle(
      TitleBarStyle.hidden,
      windowButtonVisibility: true,
    );
  } else if (Platform.isWindows) {
    await windowManager.setTitleBarStyle(
      // Windows keeps its native title bar so the system close, minimize, and
      // maximize controls remain available and behave consistently with other
      // Windows applications. macOS uses the separate hidden-titlebar style
      // above to retain its traffic-light controls and content layout.
      TitleBarStyle.normal,
      windowButtonVisibility: true,
    );
    await windowManager.setResizable(true);
    await windowManager.setMinimizable(true);
    await windowManager.setMaximizable(true);
    await windowManager.setClosable(true);
  }
}

bool get _supportsDesktopHost {
  return !kIsWeb &&
      (Platform.isMacOS || Platform.isLinux || Platform.isWindows);
}

bool get _enableFlutterTray {
  if (!_supportsDesktopHost) return false;
  return enableFlutterTrayForEnvironment(Platform.environment);
}

@visibleForTesting
bool enableFlutterTrayForEnvironment(Map<String, String> environment) {
  final value = environment['P2WLAN_ENABLE_FLUTTER_TRAY']?.trim().toLowerCase();
  if (value == null || value.isEmpty) return false;
  return value != '0' && value != 'false' && value != 'no' && value != 'off';
}
