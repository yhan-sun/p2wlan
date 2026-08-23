import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import 'app/desktop_window_operations.dart';
import 'app/p2wlan_app.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final enableFlutterTray = _enableFlutterTray;
  final autoStartDaemon = _autoStartDaemon;
  if (_supportsDesktopHost) {
    await windowManager.ensureInitialized();
    await _configureDesktopWindowChrome();
  }
  runApp(
    P2WlanApp(
      autoStartDaemon: autoStartDaemon,
      enableDesktopTray: enableFlutterTray,
      enableDesktopTaskbarStatus: _supportsDesktopHost && !enableFlutterTray,
    ),
  );
}

Future<void> _configureDesktopWindowChrome() async {
  await DesktopWindowOperations.run(() async {
    // Windows already owns a normal taskbar entry for the Flutter window.
    // window_manager's Windows setSkipTaskbar implementation requires an
    // internal ITaskbarList3 that is only created by its optional
    // waitUntilReadyToShow flow. Do not enter that fragile path: hiding the
    // native window already removes it from the taskbar when needed.
    if (!Platform.isWindows) {
      await windowManager.setSkipTaskbar(false);
    }
    await windowManager.setTitle('P2WLAN');

    if (Platform.isMacOS) {
      await windowManager.setTitleBarStyle(
        TitleBarStyle.hidden,
        windowButtonVisibility: true,
      );
    }
    // Windows deliberately keeps the runner's native frame. This preserves
    // the system minimize/maximize/close buttons and avoids changing window
    // styles while a virtual or remote display is being initialized.
  });
}

bool get _supportsDesktopHost {
  return !kIsWeb &&
      (Platform.isMacOS || Platform.isLinux || Platform.isWindows);
}

bool get _enableFlutterTray {
  if (!_supportsDesktopHost) return false;
  return enableFlutterTrayForEnvironment(Platform.environment);
}

bool get _autoStartDaemon {
  if (!_supportsDesktopHost) return false;
  return autoStartDaemonForEnvironment(Platform.environment);
}

@visibleForTesting
bool autoStartDaemonForEnvironment(Map<String, String> environment) {
  final value = environment['P2WLAN_AUTO_START_DAEMON']?.trim().toLowerCase();
  // Daemon launch may request elevation and alter system routes. It is never
  // implicit in release builds: development launchers must opt in explicitly.
  return value == '1' || value == 'true' || value == 'yes' || value == 'on';
}

@visibleForTesting
bool enableFlutterTrayForEnvironment(Map<String, String> environment) {
  final value = environment['P2WLAN_ENABLE_FLUTTER_TRAY']?.trim().toLowerCase();
  // The Flutter tray is the tray implementation that is actually bundled
  // with the desktop release app. The standalone Rust tray remains useful for
  // low-memory/headless experiments, but it is not launched by the packaged
  // macOS/Windows/Linux client. Keep the release path visible by default and
  // allow developers to opt out explicitly when running the native tray.
  if (value == null || value.isEmpty) return true;
  return value != '0' && value != 'false' && value != 'no' && value != 'off';
}
