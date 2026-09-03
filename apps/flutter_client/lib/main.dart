import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import 'app/desktop_tray_controller.dart';
import 'app/desktop_window_operations.dart';
import 'app/p2wlan_app.dart';

Future<void> main() async {
  writeDesktopTrayLifecycleTrace('main.ensureInitialized.begin');
  WidgetsFlutterBinding.ensureInitialized();
  writeDesktopTrayLifecycleTrace('main.ensureInitialized.end');
  final enableFlutterTray = _enableFlutterTray;
  if (_supportsDesktopHost) {
    writeDesktopTrayLifecycleTrace('window.ensureInitialized.begin');
    await windowManager.ensureInitialized();
    writeDesktopTrayLifecycleTrace('window.ensureInitialized.end');
    writeDesktopTrayLifecycleTrace('window.configure.begin');
    await _configureDesktopWindowChrome();
    writeDesktopTrayLifecycleTrace('window.configure.end');
  }
  writeDesktopTrayLifecycleTrace('runApp.begin');
  runApp(
    P2WlanApp(
      enableDesktopTray: enableFlutterTray,
      enableDesktopTaskbarStatus: _supportsDesktopHost && !enableFlutterTray,
    ),
  );
  writeDesktopTrayLifecycleTrace('runApp.end');
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

    if (Platform.isMacOS || Platform.isWindows) {
      await windowManager.setTitleBarStyle(
        TitleBarStyle.hidden,
        // macOS keeps its native traffic lights. Windows renders the
        // caption buttons in Flutter so the whole top edge shares one style.
        windowButtonVisibility: Platform.isMacOS,
      );
    }
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
