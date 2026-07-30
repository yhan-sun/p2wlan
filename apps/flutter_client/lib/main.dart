import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import 'app/p2wlan_app.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  if (_supportsDesktopHost) {
    await windowManager.ensureInitialized();
    await windowManager.setPreventClose(true);
  }
  runApp(P2WlanApp(enableDesktopTray: _supportsDesktopHost));
}

bool get _supportsDesktopHost {
  return !kIsWeb &&
      (Platform.isMacOS || Platform.isLinux || Platform.isWindows);
}
