import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

/// The native Windows caption buttons rendered inside the Flutter client.
///
/// Windows uses a hidden title bar so the app can share the same quiet,
/// client-rendered chrome as macOS. The buttons deliberately use the
/// window_manager package's platform-native glyphs and hover treatment, while
/// keeping the tray controller in charge of the close behavior.
class WindowsWindowControls extends StatefulWidget {
  const WindowsWindowControls({super.key, this.height = 56});

  /// The total width reserved by the three caption buttons.
  static const width = 138.0;

  final double height;

  @override
  State<WindowsWindowControls> createState() => _WindowsWindowControlsState();
}

class _WindowsWindowControlsState extends State<WindowsWindowControls>
    with WindowListener {
  bool _isMaximized = false;

  bool get _isWindows => !kIsWeb && Platform.isWindows;

  @override
  void initState() {
    super.initState();
    if (!_isWindows) return;
    windowManager.addListener(this);
    WidgetsBinding.instance.addPostFrameCallback((_) => _syncMaximized());
  }

  @override
  void dispose() {
    if (_isWindows) {
      windowManager.removeListener(this);
    }
    super.dispose();
  }

  Future<void> _syncMaximized() async {
    try {
      final maximized = await windowManager.isMaximized();
      if (mounted && maximized != _isMaximized) {
        setState(() => _isMaximized = maximized);
      }
    } catch (_) {
      // The controls remain usable even if the native window is not ready
      // during a very early test or startup frame.
    }
  }

  void _toggleMaximize() {
    unawaited(
      (_isMaximized ? windowManager.unmaximize() : windowManager.maximize())
          .then((_) => _syncMaximized()),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (!_isWindows) return const SizedBox.shrink();

    final brightness = Theme.of(context).brightness;
    return SizedBox(
      key: const Key('windows-window-controls'),
      height: widget.height,
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          WindowCaptionButton.minimize(
            brightness: brightness,
            onPressed: () => unawaited(windowManager.minimize()),
          ),
          _isMaximized
              ? WindowCaptionButton.unmaximize(
                  brightness: brightness,
                  onPressed: _toggleMaximize,
                )
              : WindowCaptionButton.maximize(
                  brightness: brightness,
                  onPressed: _toggleMaximize,
                ),
          WindowCaptionButton.close(
            brightness: brightness,
            onPressed: () => unawaited(windowManager.close()),
          ),
        ],
      ),
    );
  }

  @override
  void onWindowMaximize() {
    if (mounted) setState(() => _isMaximized = true);
  }

  @override
  void onWindowUnmaximize() {
    if (mounted) setState(() => _isMaximized = false);
  }

  @override
  void onWindowRestore() {
    unawaited(_syncMaximized());
  }
}
