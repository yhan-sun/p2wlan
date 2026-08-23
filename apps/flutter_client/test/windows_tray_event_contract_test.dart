import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/desktop_tray_controller.dart';

void main() {
  test(
    'Windows tray down-event contract restores the window or opens menu',
    () {
      expect(
        DesktopTrayController.trayPointerActionForTesting(
          isWindows: true,
          mouseDown: true,
          rightButton: false,
        ),
        DesktopTrayPointerAction.showWindow,
      );
      expect(
        DesktopTrayController.trayPointerActionForTesting(
          isWindows: true,
          mouseDown: true,
          rightButton: true,
        ),
        DesktopTrayPointerAction.contextMenu,
      );

      // Do not handle both callback names on Windows: that would make one
      // native click restore/show a second menu after the down callback fired.
      expect(
        DesktopTrayController.trayPointerActionForTesting(
          isWindows: true,
          mouseDown: false,
          rightButton: false,
        ),
        isNull,
      );
      expect(
        DesktopTrayController.trayPointerActionForTesting(
          isWindows: true,
          mouseDown: false,
          rightButton: true,
        ),
        isNull,
      );
    },
  );

  test('non-Windows tray behavior remains mouse-up context menus', () {
    expect(
      DesktopTrayController.trayPointerActionForTesting(
        isWindows: false,
        mouseDown: true,
        rightButton: false,
      ),
      isNull,
    );
    expect(
      DesktopTrayController.trayPointerActionForTesting(
        isWindows: false,
        mouseDown: false,
        rightButton: false,
      ),
      DesktopTrayPointerAction.contextMenu,
    );
  });
}
