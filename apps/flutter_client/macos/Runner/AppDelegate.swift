import Cocoa
import FlutterMacOS

@main
class AppDelegate: FlutterAppDelegate {
  private var usesFlutterTray: Bool {
    let raw = ProcessInfo.processInfo.environment["P2WLAN_ENABLE_FLUTTER_TRAY"]?
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .lowercased()
    // The Flutter tray is bundled with the desktop app and is enabled by
    // default. Only an explicit false-like environment value selects the
    // standalone/native-tray development path.
    guard let raw, !raw.isEmpty else { return true }
    return raw != "0" && raw != "false" && raw != "no" && raw != "off"
  }

  override func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    return !usesFlutterTray
  }

  override func applicationShouldHandleReopen(
    _ sender: NSApplication,
    hasVisibleWindows flag: Bool
  ) -> Bool {
    for window in sender.windows {
      window.makeKeyAndOrderFront(self)
    }
    sender.activate(ignoringOtherApps: true)
    return true
  }

  override func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
    return true
  }
}
