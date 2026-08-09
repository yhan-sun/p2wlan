import Cocoa
import FlutterMacOS

@main
class AppDelegate: FlutterAppDelegate {
  private var usesFlutterTray: Bool {
    let raw = ProcessInfo.processInfo.environment["P2WLAN_ENABLE_FLUTTER_TRAY"]?
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .lowercased()
    guard let raw, !raw.isEmpty else { return false }
    return raw != "0" && raw != "false" && raw != "no"
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
