import Cocoa
import FlutterMacOS

private final class P2wlanMacosElevationBridge {
  private let channel: FlutterMethodChannel

  init(messenger: FlutterBinaryMessenger) {
    channel = FlutterMethodChannel(
      name: "p2wlan/macos_elevation",
      binaryMessenger: messenger
    )
    channel.setMethodCallHandler { [weak self] call, result in
      self?.handle(call: call, result: result)
    }
  }

  private func handle(call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "promptPassword":
      result(promptPassword())

    case "runWithPassword":
      guard
        let arguments = call.arguments as? [String: Any],
        let command = arguments["command"] as? String,
        !command.isEmpty,
        let password = arguments["password"] as? String,
        !password.isEmpty
      else {
        result(FlutterError(
          code: "invalid_elevation_arguments",
          message: "Missing elevated command or administrator password.",
          details: nil
        ))
        return
      }

      // The password is passed only through this in-memory method call and
      // the sudo stdin pipe. It is never placed in a process argument, log,
      // or native persistent store.
      DispatchQueue.global(qos: .userInitiated).async { [weak self] in
        let response = self?.runWithPassword(command, password) ?? [
          "ok": false,
          "error": "macOS 提权桥接层不可用。",
        ]
        DispatchQueue.main.async {
          result(response)
        }
      }

    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func promptPassword() -> String? {
    let isChinese = Locale.preferredLanguages.first?.lowercased().hasPrefix("zh") == true
    let alert = NSAlert()
    alert.alertStyle = .informational
    alert.messageText = isChinese
      ? "保存 P2WLAN 管理员密码"
      : "Save the P2WLAN administrator password"
    alert.informativeText = isChinese
      ? "密码会加密保存在 P2WLAN 本地配置文件中，仅当前用户可读取；不会使用 macOS 钥匙串。以后启动不再询问。"
      : "The password is encrypted in P2WLAN's local configuration file, readable only by this user. The macOS Keychain is not used."

    let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
    field.placeholderString = isChinese ? "管理员密码" : "Administrator password"
    alert.accessoryView = field
    alert.addButton(withTitle: isChinese ? "保存并继续" : "Save and continue")
    alert.addButton(withTitle: isChinese ? "取消" : "Cancel")

    NSApp.activate(ignoringOtherApps: true)
    alert.window.initialFirstResponder = field
    let response = alert.runModal()
    guard response == .alertFirstButtonReturn, !field.stringValue.isEmpty else {
      return nil
    }
    return field.stringValue
  }

  private func runWithPassword(_ command: String, _ password: String) -> [String: Any] {
    let task = Process()
    let standardInput = Pipe()
    let standardError = Pipe()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
    task.arguments = ["-S", "-p", "", "/bin/sh", "-c", command]
    task.standardInput = standardInput
    task.standardOutput = FileHandle.nullDevice
    task.standardError = standardError

    do {
      try task.run()
      standardInput.fileHandleForWriting.write(Data((password + "\n").utf8))
      standardInput.fileHandleForWriting.closeFile()
      task.waitUntilExit()
    } catch {
      return [
        "ok": false,
        "error": "无法启动 macOS sudo 提权进程。",
      ]
    }

    let stderr = String(
      data: standardError.fileHandleForReading.readDataToEndOfFile(),
      encoding: .utf8
    )?.lowercased() ?? ""
    let authenticationFailed =
      stderr.contains("incorrect password") ||
      stderr.contains("sorry, try again") ||
      stderr.contains("authentication failure")
    if authenticationFailed {
      return [
        "ok": false,
        "authenticationFailed": true,
        "error": "macOS 管理员密码无效。",
      ]
    }
    guard task.terminationStatus == 0 else {
      return [
        "ok": false,
        "error": "macOS sudo 提权进程启动失败。",
      ]
    }
    return ["ok": true]
  }
}

class MainFlutterWindow: NSWindow {
  private var macosElevationBridge: P2wlanMacosElevationBridge?

  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.title = "P2WLAN"
    self.titleVisibility = .hidden
    self.titlebarAppearsTransparent = true
    self.styleMask.insert(.fullSizeContentView)
    self.isMovableByWindowBackground = true
    // Keep the two-level desktop settings layout usable at the smallest
    // window size. The Flutter shell switches to its compact rail before
    // this boundary, while the settings category rail remains visible.
    self.minSize = NSSize(width: 800, height: 520)
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)
    macosElevationBridge = P2wlanMacosElevationBridge(
      messenger: flutterViewController.engine.binaryMessenger
    )

    super.awakeFromNib()
    center()
    makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
  }
}
