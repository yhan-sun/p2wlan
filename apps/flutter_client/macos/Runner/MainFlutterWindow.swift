import Cocoa
import FlutterMacOS
import Security

private enum P2wlanAdminPasswordKeychain {
  private static let service = "com.p2wlan.client.macos-admin"
  private static let account = "p2wlan-daemon"

  private static var baseQuery: [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
    ]
  }

  static func hasStoredPassword() throws -> Bool {
    var query = baseQuery
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    query[kSecReturnData as String] = false
    let status = SecItemCopyMatching(query as CFDictionary, nil)
    switch status {
    case errSecSuccess:
      return true
    case errSecItemNotFound:
      return false
    default:
      throw KeychainError.status(status)
    }
  }

  static func readPassword() throws -> String {
    var query = baseQuery
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    query[kSecReturnData as String] = true

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else {
      if status == errSecItemNotFound {
        throw KeychainError.missing
      }
      throw KeychainError.status(status)
    }
    guard
      let data = result as? Data,
      let password = String(data: data, encoding: .utf8),
      !password.isEmpty
    else {
      throw KeychainError.invalidValue
    }
    return password
  }

  static func store(password: String) throws {
    guard !password.isEmpty else {
      throw KeychainError.invalidValue
    }

    let data = Data(password.utf8)
    let updateStatus = SecItemUpdate(
      baseQuery as CFDictionary,
      [kSecValueData as String: data] as CFDictionary
    )
    if updateStatus == errSecSuccess {
      return
    }
    guard updateStatus == errSecItemNotFound else {
      throw KeychainError.status(updateStatus)
    }

    let attributes: [String: Any] = [
      kSecValueData as String: data,
      // Do not sync this item to iCloud or other devices. The credential is
      // only useful for the local macOS account that authorized this daemon.
      kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      kSecAttrLabel as String: "P2WLAN administrator credential",
      kSecAttrIsInvisible as String: true,
    ]

    var item = baseQuery
    for (key, value) in attributes {
      item[key] = value
    }
    let addStatus = SecItemAdd(item as CFDictionary, nil)
    guard addStatus == errSecSuccess else {
      throw KeychainError.status(addStatus)
    }
  }

  static func clear() throws {
    let status = SecItemDelete(baseQuery as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw KeychainError.status(status)
    }
  }

  enum KeychainError: Error {
    case missing
    case invalidValue
    case status(OSStatus)
  }
}

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
    case "hasStoredPassword":
      do {
        result(try P2wlanAdminPasswordKeychain.hasStoredPassword())
      } catch {
        result(FlutterError(
          code: "keychain_unavailable",
          message: "Unable to inspect the macOS login Keychain.",
          details: nil
        ))
      }

    case "promptAndStorePassword":
      do {
        result(try promptAndStorePassword())
      } catch {
        result(FlutterError(
          code: "keychain_write_failed",
          message: "Unable to save the administrator credential in the macOS login Keychain.",
          details: nil
        ))
      }

    case "clearStoredPassword":
      do {
        try P2wlanAdminPasswordKeychain.clear()
        result(nil)
      } catch {
        result(FlutterError(
          code: "keychain_delete_failed",
          message: "Unable to remove the saved administrator credential.",
          details: nil
        ))
      }

    case "runWithStoredPassword":
      guard
        let arguments = call.arguments as? [String: Any],
        let command = arguments["command"] as? String,
        !command.isEmpty
      else {
        result(FlutterError(
          code: "invalid_command",
          message: "Missing elevated command.",
          details: nil
        ))
        return
      }

      // Password retrieval and sudo execution happen natively. The command
      // contains no password; only the native process pipe receives it.
      DispatchQueue.global(qos: .userInitiated).async { [weak self] in
        let response = self?.runWithStoredPassword(command) ?? [
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

  private func promptAndStorePassword() throws -> Bool {
    let isChinese = Locale.preferredLanguages.first?.lowercased().hasPrefix("zh") == true
    let alert = NSAlert()
    alert.alertStyle = .informational
    alert.messageText = isChinese ? "保存 P2WLAN 管理员密码" : "Save the P2WLAN administrator password"
    alert.informativeText = isChinese
      ? "密码会加密存储在当前用户的 macOS 登录钥匙串中，仅用于启动 P2WLAN 的虚拟网卡。以后启动不再询问。"
      : "The password is encrypted in this Mac user's login Keychain and is only used to start P2WLAN's virtual adapter. It will not be requested again."

    let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
    field.placeholderString = isChinese ? "管理员密码" : "Administrator password"
    alert.accessoryView = field
    alert.addButton(withTitle: isChinese ? "保存并继续" : "Save and continue")
    alert.addButton(withTitle: isChinese ? "取消" : "Cancel")

    NSApp.activate(ignoringOtherApps: true)
    alert.window.initialFirstResponder = field
    let response = alert.runModal()
    guard response == .alertFirstButtonReturn else {
      return false
    }
    let password = field.stringValue
    guard !password.isEmpty else {
      return false
    }
    try P2wlanAdminPasswordKeychain.store(password: password)
    return true
  }

  private func runWithStoredPassword(_ command: String) -> [String: Any] {
    let password: String
    do {
      password = try P2wlanAdminPasswordKeychain.readPassword()
    } catch P2wlanAdminPasswordKeychain.KeychainError.missing {
      return ["ok": false, "missingCredential": true]
    } catch P2wlanAdminPasswordKeychain.KeychainError.invalidValue {
      return ["ok": false, "missingCredential": true]
    } catch {
      return [
        "ok": false,
        "error": "无法读取 macOS 登录钥匙串中的管理员凭据。",
      ]
    }

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
    self.minSize = NSSize(width: 860, height: 560)
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
