import Cocoa
import Darwin
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
          "timedOut": false,
          "exitCode": NSNull(),
          "errorCode": "bridge_unavailable",
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
    let deadline = ProcessInfo.processInfo.systemUptime + 45
    let input = Data((password + "\n").utf8)
    guard input.count <= 4096 else {
      return elevationFailure("invalid_password_length", "管理员凭据长度无效。")
    }
    let task = Process()
    let standardInput = Pipe()
    let standardOutput = Pipe()
    let standardError = Pipe()
    let handles = [
      standardInput.fileHandleForReading, standardInput.fileHandleForWriting,
      standardOutput.fileHandleForReading, standardOutput.fileHandleForWriting,
      standardError.fileHandleForReading, standardError.fileHandleForWriting,
    ]
    defer {
      for handle in handles { try? handle.close() }
    }
    task.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
    task.arguments = ["-S", "-p", "", "/bin/sh", "-c", command]
    task.standardInput = standardInput
    task.standardOutput = standardOutput
    task.standardError = standardError

    let inputFD = standardInput.fileHandleForWriting.fileDescriptor
    var output = BoundedElevationOutput(standardOutput.fileHandleForReading.fileDescriptor)
    var errorOutput = BoundedElevationOutput(standardError.fileHandleForReading.fileDescriptor)
    do {
      for fd in [inputFD, output.fd, errorOutput.fd] {
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
          return elevationFailure("pipe_setup_failed", "无法准备管理员授权通信。")
        }
      }
      // A cancelled sudo prompt may close stdin before the password write.
      // Do not let that pipe race deliver SIGPIPE to the GUI process.
      guard fcntl(inputFD, F_SETNOSIGPIPE, 1) == 0 else {
        return elevationFailure("pipe_setup_failed", "无法准备管理员授权通信。")
      }
      try task.run()
    } catch {
      return elevationFailure("launch_failed", "无法启动 macOS sudo 提权进程。")
    }
    try? standardInput.fileHandleForReading.close()
    try? standardOutput.fileHandleForWriting.close()
    try? standardError.fileHandleForWriting.close()

    var written = 0
    var inputClosed = false
    var timedOut = false
    var pipeFailed = false
    // One bounded owner multiplexes both output pipes while feeding sudo.
    // No reader task or inherited pipe can outlive this invocation's deadline.
    while true {
      if ProcessInfo.processInfo.systemUptime >= deadline {
        timedOut = true
        break
      }
      do {
        if !inputClosed {
          let count = input.withUnsafeBytes { bytes in
            Darwin.write(inputFD, bytes.baseAddress!.advanced(by: written), input.count - written)
          }
          if count > 0 { written += count }
          if written == input.count || (count < 0 && errno == EPIPE) {
            try? standardInput.fileHandleForWriting.close()
            inputClosed = true
          } else if count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
          }
        }
        try output.drain()
        try errorOutput.drain()
        if !task.isRunning && output.reachedEOF && errorOutput.reachedEOF { break }
        var descriptors = [
          pollfd(fd: inputClosed ? -1 : inputFD, events: Int16(POLLOUT), revents: 0),
          pollfd(fd: output.reachedEOF ? -1 : output.fd, events: Int16(POLLIN), revents: 0),
          pollfd(fd: errorOutput.reachedEOF ? -1 : errorOutput.fd, events: Int16(POLLIN), revents: 0),
        ]
        let remaining = max(0, deadline - ProcessInfo.processInfo.systemUptime)
        let timeout = Int32(min(50, (remaining * 1000).rounded(.up)))
        let pollResult = descriptors.withUnsafeMutableBufferPointer {
          Darwin.poll($0.baseAddress, nfds_t($0.count), timeout)
        }
        if pollResult < 0 && errno != EINTR {
          throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
      } catch {
        pipeFailed = true
        break
      }
    }
    if (timedOut || pipeFailed) && task.isRunning { task.terminate() }
    let exitCode: Any = task.isRunning ? NSNull() : task.terminationStatus
    let marker = parseElevationChildPID(output.data)
    var response: [String: Any] = ["ok": false, "timedOut": timedOut, "exitCode": exitCode]
    if let childPID = marker.pid { response["childPid"] = childPID }
    if timedOut {
      response["errorCode"] = "elevation_timeout"
      response["error"] = "macOS 管理员授权执行超时。"
      return response
    }
    if pipeFailed {
      response["errorCode"] = "pipe_io_failed"
      response["error"] = "macOS 管理员授权通信失败。"
      return response
    }
    let stderr = String(decoding: errorOutput.data, as: UTF8.self).lowercased()
    if stderr.contains("incorrect password") || stderr.contains("sorry, try again") ||
        stderr.contains("authentication failure") {
      response["authenticationFailed"] = true
      response["errorCode"] = "authentication_failed"
      response["error"] = "macOS 管理员密码无效。"
      return response
    }
    if task.terminationStatus != 0 {
      response["errorCode"] = "command_failed"
      response["error"] = "macOS sudo 提权进程执行失败。"
      return response
    }
    if marker.invalid || output.exceededLimit || errorOutput.exceededLimit {
      response["errorCode"] = "invalid_elevation_output"
      response["error"] = "macOS 管理员授权返回了无效结果。"
      return response
    }
    response["ok"] = true
    return response
  }

  private func elevationFailure(_ code: String, _ message: String) -> [String: Any] {
    return ["ok": false, "timedOut": false, "exitCode": NSNull(), "errorCode": code, "error": message]
  }

}

// These buffers are private to one worker. Only a validated PID, never the
// command's stdout/stderr or the administrator password, crosses back to Dart.
private struct BoundedElevationOutput {
  let fd: Int32
  var data = Data()
  var reachedEOF = false
  var exceededLimit = false
  private static let limit = 16 * 1024

  init(_ fd: Int32) { self.fd = fd }

  mutating func drain() throws {
    guard !reachedEOF else { return }
    var bytes = [UInt8](repeating: 0, count: 4096)
    // Limit work per turn so a continuously noisy child cannot starve the
    // other pipe, password delivery, or the fixed monotonic deadline.
    for _ in 0..<16 {
      let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
      if count == 0 { reachedEOF = true; return }
      if count < 0 {
        if errno == EAGAIN || errno == EWOULDBLOCK { return }
        if errno == EINTR { continue }
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
      }
      let retained = min(count, Self.limit - data.count)
      data.append(contentsOf: bytes.prefix(retained))
      exceededLimit = exceededLimit || retained != count
    }
  }
}

private func parseElevationChildPID(_ output: Data) -> (pid: Int32?, invalid: Bool) {
  let prefix = "__P2WLAN_POSIX_CHILD_PID__="
  let text = String(decoding: output, as: UTF8.self)
  var pid: Int32?
  // An unterminated last line is not a complete launcher receipt.
  for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false).dropLast() {
    let line = rawLine.hasSuffix("\r") ? rawLine.dropLast() : rawLine[...]
    guard line.hasPrefix(prefix) else { continue }
    let value = line.dropFirst(prefix.count)
    guard pid == nil, !value.isEmpty, value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let parsed = Int32(value), parsed > 0 else {
      return (nil, true)
    }
    pid = parsed
  }
  return (pid, false)
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
    // Below the labeled-sidebar breakpoint, Flutter uses its compact rail.
    self.contentMinSize = NSSize(width: 680, height: 500)
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
