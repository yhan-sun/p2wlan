from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one match in {path}, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


controller = Path(
    "apps/flutter_client/lib/core/daemon/daemon_controller.dart"
)
replace_once(
    controller,
    "  static const _directReadyTimeout = Duration(seconds: 20);\n",
    "  static const _directReadyTimeout = Duration(seconds: 20);\n"
    "  // The daemon runtime gives its task graph ten seconds to drain after a\n"
    "  // shutdown signal. The GUI must allow that full budget plus scheduler\n"
    "  // margin before it considers the authenticated shutdown failed.\n"
    "  static const _gracefulShutdownTimeout = Duration(seconds: 12);\n",
)
replace_once(
    controller,
    """    if (shutdownRequested) {
      final endpointDown = await _waitForHealthDown(
        diagnosticsUrl,
        const Duration(seconds: 8),
      );
      final processDown = Platform.isWindows && windowsDaemonPids.isNotEmpty
          ? await _waitForWindowsDaemonPidsExit(
              windowsDaemonPids,
              const Duration(seconds: 3),
            )
          : statusPid == null ||
                await _waitForDaemonPidExit(
                  statusPid,
                  const Duration(seconds: 3),
                );
""",
    """    if (shutdownRequested) {
      // The diagnostics listener can close before the daemon has finished
      // draining its TUN, UDP, relay and control tasks. Wait for endpoint and
      // verified process exit concurrently, using the daemon's own shutdown
      // budget, before escalating to the Windows /F fallback.
      final endpointDownFuture = _waitForHealthDown(
        diagnosticsUrl,
        _gracefulShutdownTimeout,
      );
      final processDownFuture =
          Platform.isWindows && windowsDaemonPids.isNotEmpty
          ? _waitForWindowsDaemonPidsExit(
              windowsDaemonPids,
              _gracefulShutdownTimeout,
            )
          : statusPid == null
          ? Future<bool>.value(true)
          : _waitForDaemonPidExit(
              statusPid,
              _gracefulShutdownTimeout,
            );
      final gracefulResults = await Future.wait<bool>([
        endpointDownFuture,
        processDownFuture,
      ]);
      final endpointDown = gracefulResults[0];
      final processDown = gracefulResults[1];
""",
)
replace_once(
    controller,
    """        return DaemonCommandResult(ok: true, message: 'p2wlan-daemon stopped.');
""",
    """        return const DaemonCommandResult(
          ok: true,
          message:
              'p2wlan-daemon stopped after forced process termination fallback.',
        );
""",
)

test_path = Path(
    "apps/flutter_client/test/windows_binary_probe_integration_test.dart"
)
test_text = test_path.read_text(encoding="utf-8")
marker = "\n}\n\nFuture<Directory> _createTempRoot()"
if test_text.count(marker) != 1:
    raise SystemExit(
        f"expected one main() insertion marker in {test_path}, "
        f"found {test_text.count(marker)}"
    )

test_case = r'''

  test(
    'Windows daemon completes three graceful start-stop cycles without force kill',
    () async {
      final binaryPath = _resolveWindowsDaemonBinary();
      expect(
        binaryPath,
        isNotNull,
        reason:
            'Set P2WLAN_DAEMON_BIN or build a Windows release daemon before '
            'running this integration test.',
      );

      final root = await _createTempRoot();
      addTearDown(() => _deleteTempRoot(root));

      for (var cycle = 0; cycle < 3; cycle++) {
        final cycleDir = Directory(
          '${root.path}${Platform.pathSeparator}cycle-$cycle',
        );
        await cycleDir.create(recursive: true);
        final config = File(
          '${cycleDir.path}${Platform.pathSeparator}p2wlan-config.json',
        );
        final log = File(
          '${cycleDir.path}${Platform.pathSeparator}p2wlan-daemon.log',
        );
        final auth = File(
          '${cycleDir.path}${Platform.pathSeparator}p2wlan-daemon.diag-auth',
        );
        final port = await _reserveTcpPort();
        final diagnosticsUrl = 'http://127.0.0.1:$port/status';

        final process = await Process.start(
          binaryPath!,
          [
            '--config',
            config.path,
            '--control',
            'http://127.0.0.1:9',
            '--network',
            'default',
            '--diagnostics-bind',
            '127.0.0.1:$port',
            '--log-file',
            log.path,
            '--udp-bind',
            '127.0.0.1:0',
            '--interface',
            'p2wlan-lifecycle-$cycle',
            '--manual',
          ],
          environment: {
            'P2WLAN_DISABLE_TUN': '1',
            'RUST_LOG': 'info',
          },
        );
        var exited = false;
        addTearDown(() async {
          if (!exited) {
            process.kill(ProcessSignal.sigkill);
            try {
              await process.exitCode.timeout(const Duration(seconds: 5));
            } catch (_) {}
          }
        });
        final stdoutFuture = process.stdout.transform(utf8.decoder).join();
        final stderrFuture = process.stderr.transform(utf8.decoder).join();

        await _waitForWindowsDaemonHealth(port);
        await _waitForNonEmptyFile(auth);

        final api = DiagnosticsApi(
          authTokenReader: () async => (await auth.readAsString()).trim(),
        );
        final controller = DaemonController(diagnosticsApi: api);
        final stopped = await controller.stop(diagnosticsUrl);
        api.close();

        expect(stopped.ok, isTrue, reason: stopped.message);
        expect(
          stopped.message,
          isNot(contains('forced process termination')),
          reason: 'normal UI stop must not use taskkill /F',
        );

        final exitCode = await process.exitCode.timeout(
          const Duration(seconds: 15),
        );
        exited = true;
        final stdout = await stdoutFuture;
        final stderr = await stderrFuture;
        expect(
          exitCode,
          0,
          reason: 'cycle=$cycle stdout=$stdout stderr=$stderr',
        );
        expect(await auth.exists(), isFalse);
        expect(await log.exists(), isTrue);
        expect(await log.readAsString(), contains('Shutdown complete.'));
      }
    },
    skip: !Platform.isWindows,
  );
'''

test_text = test_text.replace(marker, f"{test_case}{marker}", 1)
helpers = r'''

Future<int> _reserveTcpPort() async {
  final socket = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = socket.port;
  await socket.close();
  return port;
}

Future<void> _waitForWindowsDaemonHealth(int port) async {
  final client = HttpClient()
    ..connectionTimeout = const Duration(milliseconds: 500)
    ..findProxy = null;
  final deadline = DateTime.now().add(const Duration(seconds: 20));
  try {
    while (DateTime.now().isBefore(deadline)) {
      try {
        final request = await client
            .getUrl(Uri.parse('http://127.0.0.1:$port/health'))
            .timeout(const Duration(milliseconds: 500));
        final response = await request
            .close()
            .timeout(const Duration(milliseconds: 500));
        await response.drain<void>();
        if (response.statusCode == HttpStatus.ok) return;
      } catch (_) {}
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
  } finally {
    client.close(force: true);
  }
  throw StateError('daemon health endpoint did not become ready on port $port');
}

Future<void> _waitForNonEmptyFile(File file) async {
  final deadline = DateTime.now().add(const Duration(seconds: 10));
  while (DateTime.now().isBefore(deadline)) {
    try {
      if (await file.exists() && (await file.length()) > 0) return;
    } catch (_) {}
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
  throw StateError('file did not become ready: ${file.path}');
}
'''
if "Future<int> _reserveTcpPort() async" in test_text:
    raise SystemExit("Windows lifecycle helpers already exist")
test_path.write_text(test_text.rstrip() + helpers + "\n", encoding="utf-8")
