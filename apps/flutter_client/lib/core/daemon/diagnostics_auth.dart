// Per-process local diagnostics session token.
//
// The daemon generates a fresh random token at startup, writes it to a 0600
// file next to its log file, and deletes it on shutdown. Native callers attach
// it to every sensitive diagnostics request as `Authorization: Bearer <token>`;
// only `/health` and `/status.version` are public.
// The token never appears on the daemon command line or in the persisted
// config, and it is per-process: after a daemon restart the file (and the
// token) is regenerated, so callers always read it fresh.
import 'dart:io';

/// Platform-normalized directory the daemon writes its log and token files to.
Directory defaultP2WlanLogDir() {
  if (Platform.isMacOS) {
    final home = Platform.environment['HOME'];
    if (home != null && home.isNotEmpty) {
      return Directory('$home/Library/Logs/p2wlan');
    }
  }
  if (Platform.isWindows) {
    final localAppData = Platform.environment['LOCALAPPDATA'];
    if (localAppData != null && localAppData.isNotEmpty) {
      return Directory('$localAppData\\p2wlan\\logs');
    }
  }
  final home = Platform.environment['HOME'];
  if (home != null && home.isNotEmpty) {
    return Directory('$home/.local/state/p2wlan');
  }
  return Directory(
    '${Directory.systemTemp.path}${Platform.pathSeparator}p2wlan',
  );
}

/// Path of the per-process diagnostics auth token file.
String diagnosticsAuthTokenPath() {
  return '${defaultP2WlanLogDir().path}${Platform.pathSeparator}p2wlan-daemon.diag-auth';
}

/// Read the current per-process diagnostics auth token, or `null` when the
/// daemon has not written one yet (not running, or just starting up).
Future<String?> readDiagnosticsAuthToken() async {
  final file = File(diagnosticsAuthTokenPath());
  try {
    if (!await file.exists()) return null;
    final value = (await file.readAsString()).trim();
    return value.isEmpty ? null : value;
  } catch (_) {
    return null;
  }
}
