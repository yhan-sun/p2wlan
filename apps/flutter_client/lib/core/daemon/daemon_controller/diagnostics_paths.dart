part of '../daemon_controller.dart';

extension DaemonControllerDiagnosticsPaths on DaemonController {
  Future<bool> _waitForHealth(String diagnosticsUrl, Duration timeout) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (await _diagnosticsApi.fetchHealth(diagnosticsUrl)) return true;
      await Future<void>.delayed(DaemonController._readyPoll);
    }
    return _diagnosticsApi.fetchHealth(diagnosticsUrl);
  }

  Future<bool> _waitForHealthDown(
    String diagnosticsUrl,
    Duration timeout,
  ) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (!await _diagnosticsApi.fetchHealth(diagnosticsUrl)) return true;
      await Future<void>.delayed(DaemonController._readyPoll);
    }
    return !await _diagnosticsApi.fetchHealth(diagnosticsUrl);
  }

  String _diagnosticsBindFromStatusUrl(String diagnosticsUrl) {
    final parsed = Uri.parse(normalizeDiagnosticsUrl(diagnosticsUrl));
    final host = parsed.host.contains(':') ? '[${parsed.host}]' : parsed.host;
    return '$host:${parsed.port}';
  }

  File _defaultConfigPath() {
    final override = Platform.environment['P2WLAN_CONFIG'];
    if (override != null && override.trim().isNotEmpty) {
      return File(override.trim());
    }
    return File(
      '${_configBaseDir().path}${Platform.pathSeparator}p2wlan-config.json',
    );
  }

  Directory _configBaseDir() {
    if (Platform.isMacOS) {
      final home = Platform.environment['HOME'];
      if (home != null && home.isNotEmpty) {
        return Directory('$home/Library/Application Support/p2wlan');
      }
    }
    if (Platform.isWindows) {
      final appData = Platform.environment['APPDATA'];
      if (appData != null && appData.isNotEmpty) {
        return Directory('$appData\\p2wlan');
      }
    }
    final xdg = Platform.environment['XDG_CONFIG_HOME'];
    if (xdg != null && xdg.isNotEmpty) return Directory('$xdg/p2wlan');
    final home = Platform.environment['HOME'];
    if (home != null && home.isNotEmpty) {
      return Directory('$home/.config/p2wlan');
    }
    return Directory(
      '${Directory.systemTemp.path}${Platform.pathSeparator}p2wlan',
    );
  }

  Directory _defaultLogDir() {
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
}
