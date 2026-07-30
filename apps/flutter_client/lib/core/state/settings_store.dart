import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../api/diagnostics_api.dart';
import '../models/diagnostics_models.dart';

class SettingsStore extends ChangeNotifier {
  SettingsStore({File? settingsFile}) : _settingsFileOverride = settingsFile;

  final File? _settingsFileOverride;

  AppSettings _settings = const AppSettings();
  var _loaded = false;
  String? _lastError;
  String? _configPath;

  AppSettings get settings => _settings;
  bool get loaded => _loaded;
  String? get lastError => _lastError;
  String? get configPath => _configPath;

  Future<void> load() async {
    try {
      final file = _settingsFile();
      _configPath = file.path;
      final sourceFile = await _settingsSourceFile(file);
      if (sourceFile != null) {
        final raw = await sourceFile.readAsString();
        final decoded = jsonDecode(raw);
        if (decoded is Map<String, dynamic>) {
          _settings = AppSettings.fromJson(decoded);
          if (sourceFile.path != file.path) {
            await _writeSettingsFile(file);
          }
        }
      }
      _lastError = null;
    } catch (error) {
      _lastError = 'Failed to load local settings: $error';
      _settings = const AppSettings();
    } finally {
      _loaded = true;
      notifyListeners();
    }
  }

  Future<void> updateDiagnosticsUrl(String diagnosticsUrl) async {
    final normalized = normalizeDiagnosticsUrl(diagnosticsUrl);
    _settings = _settings.copyWith(diagnosticsUrl: normalized);
    await _save();
    notifyListeners();
  }

  Future<void> updateConnectionSettings({
    required String diagnosticsUrl,
    required String controlServer,
    required String authToken,
    required String networkId,
    required String deviceName,
    required bool manualMode,
  }) async {
    final normalizedDiagnosticsUrl = normalizeDiagnosticsUrl(diagnosticsUrl);
    final normalizedControlServer = normalizeControlServer(controlServer);
    final normalizedNetworkId = networkId.trim().isEmpty
        ? defaultNetworkId
        : networkId.trim();
    _settings = _settings.copyWith(
      diagnosticsUrl: normalizedDiagnosticsUrl,
      controlServer: normalizedControlServer,
      authToken: authToken.trim(),
      networkId: normalizedNetworkId,
      deviceName: deviceName.trim(),
      manualMode: manualMode,
    );
    await _save();
    notifyListeners();
  }

  Future<void> updateLanguageCode(String languageCode) async {
    _settings = _settings.copyWith(languageCode: languageCode);
    await _save();
    notifyListeners();
  }

  Future<void> updateThemeMode(String themeMode) async {
    _settings = _settings.copyWith(themeMode: themeMode);
    await _save();
    notifyListeners();
  }

  Future<void> resetDiagnosticsUrl() async {
    _settings = _settings.copyWith(diagnosticsUrl: defaultDiagnosticsUrl);
    await _save();
    notifyListeners();
  }

  Future<void> _save() async {
    try {
      final file = _settingsFile();
      _configPath = file.path;
      await _writeSettingsFile(file);
      _lastError = null;
    } catch (error) {
      _lastError = 'Failed to save local settings: $error';
      rethrow;
    }
  }

  File _settingsFile() {
    final override = _settingsFileOverride;
    if (override != null) return override;
    return File(
      '${_configDirectory().path}${Platform.pathSeparator}flutter-client-settings.json',
    );
  }

  Future<File?> _settingsSourceFile(File preferredFile) async {
    if (await preferredFile.exists()) return preferredFile;
    final legacyFile = _legacySettingsFile();
    if (legacyFile != null && await legacyFile.exists()) return legacyFile;
    return null;
  }

  Future<void> _writeSettingsFile(File file) async {
    await file.parent.create(recursive: true);
    await file.writeAsString(
      const JsonEncoder.withIndent('  ').convert(_settings.toJson()),
    );
  }

  File? _legacySettingsFile() {
    if (!Platform.isMacOS || _settingsFileOverride != null) return null;
    final home = Platform.environment['HOME'];
    if (home == null || home.isEmpty) return null;
    return File(
      '$home/Library/Application Support/p2wlan/flutter-client-settings.json',
    );
  }

  Directory _configDirectory() {
    if (Platform.isMacOS) {
      final home = Platform.environment['HOME'];
      if (home != null && home.isNotEmpty) {
        return Directory('$home/Library/Application Support/p2wlan-client');
      }
    }
    if (Platform.isWindows) {
      final appData = Platform.environment['APPDATA'];
      if (appData != null && appData.isNotEmpty) {
        return Directory('$appData\\p2wlan');
      }
    }
    final xdg = Platform.environment['XDG_CONFIG_HOME'];
    if (xdg != null && xdg.isNotEmpty) {
      return Directory('$xdg/p2wlan');
    }
    final home = Platform.environment['HOME'];
    if (home != null && home.isNotEmpty) {
      return Directory('$home/.config/p2wlan');
    }
    return Directory(
      '${Directory.systemTemp.path}${Platform.pathSeparator}p2wlan',
    );
  }
}

String normalizeControlServer(String value) {
  final trimmed = value.trim().isEmpty ? defaultControlServer : value.trim();
  final parsed = Uri.tryParse(trimmed);
  if (parsed == null || !parsed.hasScheme || parsed.host.isEmpty) {
    throw FormatException('Control server must be a valid URL', value);
  }
  if (parsed.scheme != 'http' && parsed.scheme != 'https') {
    throw FormatException('Control server must use http or https', value);
  }
  return trimmed.replaceFirst(RegExp(r'/+$'), '');
}
