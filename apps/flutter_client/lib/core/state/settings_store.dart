import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../api/daemon_api.dart';
import '../models/daemon_models.dart';

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
      if (await file.exists()) {
        final raw = await file.readAsString();
        final decoded = jsonDecode(raw);
        if (decoded is Map<String, dynamic>) {
          _settings = AppSettings.fromJson(decoded);
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

  Future<void> updateLanguageCode(String languageCode) async {
    _settings = _settings.copyWith(languageCode: languageCode);
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
      await file.parent.create(recursive: true);
      await file.writeAsString(
        const JsonEncoder.withIndent('  ').convert(_settings.toJson()),
      );
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

  Directory _configDirectory() {
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
