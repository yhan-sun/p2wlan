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
    required String overlayCidr,
    required String tunInterface,
    required int mtu,
    required String udpBind,
    required String udpAdvertise,
    required String socketPool,
    required String relayServers,
    required String closeBehavior,
  }) async {
    final normalizedDiagnosticsUrl = normalizeDiagnosticsUrl(diagnosticsUrl);
    final normalizedControlServer = normalizeControlServer(controlServer);
    final normalizedNetworkId = networkId.trim().isEmpty
        ? defaultNetworkId
        : networkId.trim();
    final normalizedSocketPool = normalizeSocketPool(socketPool);
    final nextSettings = _settings.copyWith(
      diagnosticsUrl: normalizedDiagnosticsUrl,
      controlServer: normalizedControlServer,
      authToken: authToken.trim(),
      networkId: normalizedNetworkId,
      deviceName: deviceName.trim(),
      manualMode: manualMode,
      overlayCidr: overlayCidr.trim().isEmpty
          ? defaultOverlayCidr
          : overlayCidr.trim(),
      tunInterface: tunInterface.trim().isEmpty
          ? defaultTunInterface
          : tunInterface.trim(),
      mtu: mtu,
      udpBind: udpBind.trim().isEmpty ? defaultUdpBind : udpBind.trim(),
      udpAdvertise: udpAdvertise.trim(),
      socketPool: normalizedSocketPool,
      relayServers: relayServers.trim(),
      closeBehavior: normalizeCloseBehavior(closeBehavior),
    );
    final errors = validateAppSettings(nextSettings);
    if (errors.isNotEmpty) {
      throw FormatException(errors.join('\n'));
    }
    await updateSettings(nextSettings);
  }

  Future<void> updateSettings(AppSettings settings) async {
    final normalizedSettings = settings.copyWith(
      diagnosticsUrl: normalizeDiagnosticsUrl(settings.diagnosticsUrl),
      controlServer: normalizeControlServer(settings.controlServer),
      networkId: settings.networkId.trim().isEmpty
          ? defaultNetworkId
          : settings.networkId.trim(),
      deviceName: settings.deviceName.trim(),
      overlayCidr: settings.overlayCidr.trim().isEmpty
          ? defaultOverlayCidr
          : settings.overlayCidr.trim(),
      tunInterface: settings.effectiveTunInterface,
      udpBind: settings.udpBind.trim().isEmpty
          ? defaultUdpBind
          : settings.udpBind.trim(),
      udpAdvertise: settings.udpAdvertise.trim(),
      socketPool: normalizeSocketPool(settings.socketPool),
      relayServers: settings.relayServers.trim(),
      closeBehavior: normalizeCloseBehavior(settings.closeBehavior),
    );
    final errors = validateAppSettings(normalizedSettings);
    if (errors.isNotEmpty) {
      throw FormatException(errors.join('\n'));
    }
    _settings = normalizedSettings;
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

String normalizeCloseBehavior(String value) {
  final normalized = value.trim();
  if (normalized == 'keep-running' || normalized == 'stop-and-quit') {
    return normalized;
  }
  return defaultCloseBehavior;
}

String normalizeSocketPool(String value) {
  final normalized = value.trim().toLowerCase();
  if (normalized == 'auto' ||
      normalized == 'on' ||
      normalized == 'true' ||
      normalized == 'yes') {
    return defaultSocketPool;
  }
  if (normalized == 'off' ||
      normalized == 'false' ||
      normalized == 'no' ||
      normalized == 'none') {
    return 'off';
  }
  return normalized.isEmpty ? defaultSocketPool : normalized;
}

List<String> validateAppSettings(AppSettings settings) {
  final errors = <String>[];
  try {
    normalizeDiagnosticsUrl(settings.diagnosticsUrl);
  } catch (error) {
    errors.add(error is FormatException ? error.message : error.toString());
  }
  try {
    normalizeControlServer(settings.controlServer);
  } catch (error) {
    errors.add(error is FormatException ? error.message : error.toString());
  }
  if (settings.networkId.trim().isEmpty) {
    errors.add('Network ID is required');
  }
  if (settings.deviceName.trim().isEmpty && !settings.manualMode) {
    errors.add('Device name is required outside manual/offline mode');
  }
  final overlay = settings.overlayCidr.trim();
  if (!_isIpv4Cidr(overlay)) {
    errors.add('Overlay CIDR must look like 10.20.0.0/16');
  }
  if (settings.mtu < 576 || settings.mtu > 65535) {
    errors.add('MTU must be between 576 and 65535');
  }
  if (!_isSocketAddress(settings.udpBind, allowPortZero: true)) {
    errors.add('UDP bind must look like 0.0.0.0:60207');
  }
  final advertise = settings.udpAdvertise.trim();
  if (advertise.isNotEmpty) {
    if (!_isSocketAddress(advertise, allowPortZero: false)) {
      errors.add('UDP advertise must look like 203.0.113.10:60207');
    } else if (_isUnspecifiedAddress(advertise)) {
      errors.add('UDP advertise cannot use 0.0.0.0 or ::');
    }
  }
  final socketPool = normalizeSocketPool(settings.socketPool);
  if (socketPool != 'off') {
    final count = int.tryParse(socketPool);
    if (count == null || count < 2 || count > 4) {
      errors.add('Socket pool must be off or 2-4');
    }
  }
  if (normalizeCloseBehavior(settings.closeBehavior) !=
      settings.closeBehavior) {
    errors.add('Close behavior is invalid');
  }
  return errors;
}

bool _isIpv4Cidr(String value) {
  final parts = value.split('/');
  if (parts.length != 2) return false;
  final prefix = int.tryParse(parts[1]);
  if (prefix == null || prefix < 0 || prefix > 32) return false;
  return _isIpv4Address(parts[0]);
}

bool _isSocketAddress(String value, {required bool allowPortZero}) {
  final trimmed = value.trim();
  if (trimmed.isEmpty) return false;
  String? host;
  String? portText;
  if (trimmed.startsWith('[')) {
    final close = trimmed.indexOf(']');
    if (close <= 1 || close + 2 > trimmed.length) return false;
    if (trimmed[close + 1] != ':') return false;
    host = trimmed.substring(1, close);
    portText = trimmed.substring(close + 2);
  } else {
    final separator = trimmed.lastIndexOf(':');
    if (separator <= 0) return false;
    host = trimmed.substring(0, separator);
    portText = trimmed.substring(separator + 1);
  }
  final port = int.tryParse(portText);
  if (port == null || port < (allowPortZero ? 0 : 1) || port > 65535) {
    return false;
  }
  return _isIpv4Address(host) || host.contains(':');
}

bool _isIpv4Address(String value) {
  final octets = value.split('.');
  if (octets.length != 4) return false;
  for (final part in octets) {
    final number = int.tryParse(part);
    if (number == null || number < 0 || number > 255) return false;
  }
  return true;
}

bool _isUnspecifiedAddress(String value) {
  final normalized = value.trim().toLowerCase();
  return normalized.startsWith('0.0.0.0:') || normalized.startsWith('[::]:');
}
