import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../api/diagnostics_api.dart';
import '../models/diagnostics_models.dart';
import '../security/secure_token_repository.dart';

class SettingsStore extends ChangeNotifier {
  SettingsStore({File? settingsFile, SecureTokenRepository? tokenRepository})
    : _settingsFileOverride = settingsFile {
    _tokenRepository =
        tokenRepository ??
        FileSecureTokenRepository(File('${_settingsFile().path}.token'));
  }

  final File? _settingsFileOverride;
  late final SecureTokenRepository _tokenRepository;

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
          final loadedSettings = AppSettings.fromJson(decoded);
          // One-time secure-token migration: a legacy settings file may carry
          // the token in JSON. Move it into the secure store (verifying by
          // re-read) before we persist, and keep the effective value in memory.
          final legacyToken = loadedSettings.authToken.trim();
          if (legacyToken.isNotEmpty) {
            await _tokenRepository.write(legacyToken);
          }
          final effectiveToken = legacyToken.isNotEmpty
              ? legacyToken
              : (await _tokenRepository.read()) ?? '';
          _settings = (await _migrateSettings(
            loadedSettings,
          )).copyWith(authToken: effectiveToken);
          final migrated =
              jsonEncode(_persistedSettings().toJson()) !=
              jsonEncode(_stripToken(loadedSettings.toJson()));
          if (sourceFile.path != file.path || migrated) {
            await _writeSettingsFile(file);
          }
        }
      } else {
        _settings = (await _migrateSettings(
          _settings,
        )).copyWith(authToken: (await _tokenRepository.read()) ?? '');
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
    required String virtualIp,
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
    final normalizedDeviceName = deviceName.trim().isEmpty
        ? await resolveDefaultDeviceName()
        : deviceName.trim();
    final enteredToken = authToken.trim();
    final resolvedAuthToken = enteredToken.isNotEmpty
        ? enteredToken
        : (manualMode
              ? '' // manual/offline mode intentionally has no control token
              : _settings.authToken); // managed: empty means "keep stored"
    final nextSettings = _settings.copyWith(
      diagnosticsUrl: normalizedDiagnosticsUrl,
      controlServer: normalizedControlServer,
      // The token field is never prefilled with the stored value, so an empty
      // entry in managed mode preserves it; explicit clearing happens via
      // logout or manual mode.
      authToken: resolvedAuthToken,
      networkId: normalizedNetworkId,
      virtualIp: virtualIp.trim(),
      deviceName: normalizedDeviceName,
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
    final normalizedDeviceName = settings.deviceName.trim().isEmpty
        ? await resolveDefaultDeviceName()
        : settings.deviceName.trim();
    final normalizedSettings = settings.copyWith(
      diagnosticsUrl: normalizeDiagnosticsUrl(settings.diagnosticsUrl),
      controlServer: normalizeControlServer(settings.controlServer),
      networkId: settings.networkId.trim().isEmpty
          ? defaultNetworkId
          : settings.networkId.trim(),
      virtualIp: settings.virtualIp.trim(),
      deviceName: normalizedDeviceName,
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
    notifyListeners();
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
      // Keep the credential in the secure store in lockstep with the
      // in-memory value. A blank token clears the secure store.
      await _tokenRepository.write(_settings.authToken);
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
    // Persist non-credential settings only. The auth token lives in the secure
    // repository, never in this JSON (it can be backed up or shipped in support
    // bundles), so it is always written blank.
    await file.writeAsString(
      const JsonEncoder.withIndent('  ').convert(_persistedSettings().toJson()),
    );
  }

  /// Settings as they should be written to disk: identical to the in-memory
  /// settings except the auth token is blanked (it is stored separately).
  AppSettings _persistedSettings() => _settings.copyWith(authToken: '');

  /// The token field in [json] blanked, for comparing persisted content.
  Map<String, dynamic> _stripToken(Map<String, dynamic> json) {
    final copy = Map<String, dynamic>.from(json);
    copy['authToken'] = '';
    return copy;
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

Future<AppSettings> _migrateSettings(AppSettings settings) async {
  final controlServer = settings.controlServer.trim();
  final hasAuthToken = settings.authToken.trim().isNotEmpty;
  final legacyLocalControl =
      controlServer == 'http://127.0.0.1:8080' ||
      controlServer == 'http://localhost:8080';
  final currentDeviceName = settings.deviceName.trim();
  var migrated = settings;
  if (!hasAuthToken &&
      (controlServer == legacyControlServer || legacyLocalControl)) {
    migrated = migrated.copyWith(controlServer: defaultControlServer);
  }
  if (_shouldReplaceDefaultDeviceName(currentDeviceName)) {
    migrated = migrated.copyWith(deviceName: await resolveDefaultDeviceName());
  }
  return migrated;
}

Future<String> resolveDefaultDeviceName() async {
  final candidates = <String>[
    if (Platform.isMacOS) ...await _macosDeviceNameCandidates(),
    Platform.environment['COMPUTERNAME'] ?? '',
    Platform.environment['HOSTNAME'] ?? '',
    Platform.localHostname,
    'this-device',
  ];
  for (final candidate in candidates) {
    final normalized = _normalizeDeviceNameCandidate(candidate);
    if (normalized.isNotEmpty && !_looksLikeIpAddress(normalized)) {
      return normalized;
    }
  }
  return 'this-device';
}

Future<List<String>> _macosDeviceNameCandidates() async {
  final values = <String>[];
  for (final key in const ['ComputerName', 'HostName', 'LocalHostName']) {
    try {
      final result = await Process.run('scutil', [
        '--get',
        key,
      ]).timeout(const Duration(milliseconds: 800));
      if (result.exitCode == 0) values.add(result.stdout.toString());
    } catch (_) {
      // Ignore platform command failures and fall back to environment names.
    }
  }
  return values;
}

String _normalizeDeviceNameCandidate(String value) {
  return value.trim().split(RegExp(r'\s+')).join(' ');
}

bool _shouldReplaceDefaultDeviceName(String value) {
  final normalized = _normalizeDeviceNameCandidate(value);
  return normalized.isEmpty ||
      normalized == 'this-device' ||
      normalized == Platform.localHostname ||
      _looksLikeIpAddress(normalized);
}

bool _looksLikeIpAddress(String value) {
  return InternetAddress.tryParse(value) != null ||
      RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(value);
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
  final virtualIp = settings.virtualIp.trim();
  if (virtualIp.isNotEmpty && !_isIpv4Address(virtualIp)) {
    errors.add('Virtual IP must look like 10.20.0.42');
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
