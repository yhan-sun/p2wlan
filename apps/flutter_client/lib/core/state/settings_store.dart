import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../api/diagnostics_api.dart';
import '../models/diagnostics_models.dart';
import '../platform/android_platform.dart';
import '../rooms/room_profiles.dart';
import '../security/local_config_secret.dart';
import '../security/secure_token_repository.dart';

class SettingsCredentialRestoreException implements Exception {
  const SettingsCredentialRestoreException(
    this.saveError,
    this.restoreError, {
    this.clearError,
  });
  final Object saveError;
  final Object restoreError;
  final Object? clearError;
  bool get credentialCleared => clearError == null;

  @override
  String toString() => credentialCleared
      ? 'Settings could not be saved and the previous credential could not be restored. The stored credential was cleared; sign in again before reconnecting.'
      : 'Settings could not be saved and credential recovery failed. Sign in again before reconnecting.';
}

class SettingsStore extends ChangeNotifier {
  SettingsStore({File? settingsFile, SecureTokenRepository? tokenRepository})
    : _settingsFileOverride = settingsFile {
    _tokenRepository = tokenRepository ?? LocalTokenRepository();
  }

  final File? _settingsFileOverride;
  late final SecureTokenRepository _tokenRepository;

  Future<void> Function(
    AppSettings current,
    AppSettings next,
    Future<void> Function() commit,
  )?
  applySessionChange;
  Future<void>? _pendingSettingsWrite;
  final _writeOwnerKey = Object();
  Object? _activeWriteOwner;

  AppSettings _settings = const AppSettings();
  var _loaded = false;
  String? _lastError;
  String? _configPath;

  AppSettings get settings => _settings;
  bool get loaded => _loaded;
  String? get lastError => _lastError;
  String? get configPath => _configPath;

  Future<void> load() async {
    AppSettings? parsedSettings;
    try {
      final file = Platform.isAndroid
          ? await _settingsFile()
          : _settingsFileSync();
      _configPath = file.path;
      final sourceFile = await _settingsSourceFile(file);
      if (sourceFile != null) {
        final raw = await sourceFile.readAsString();
        final decoded = jsonDecode(raw);
        if (decoded is Map<String, dynamic>) {
          final loadedSettings = AppSettings.fromJson(decoded);
          parsedSettings = loadedSettings;

          // Migrate every legacy spelling only after checking whether a secure
          // value already exists. Never overwrite an established secure value.
          final legacyToken = _legacyToken(decoded, loadedSettings);
          final secureToken = (await _tokenRepository.read())?.trim() ?? '';
          var effectiveToken = secureToken;
          if (effectiveToken.isEmpty && legacyToken.isNotEmpty) {
            await _tokenRepository.write(legacyToken);
            final verified = (await _tokenRepository.read())?.trim() ?? '';
            if (verified != legacyToken) {
              throw const SecureTokenStorageException('系统安全存储写入校验失败，旧配置保持不变。');
            }
            effectiveToken = legacyToken;
          }
          var restoredSettings = (await _migrateSettings(loadedSettings))
              .copyWith(authToken: effectiveToken);
          final encryptedAdminPassword = loadedSettings
              .macosAdminPasswordCiphertext
              .trim();
          if (encryptedAdminPassword.isNotEmpty) {
            // A missing/invalid sidecar key must not prevent the rest of the
            // settings from loading. The next macOS daemon start will ask for
            // the password again and replace the invalid local credential.
            try {
              final password = await LocalConfigSecret.decrypt(
                encryptedAdminPassword,
                keyFile: _adminPasswordKeyFile(sourceFile),
              );
              restoredSettings = restoredSettings.copyWith(
                macosAdminPassword: password,
              );
            } catch (_) {
              // Keep the ciphertext in place so a transient file-permission
              // problem does not destroy the user's saved value.
            }
          }
          _settings = restoredSettings;
          final migrated =
              jsonEncode(_persistedSettings().toJson()) !=
              jsonEncode(_stripToken(loadedSettings.toJson()));
          if (sourceFile.path != file.path ||
              migrated ||
              _hasLegacyFields(decoded)) {
            await _writeSettingsFile(file);
          }
        }
      } else {
        _settings = (await _migrateSettings(_settings))
            .copyWith(authToken: (await _tokenRepository.read()) ?? '');
      }
      _lastError = null;
    } catch (error) {
      _lastError = 'Failed to load local settings: $error';
      // Keep the parsed legacy value in memory when secure migration fails so
      // the caller cannot mistake a failed migration for an empty credential.
      _settings = parsedSettings ?? const AppSettings();
    } finally {
      _loaded = true;
      notifyListeners();
    }
  }

  Future<void> updateDiagnosticsUrl(String diagnosticsUrl) async {
    final normalized = normalizeDiagnosticsUrl(diagnosticsUrl);
    await _mutateSettings(
      (current) => current.copyWith(diagnosticsUrl: normalized),
      accountScoped: true,
    );
  }

  /// Persist the non-secret identity returned by the control server so the
  /// account page remains useful after a restart and when profile loading is
  /// temporarily unavailable.
  Future<void> updateAccountIdentity({
    required String email,
    String? username,
  }) async {
    final normalizedEmail = email.trim().toLowerCase();
    final normalizedUsername = username?.trim();
    if (normalizedEmail.isEmpty &&
        (normalizedUsername == null || normalizedUsername.isEmpty)) {
      return;
    }
    await _mutateSettings(
      (current) => current.copyWith(
        accountEmail: normalizedEmail.isEmpty
            ? current.accountEmail
            : normalizedEmail,
        accountUsername: normalizedUsername ?? current.accountUsername,
      ),
      accountScoped: true,
    );
  }

  Future<void> updateConnectionSettings({
    required String diagnosticsUrl,
    required String controlServer,
    required String authToken,
    required String networkId,
    required String virtualIp,
    required String deviceName,
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
    if (normalizedControlServer.isEmpty) {
      throw const FormatException('请输入服务器地址并登录后才能使用 P2WLAN。');
    }
    final normalizedNetworkId = networkId.trim().isEmpty
        ? defaultNetworkId
        : networkId.trim();
    final normalizedSocketPool = normalizeSocketPool(socketPool);
    final enteredToken = authToken.trim();
    // A blank draft may retain a credential only for its existing server.
    // Publishing a different server with that token would immediately allow
    // profile and room requests to send it to the new destination.
    await _mutateSettings((current) {
      if (enteredToken.isEmpty &&
          current.authToken.trim().isNotEmpty &&
          normalizedControlServer !=
              normalizeControlServer(current.controlServer)) {
        throw const FormatException(
          'Changing servers requires a new credential. Sign in to the new server or enter its credential.',
        );
      }
      // Resolve a blank credential against the latest queued value, never a
      // snapshot captured before another settings write completed.
      return current.copyWith(
        diagnosticsUrl: normalizedDiagnosticsUrl,
        controlServer: normalizedControlServer,
        authToken: enteredToken.isNotEmpty ? enteredToken : current.authToken,
        networkId: normalizedNetworkId,
        virtualIp: virtualIp.trim(),
        deviceName: deviceName.trim(),
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
    }, accountScoped: true);
  }

  Future<void> updateSettings(AppSettings settings) {
    final expectedSession = accountSessionKey(_settings);
    Future<void> apply() {
      if (accountSessionKey(settings) == expectedSession &&
          accountSessionKey(_settings) != expectedSession) {
        throw const FormatException('账号已变化，未保存旧账号设置。请重新打开页面后操作。');
      }
      return _updateSettings(settings);
    }

    return _enqueueSettingsWrite(apply);
  }

  Future<void> _mutateSettings(
    AppSettings Function(AppSettings current) change, {
    bool accountScoped = false,
  }) {
    final expectedSession = accountSessionKey(_settings);
    return _enqueueSettingsWrite(() {
      if (accountScoped && accountSessionKey(_settings) != expectedSession) {
        throw const FormatException('账号已变化，未保存旧账号设置。请重新打开页面后操作。');
      }
      return _updateSettings(change(_settings));
    });
  }

  Future<void> _enqueueSettingsWrite(
    Future<void> Function() apply, {
    bool allowOwnerReentry = false,
  }) {
    // A macOS stop performed inside account transition can prompt and save
    // its machine credential. Queueing that callback behind its own caller
    // would deadlock; only that transaction's async context may reenter.
    if (allowOwnerReentry &&
        _activeWriteOwner != null &&
        identical(Zone.current[_writeOwnerKey], _activeWriteOwner)) {
      return apply();
    }
    Future<void> run() async {
      final owner = Object();
      _activeWriteOwner = owner;
      try {
        await runZoned(apply, zoneValues: {_writeOwnerKey: owner});
      } finally {
        _activeWriteOwner = null;
      }
    }

    final previousWrite = _pendingSettingsWrite;
    final write = previousWrite == null
        ? run()
        : previousWrite.then((_) => run());
    final tail = write.then<void>((_) {}, onError: (Object _, StackTrace _) {});
    _pendingSettingsWrite = tail;
    unawaited(
      tail.then((_) {
        if (identical(_pendingSettingsWrite, tail)) {
          _pendingSettingsWrite = null;
        }
      }),
    );
    return write;
  }

  Future<void> _updateSettings(AppSettings settings) async {
    final normalizedDeviceName = settings.deviceName.trim().isEmpty
        ? await resolveDefaultDeviceName()
        : settings.deviceName.trim();
    var normalizedSettings = settings.copyWith(
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
    final previous = _settings;
    final sessionChanged =
        accountSessionKey(previous) != accountSessionKey(normalizedSettings);
    if (sessionChanged) {
      if (isRoomNetwork(normalizedSettings.networkId)) {
        normalizedSettings = personalNetworkSettings(normalizedSettings);
      }
      normalizedSettings = normalizedSettings.copyWith(
        virtualIp: '',
        personalVirtualIp: '',
      );
    }
    Future<void> commit() async {
      if (_settings.macosAdminPassword != previous.macosAdminPassword ||
          _settings.macosAdminPasswordCiphertext !=
              previous.macosAdminPasswordCiphertext) {
        normalizedSettings = normalizedSettings.copyWith(
          macosAdminPassword: _settings.macosAdminPassword,
          macosAdminPasswordCiphertext: _settings.macosAdminPasswordCiphertext,
        );
      }
      await _save(normalizedSettings);
      _settings = normalizedSettings;
      notifyListeners();
    }

    final transition = applySessionChange;
    if (sessionChanged && transition != null) {
      await transition(previous, normalizedSettings, commit);
    } else {
      await commit();
    }
  }

  /// Encrypt and persist the macOS administrator password in the local
  /// settings file. The plaintext remains in memory only for daemon startup.
  Future<void> updateMacosAdminPassword(String password) async {
    if (password.isEmpty) {
      throw const FormatException('管理员密码不能为空。');
    }
    await _enqueueSettingsWrite(() async {
      final file = Platform.isAndroid
          ? await _settingsFile()
          : _settingsFileSync();
      final ciphertext = await LocalConfigSecret.encrypt(
        password,
        keyFile: _adminPasswordKeyFile(file),
      );
      await _updateSettings(
        _settings.copyWith(
          macosAdminPassword: password,
          macosAdminPasswordCiphertext: ciphertext,
        ),
      );
    }, allowOwnerReentry: true);
  }

  /// Forget the local macOS administrator credential without touching the
  /// P2WLAN login token or the rest of the settings.
  Future<void> clearMacosAdminPassword() => _enqueueSettingsWrite(
    () => _updateSettings(
      _settings.copyWith(
        macosAdminPassword: '',
        macosAdminPasswordCiphertext: '',
      ),
    ),
    allowOwnerReentry: true,
  );

  Future<void> updateLanguageCode(String languageCode) => _mutateSettings(
    (current) => current.copyWith(languageCode: languageCode),
  );

  Future<void> updateThemeMode(String themeMode) =>
      _mutateSettings((current) => current.copyWith(themeMode: themeMode));

  /// Persist that the local-node onboarding flow is complete. Idempotent.
  Future<void> markOnboardingCompleted() async {
    if (_settings.onboardingCompleted) return;
    await _mutateSettings(
      (current) => current.copyWith(onboardingCompleted: true),
      accountScoped: true,
    );
  }

  Future<void> resetDiagnosticsUrl() =>
      updateDiagnosticsUrl(defaultDiagnosticsUrl);

  Future<void> _save(AppSettings candidate) async {
    final previousToken = _settings.authToken;
    var credentialWritten = false;
    try {
      final file = Platform.isAndroid
          ? await _settingsFile()
          : _settingsFileSync();
      _configPath = file.path;
      // A blank token clears the local token file. Publish the candidate only
      // after both this protected store and the settings JSON have committed.
      await _tokenRepository.write(candidate.authToken);
      credentialWritten = true;
      await _writeSettingsFile(file, candidate: candidate);
      _lastError = null;
    } catch (error) {
      if (credentialWritten && candidate.authToken != previousToken) {
        try {
          await _tokenRepository.write(previousToken);
        } catch (restoreError) {
          Object? clearError;
          try {
            await _tokenRepository.clear();
          } catch (error) {
            clearError = error;
          }
          final failure = SettingsCredentialRestoreException(
            error,
            restoreError,
            clearError: clearError,
          );
          _lastError = failure.toString();
          throw failure;
        }
      }
      _lastError = 'Failed to save local settings: $error';
      rethrow;
    }
  }

  File _settingsFileSync() {
    final override = _settingsFileOverride;
    if (override != null) return override;
    final directory = _configDirectorySync();
    return File(
      '${directory.path}${Platform.pathSeparator}flutter-client-settings.json',
    );
  }

  Future<File> _settingsFile() async {
    final override = _settingsFileOverride;
    if (override != null) return override;
    final applicationSupport = await resolveApplicationSupportDirectory();
    if (applicationSupport == null) {
      throw StateError('Android application support directory is unavailable.');
    }
    return File(
      '${applicationSupport.path}${Platform.pathSeparator}flutter-client-settings.json',
    );
  }

  Future<File?> _settingsSourceFile(File preferredFile) async {
    if (await preferredFile.exists()) return preferredFile;
    final legacyFile = _legacySettingsFile();
    if (legacyFile != null && await legacyFile.exists()) return legacyFile;
    return null;
  }

  Future<void> _writeSettingsFile(File file, {AppSettings? candidate}) async {
    await file.parent.create(recursive: true);
    await _restrictDirectory(file.parent);
    // The auth token lives in the separate local token file, never in this
    // JSON, so it is always written blank. The macOS administrator password is
    // represented here only by authenticated ciphertext; its random key is in
    // the protected sidecar file next to this JSON.
    final temp = File(
      '${file.path}.${DateTime.now().microsecondsSinceEpoch}.tmp',
    );
    try {
      await temp.writeAsString(
        const JsonEncoder.withIndent('  ')
            .convert(_persistedSettings(candidate).toJson()),
        flush: true,
      );
      await _restrictFile(temp);
      try {
        await temp.rename(file.path);
      } on FileSystemException {
        // Dart cannot replace an existing file with rename on every Windows
        // filesystem. The temporary file is still fully flushed before this
        // narrow fallback, and it never contains credentials.
        if (await file.exists()) await file.delete();
        await temp.rename(file.path);
      }
      // rename preserves the permissions already set on the flushed temporary
      // file. Keep all fallible preparation before the commit point so an
      // error cannot roll back the token after the new JSON was installed.
    } finally {
      if (await temp.exists()) await temp.delete();
    }
  }

  /// Settings as they should be written to disk: the auth token and plaintext
  /// administrator password are blanked (only their protected stores remain).
  AppSettings _persistedSettings([AppSettings? source]) =>
      (source ?? _settings).copyWith(authToken: '', macosAdminPassword: '');

  File _adminPasswordKeyFile(File settingsFile) =>
      File('${settingsFile.path}.key');

  Future<void> _restrictDirectory(Directory directory) async {
    if (!Platform.isMacOS && !Platform.isLinux) return;
    // This is a tiny local metadata operation. Keep it synchronous so saves
    // initiated from Flutter test/fake-async callbacks cannot strand a
    // subprocess future outside the test event loop.
    final result = Process.runSync('/bin/chmod', ['700', directory.path]);
    if (result.exitCode != 0) {
      throw const SecureTokenStorageException('无法限制本地配置目录权限。');
    }
  }

  Future<void> _restrictFile(File file) async {
    if (!Platform.isMacOS && !Platform.isLinux) return;
    final result = Process.runSync('/bin/chmod', ['600', file.path]);
    if (result.exitCode != 0) {
      throw const SecureTokenStorageException('无法限制本地配置文件权限。');
    }
  }

  /// The token field in [json] blanked, for comparing persisted content.
  Map<String, dynamic> _stripToken(Map<String, dynamic> json) {
    final copy = Map<String, dynamic>.from(json);
    copy['authToken'] = '';
    return copy;
  }

  String _legacyToken(Map<String, dynamic> json, AppSettings loaded) {
    for (final key in const ['authToken', 'auth_token', 'token']) {
      final value = json[key];
      if (value is String && value.trim().isNotEmpty) return value.trim();
    }
    return loaded.authToken.trim();
  }

  bool _hasLegacyFields(Map<String, dynamic> json) {
    if (json.containsKey('manualMode') ||
        json.containsKey('personalManualMode')) {
      return true;
    }
    return json.containsKey('auth_token') ||
        json.containsKey('token') ||
        (json['authToken'] is String &&
            (json['authToken'] as String).trim().isNotEmpty);
  }

  File? _legacySettingsFile() {
    if (_settingsFileOverride != null) return null;
    if (Platform.isAndroid) {
      // Builds before the persistent storage bridge used systemTemp (the
      // Android cache directory). Migrate it when it is still available after
      // an update; future reads use Context.filesDir instead.
      return File(
        '${Directory.systemTemp.path}${Platform.pathSeparator}p2wlan${Platform.pathSeparator}flutter-client-settings.json',
      );
    }
    if (!Platform.isMacOS) return null;
    final home = Platform.environment['HOME'];
    if (home == null || home.isEmpty) return null;
    return File(
      '$home/Library/Application Support/p2wlan/flutter-client-settings.json',
    );
  }

  Directory _configDirectorySync() {
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
  final legacyPlaceholderControl =
      controlServer == legacyPlaceholderControlServer;
  final currentDeviceName = settings.deviceName.trim();
  var migrated = settings;
  if (controlServer == legacyControlServer || legacyPlaceholderControl) {
    // Known project defaults are cleared.  A localhost/custom address is
    // explicit user data and must survive migration.
    migrated = migrated.copyWith(controlServer: '');
  }
  if (_shouldReplaceDefaultDeviceName(currentDeviceName)) {
    migrated = migrated.copyWith(deviceName: await resolveDefaultDeviceName());
  }
  return migrated;
}

Future<String> resolveDefaultDeviceName() async {
  final candidates = <String>[
    if (Platform.isAndroid) (await resolveAndroidDeviceName()) ?? '',
    if (Platform.isMacOS) ...await _macosDeviceNameCandidates(),
    Platform.environment['COMPUTERNAME'] ?? '',
    Platform.environment['HOSTNAME'] ?? '',
    Platform.localHostname,
    'this-device',
  ];
  for (final candidate in candidates) {
    final normalized = _normalizeDeviceNameCandidate(candidate);
    if (normalized.isNotEmpty &&
        !_looksLikeIpAddress(normalized) &&
        !_looksLikePlaceholderDeviceName(normalized)) {
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
      _looksLikeIpAddress(normalized) ||
      _looksLikePlaceholderDeviceName(normalized);
}

bool _looksLikePlaceholderDeviceName(String value) {
  switch (value.trim().toLowerCase()) {
    case 'localhost':
    case 'localhost.localdomain':
    case 'android':
    case 'android device':
    case 'unknown':
    case 'device':
    case 'default':
    case 'emulator':
    case 'this-device':
      return true;
    default:
      return false;
  }
}

bool _looksLikeIpAddress(String value) {
  return InternetAddress.tryParse(value) != null ||
      RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(value);
}

String normalizeControlServer(String value) {
  final trimmed = value.trim();
  if (trimmed.isEmpty) return '';
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
  if (settings.deviceName.trim().isEmpty) {
    errors.add('Device name is required');
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
