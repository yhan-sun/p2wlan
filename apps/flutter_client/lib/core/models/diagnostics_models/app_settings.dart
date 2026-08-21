part of '../diagnostics_models.dart';

const defaultDiagnosticsUrl = 'http://127.0.0.1:39277/status';
const legacyControlServer = 'https://control.p2wlan.io';
const legacyPlaceholderControlServer = 'http://control.example.com:18080';
const defaultControlServer = String.fromEnvironment(
  'P2WLAN_DEFAULT_CONTROL_SERVER',
  defaultValue: 'http://47.109.40.237:18080',
);
const defaultNetworkId = 'default';
const defaultLanguageCode = 'zh-Hans';
const defaultOverlayCidr = '10.20.0.0/16';
const defaultMtu = 1420;
const defaultUdpBind = '0.0.0.0:0';
const defaultSocketPool = '3';
const defaultCloseBehavior = 'keep-running';

/// Return whether a JWT-shaped user token is expired.
///
/// This is only a local UX guard; the control server remains authoritative.
/// Opaque/manual credentials and malformed tokens are left alone so custom
/// deployments are not rejected before the server can validate them.
bool isAuthTokenExpired(String token, {DateTime? now}) {
  final parts = token.trim().split('.');
  if (parts.length != 3) return false;
  try {
    final payload = jsonDecode(
      utf8.decode(base64Url.decode(base64Url.normalize(parts[1]))),
    );
    if (payload is! Map<String, dynamic>) return false;
    final exp = payload['exp'];
    if (exp is! num) return false;
    final expiresAt = DateTime.fromMillisecondsSinceEpoch(
      (exp * 1000).round(),
      isUtc: true,
    );
    final reference = (now ?? DateTime.now()).toUtc();
    return !expiresAt.isAfter(reference.add(const Duration(seconds: 30)));
  } catch (_) {
    return false;
  }
}

String get defaultTunInterface => Platform.isWindows ? 'p2wlan' : 'p2wlan0';

typedef JsonMap = Map<String, dynamic>;

enum AppThemeMode {
  system('system'),
  light('light'),
  dark('dark');

  const AppThemeMode(this.code);
  final String code;

  static AppThemeMode fromCode(String? code) {
    final normalized = (code ?? 'system').trim().toLowerCase();
    return switch (normalized) {
      'light' => light,
      'dark' => dark,
      _ => system,
    };
  }
}

enum AppLanguage {
  english('en'),
  simplifiedChinese('zh-Hans');

  const AppLanguage(this.code);

  final String code;

  static AppLanguage fromCode(String? code) {
    final trimmed = code?.trim();
    final normalized =
        (trimmed == null || trimmed.isEmpty ? defaultLanguageCode : trimmed)
            .replaceAll('_', '-')
            .toLowerCase();
    return switch (normalized) {
      'zh' || 'zh-cn' || 'zh-hans' || 'zh-hans-cn' => simplifiedChinese,
      _ => english,
    };
  }
}

class AppSettings {
  const AppSettings({
    this.diagnosticsUrl = defaultDiagnosticsUrl,
    this.controlServer = defaultControlServer,
    this.authToken = '',
    this.networkId = defaultNetworkId,
    this.virtualIp = '',
    this.deviceName = '',
    this.manualMode = false,
    this.overlayCidr = defaultOverlayCidr,
    this.tunInterface = '',
    this.mtu = defaultMtu,
    this.udpBind = defaultUdpBind,
    this.udpAdvertise = '',
    this.socketPool = defaultSocketPool,
    this.relayServers = '',
    this.closeBehavior = defaultCloseBehavior,
    this.languageCode = defaultLanguageCode,
    this.themeMode = 'system',
    this.onboardingCompleted = false,
  });

  final String diagnosticsUrl;
  final String controlServer;
  final String authToken;
  final String networkId;
  final String virtualIp;
  final String deviceName;
  final bool manualMode;
  final String overlayCidr;
  final String tunInterface;
  final int mtu;
  final String udpBind;
  final String udpAdvertise;
  final String socketPool;
  final String relayServers;
  final String closeBehavior;
  final String languageCode;
  final String themeMode;

  /// Whether the local-node onboarding flow has been completed on this device.
  /// Persisted so a restart resumes at the shell rather than re-running
  /// first-run. Managed-mode users who have never signed in see it as false.
  final bool onboardingCompleted;

  String get effectiveTunInterface {
    final trimmed = tunInterface.trim();
    return trimmed.isEmpty ? defaultTunInterface : trimmed;
  }

  AppSettings copyWith({
    String? diagnosticsUrl,
    String? controlServer,
    String? authToken,
    String? networkId,
    String? virtualIp,
    String? deviceName,
    bool? manualMode,
    String? overlayCidr,
    String? tunInterface,
    int? mtu,
    String? udpBind,
    String? udpAdvertise,
    String? socketPool,
    String? relayServers,
    String? closeBehavior,
    String? languageCode,
    String? themeMode,
    bool? onboardingCompleted,
  }) {
    return AppSettings(
      diagnosticsUrl: diagnosticsUrl ?? this.diagnosticsUrl,
      controlServer: controlServer ?? this.controlServer,
      authToken: authToken ?? this.authToken,
      networkId: networkId ?? this.networkId,
      virtualIp: virtualIp ?? this.virtualIp,
      deviceName: deviceName ?? this.deviceName,
      manualMode: manualMode ?? this.manualMode,
      overlayCidr: overlayCidr ?? this.overlayCidr,
      tunInterface: tunInterface ?? this.tunInterface,
      mtu: mtu ?? this.mtu,
      udpBind: udpBind ?? this.udpBind,
      udpAdvertise: udpAdvertise ?? this.udpAdvertise,
      socketPool: socketPool ?? this.socketPool,
      relayServers: relayServers ?? this.relayServers,
      closeBehavior: _normalizeCloseBehavior(
        closeBehavior ?? this.closeBehavior,
      ),
      languageCode: languageCode == null
          ? this.languageCode
          : AppLanguage.fromCode(languageCode).code,
      themeMode: themeMode == null
          ? this.themeMode
          : AppThemeMode.fromCode(themeMode).code,
      onboardingCompleted: onboardingCompleted ?? this.onboardingCompleted,
    );
  }

  factory AppSettings.fromJson(JsonMap json) {
    return AppSettings(
      diagnosticsUrl: _string(json['diagnosticsUrl'], defaultDiagnosticsUrl),
      controlServer: _string(json['controlServer'], defaultControlServer),
      authToken: _string(json['authToken']),
      networkId: _string(json['networkId'], defaultNetworkId),
      virtualIp: _string(json['virtualIp']),
      deviceName: _string(json['deviceName']),
      manualMode: _bool(json['manualMode']),
      overlayCidr: _string(json['overlayCidr'], defaultOverlayCidr),
      tunInterface: _string(json['tunInterface'], defaultTunInterface),
      mtu: _int(json['mtu'], defaultMtu),
      udpBind: _string(json['udpBind'], defaultUdpBind),
      udpAdvertise: _string(json['udpAdvertise']),
      socketPool: _normalizeSocketPool(
        _string(json['socketPool'], defaultSocketPool),
      ),
      relayServers: _string(json['relayServers']),
      closeBehavior: _normalizeCloseBehavior(
        _string(json['closeBehavior'], defaultCloseBehavior),
      ),
      languageCode: AppLanguage.fromCode(
        json.containsKey('languageCode') ? _string(json['languageCode']) : null,
      ).code,
      themeMode: AppThemeMode.fromCode(_string(json['themeMode'])).code,
      onboardingCompleted: _bool(json['onboardingCompleted']),
    );
  }

  JsonMap toJson() => {
    'diagnosticsUrl': diagnosticsUrl,
    'controlServer': controlServer,
    'authToken': authToken,
    'networkId': networkId,
    'virtualIp': virtualIp,
    'deviceName': deviceName,
    'manualMode': manualMode,
    'overlayCidr': overlayCidr,
    'tunInterface': effectiveTunInterface,
    'mtu': mtu,
    'udpBind': udpBind,
    'udpAdvertise': udpAdvertise,
    'socketPool': _normalizeSocketPool(socketPool),
    'relayServers': relayServers,
    'closeBehavior': _normalizeCloseBehavior(closeBehavior),
    'languageCode': languageCode,
    'themeMode': themeMode,
    'onboardingCompleted': onboardingCompleted,
  };
}

String _normalizeCloseBehavior(String value) {
  final normalized = value.trim();
  if (normalized == 'stop-and-quit' || normalized == 'keep-running') {
    return normalized;
  }
  return defaultCloseBehavior;
}

String _normalizeSocketPool(String value) {
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
