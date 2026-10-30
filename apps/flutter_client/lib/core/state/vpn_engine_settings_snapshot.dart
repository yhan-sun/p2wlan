import 'dart:convert';
import 'dart:io';

import '../models/diagnostics_models.dart';

const int vpnEngineSettingsSchemaVersion = 1;
const int vpnEngineSettingsMaxBytes = 64 * 1024;
const int _maxSafeRevision = 9007199254740991;

const Set<String> _settingsFields = {
  'controlServer',
  'authToken',
  'networkId',
  'manualMode',
  'virtualIp',
  'deviceName',
  'overlayCidr',
  'tunInterface',
  'mtu',
  'udpBind',
  'udpAdvertise',
  'socketPool',
  'relayServers',
};

/// Stable, path-free failures for the local snapshot consumed by the VPN
/// extension. Never include snapshot contents or filesystem paths here.
class VpnEngineSettingsSnapshotException implements Exception {
  const VpnEngineSettingsSnapshotException(this.code);

  final String code;

  @override
  String toString() => code;
}

abstract interface class VpnEngineSettingsSnapshotWriter {
  /// Atomically publishes one complete settings/token revision and returns it.
  Future<int> publish(AppSettings settings);
}

/// Produces the versioned engine input from the same in-memory settings and
/// token that SettingsStore persists. The token is intentionally written only
/// to the app-private file; it never crosses a MethodChannel or a Want.
Map<String, Object?> vpnEngineSettingsValues(AppSettings settings) {
  final token = settings.authToken.trim();
  return <String, Object?>{
    'controlServer': settings.controlServer.trim(),
    'authToken': token,
    'networkId': settings.networkId.trim().isEmpty
        ? defaultNetworkId
        : settings.networkId.trim(),
    // The app no longer exposes manual/offline mode. Keep the field in the
    // versioned Native schema, but never revive it from legacy settings.
    'manualMode': false,
    'virtualIp': settings.virtualIp.trim(),
    'deviceName': settings.deviceName.trim(),
    'overlayCidr': settings.overlayCidr.trim().isEmpty
        ? defaultOverlayCidr
        : settings.overlayCidr.trim(),
    'tunInterface': settings.effectiveTunInterface,
    'mtu': settings.mtu,
    'udpBind': settings.udpBind.trim().isEmpty
        ? defaultUdpBind
        : settings.udpBind.trim(),
    'udpAdvertise': settings.udpAdvertise.trim(),
    // Keep the existing daemon CLI semantics and carry its value into the
    // native config instead of silently dropping the user's socket-pool mode.
    'socketPool': settings.socketPool.trim(),
    // Rust's current CLI splits this input on commas and trims each endpoint.
    'relayServers': _relayServerList(settings.relayServers),
  };
}

bool vpnEngineSettingsCanStart(Map<String, Object?> settings) {
  if (settings['manualMode'] == true) return true;
  final token = settings['authToken'];
  return token is String && token.trim().isNotEmpty;
}

bool vpnEngineSettingsEqual(AppSettings left, AppSettings right) =>
    jsonEncode(vpnEngineSettingsValues(left)) ==
    jsonEncode(vpnEngineSettingsValues(right));

List<String> _relayServerList(String value) => value
    .split(',')
    .map((server) => server.trim())
    .where((server) => server.isNotEmpty)
    .toList(growable: false);

/// App-private, same-directory atomic file writer for
/// `filesDir/p2wlan/vpn-engine-settings-v1.json`.
class FileVpnEngineSettingsSnapshotWriter
    implements VpnEngineSettingsSnapshotWriter {
  FileVpnEngineSettingsSnapshotWriter({required this.file});

  final File file;
  static int _temporaryFileSequence = 0;

  @override
  Future<int> publish(AppSettings appSettings) async {
    final values = vpnEngineSettingsValues(appSettings);
    _validateSettings(values);

    final previous = await _readCurrent();
    final revision = previous == null
        ? 1
        : _sameSettings(previous.settings, values)
        ? previous.revision
        : previous.revision + 1;
    if (revision > _maxSafeRevision || revision <= 0) {
      throw const VpnEngineSettingsSnapshotException(
        'VPN_ENGINE_SETTINGS_SNAPSHOT_REVISION_INVALID',
      );
    }

    final snapshot = <String, Object?>{
      'schemaVersion': vpnEngineSettingsSchemaVersion,
      'revision': revision,
      'settings': values,
    };
    final encoded = jsonEncode(snapshot);
    if (utf8.encode(encoded).length > vpnEngineSettingsMaxBytes) {
      throw const VpnEngineSettingsSnapshotException(
        'VPN_ENGINE_SETTINGS_SNAPSHOT_TOO_LARGE',
      );
    }

    if (previous != null && previous.revision == revision) return revision;
    await _writeAtomically(encoded);
    return revision;
  }

  Future<_ParsedVpnEngineSnapshot?> _readCurrent() async {
    try {
      if (!await file.exists()) return null;
      if (await file.length() > vpnEngineSettingsMaxBytes) {
        throw const VpnEngineSettingsSnapshotException(
          'VPN_ENGINE_SETTINGS_SNAPSHOT_TOO_LARGE',
        );
      }
      final decoded = jsonDecode(await file.readAsString());
      if (decoded is! Map<String, dynamic> ||
          !_hasExactKeys(decoded, const {
            'schemaVersion',
            'revision',
            'settings',
          })) {
        throw const VpnEngineSettingsSnapshotException(
          'VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID',
        );
      }
      final schemaVersion = decoded['schemaVersion'];
      final revision = decoded['revision'];
      final settings = decoded['settings'];
      if (schemaVersion != vpnEngineSettingsSchemaVersion ||
          revision is! int ||
          revision <= 0 ||
          revision > _maxSafeRevision ||
          settings is! Map<String, dynamic>) {
        throw const VpnEngineSettingsSnapshotException(
          'VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID',
        );
      }
      _validateSettings(settings);
      return _ParsedVpnEngineSnapshot(revision: revision, settings: settings);
    } on VpnEngineSettingsSnapshotException {
      rethrow;
    } catch (_) {
      throw const VpnEngineSettingsSnapshotException(
        'VPN_ENGINE_SETTINGS_SNAPSHOT_READ_FAILED',
      );
    }
  }

  Future<void> _writeAtomically(String encoded) async {
    final sequence = _temporaryFileSequence++;
    final temp = File(
      '${file.path}.${DateTime.now().microsecondsSinceEpoch}.$sequence.tmp',
    );
    try {
      await file.parent.create(recursive: true);
      await temp.writeAsString(encoded, encoding: utf8, flush: true);
      // The temp file is a sibling, so HarmonyOS POSIX rename replaces the
      // destination atomically. Do not delete the old snapshot as a fallback.
      await temp.rename(file.path);
    } catch (_) {
      throw const VpnEngineSettingsSnapshotException(
        'VPN_ENGINE_SETTINGS_SNAPSHOT_WRITE_FAILED',
      );
    } finally {
      try {
        if (await temp.exists()) await temp.delete();
      } catch (_) {
        // A leftover temp file is never read by the VPN extension.
      }
    }
  }

  static bool _sameSettings(
    Map<String, dynamic> left,
    Map<String, Object?> right,
  ) {
    if (left.length != right.length || !_hasExactKeys(left, _settingsFields)) {
      return false;
    }
    for (final key in _settingsFields) {
      if (jsonEncode(left[key]) != jsonEncode(right[key])) return false;
    }
    return true;
  }

  static void _validateSettings(Map<Object?, Object?> settings) {
    if (!_hasExactKeys(settings, _settingsFields) ||
        settings['controlServer'] is! String ||
        settings['authToken'] is! String ||
        settings['networkId'] is! String ||
        settings['manualMode'] is! bool ||
        settings['virtualIp'] is! String ||
        settings['deviceName'] is! String ||
        settings['overlayCidr'] is! String ||
        settings['tunInterface'] is! String ||
        settings['mtu'] is! int ||
        settings['udpBind'] is! String ||
        settings['udpAdvertise'] is! String ||
        settings['socketPool'] is! String) {
      throw const VpnEngineSettingsSnapshotException(
        'VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID',
      );
    }
    final relays = settings['relayServers'];
    if (relays is! List<Object?> || relays.any((value) => value is! String)) {
      throw const VpnEngineSettingsSnapshotException(
        'VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID',
      );
    }
  }

  static bool _hasExactKeys(
    Map<Object?, Object?> value,
    Set<String> expected,
  ) =>
      value.length == expected.length &&
      value.keys.every((key) => key is String && expected.contains(key));
}

class _ParsedVpnEngineSnapshot {
  const _ParsedVpnEngineSnapshot({
    required this.revision,
    required this.settings,
  });

  final int revision;
  final Map<String, dynamic> settings;
}
