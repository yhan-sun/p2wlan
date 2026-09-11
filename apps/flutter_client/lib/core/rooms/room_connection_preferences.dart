import 'dart:convert';
import 'dart:io';

import '../daemon/diagnostics_auth.dart';

class RoomConnectionPreference {
  const RoomConnectionPreference({
    this.autoConnect = false,
    this.wanted = false,
    this.diagnosticsPort,
  });
  final bool autoConnect;
  final bool wanted;
  final int? diagnosticsPort;
}

/// Local installation only. Profile IDs scope preferences to server/account/room.
/// Logout and app shutdown stop processes without opting other devices in/out.
class RoomConnectionPreferences {
  RoomConnectionPreferences({
    this.persistent = false,
    Directory Function(String)? directoryForProfile,
  }) : _directoryForProfile = directoryForProfile ?? roomRuntimeDirectory;
  final bool persistent;
  final Directory Function(String) _directoryForProfile;
  final _values = <String, RoomConnectionPreference>{};
  final _writes = <String, Future<void>>{};

  Future<RoomConnectionPreference> read(String profile) async {
    await _writes[profile];
    if (_values.containsKey(profile)) return _values[profile]!;
    if (persistent) {
      final file = File(
        '${_directoryForProfile(profile).path}/connection.json',
      );
      if (await file.exists()) {
        final json = jsonDecode(await file.readAsString()) as Map;
        return _values[profile] = RoomConnectionPreference(
          autoConnect: json['auto_connect'] == true,
          wanted: json['wanted'] == true,
          diagnosticsPort: _storedPort(json['diagnostics_port']),
        );
      }
    }
    return const RoomConnectionPreference();
  }

  Future<void> update(
    String profile, {
    bool? autoConnect,
    bool? wanted,
    int? diagnosticsPort,
  }) {
    if (diagnosticsPort != null &&
        (diagnosticsPort < 40000 || diagnosticsPort >= 60000)) {
      throw ArgumentError.value(diagnosticsPort, 'diagnosticsPort');
    }
    final previous = _writes[profile];
    final next = () async {
      await previous;
      // Do not call read here: it would wait for this very write.
      var old = _values[profile];
      if (old == null && persistent) {
        final file = File(
          '${_directoryForProfile(profile).path}/connection.json',
        );
        if (await file.exists()) {
          final json = jsonDecode(await file.readAsString()) as Map;
          old = RoomConnectionPreference(
            autoConnect: json['auto_connect'] == true,
            wanted: json['wanted'] == true,
            diagnosticsPort: _storedPort(json['diagnostics_port']),
          );
        }
      }
      old ??= const RoomConnectionPreference();
      final value = RoomConnectionPreference(
        autoConnect: autoConnect ?? old.autoConnect,
        wanted: wanted ?? old.wanted,
        diagnosticsPort: diagnosticsPort ?? old.diagnosticsPort,
      );
      if (persistent) {
        final dir = _directoryForProfile(profile);
        await dir.create(recursive: true);
        final temp = File('${dir.path}/connection.json.tmp');
        await temp.writeAsString(
          jsonEncode({
            'auto_connect': value.autoConnect,
            'wanted': value.wanted,
            if (value.diagnosticsPort != null)
              'diagnostics_port': value.diagnosticsPort,
          }),
          flush: true,
        );
        await temp.rename('${dir.path}/connection.json');
      }
      _values[profile] = value;
    }();
    _writes[profile] = next;
    return next.whenComplete(() {
      if (identical(_writes[profile], next)) _writes.remove(profile);
    });
  }
}

int? _storedPort(Object? value) {
  if (value == null) return null;
  if (value is! int || value < 40000 || value >= 60000) {
    throw const FormatException('Invalid room diagnostics port');
  }
  return value;
}
