import 'dart:convert';
import 'dart:io';

import '../security/redactor.dart';

const maxCurrentSessionLogBytesPerFile = 8 * 1024 * 1024;

class SessionLogFile {
  const SessionLogFile({required this.name, required this.content});

  final String name;
  final String content;
}

class CurrentSessionLogBundle {
  const CurrentSessionLogBundle({required this.files});

  final List<SessionLogFile> files;

  /// Read only the two files that represent the current daemon startup.
  /// Rotated `.1` files are deliberately never consulted.
  static Future<CurrentSessionLogBundle> collect({
    required String daemonLogPath,
    required String clientLogPath,
    int maxBytesPerFile = maxCurrentSessionLogBytesPerFile,
  }) async {
    final candidates = <({String name, String path})>[
      (name: 'p2wlan-daemon.log', path: daemonLogPath),
      (name: 'p2wlan-client.log', path: clientLogPath),
    ];
    final files = <SessionLogFile>[];
    final seenPaths = <String>{};
    for (final candidate in candidates) {
      final normalizedPath = candidate.path.trim();
      if (normalizedPath.isEmpty || !seenPaths.add(normalizedPath)) continue;
      final file = File(normalizedPath);
      if (!await file.exists()) continue;
      final content = redactSensitive(
        await _readCurrentFile(file, maxBytesPerFile),
      );
      if (content.trim().isEmpty) continue;
      files.add(SessionLogFile(name: candidate.name, content: content));
    }
    if (files.isEmpty) {
      throw const FileSystemException(
        'No current startup log files were found.',
      );
    }
    return CurrentSessionLogBundle(files: List.unmodifiable(files));
  }
}

Future<String> _readCurrentFile(File file, int maxBytes) async {
  if (maxBytes <= 0) {
    throw ArgumentError('maxBytes must be positive');
  }
  final length = await file.length();
  final truncated = length > maxBytes;
  final start = truncated ? length - maxBytes : 0;
  final bytes = <int>[];
  await for (final chunk in file.openRead(start)) {
    bytes.addAll(chunk);
  }
  final decoded = utf8.decode(bytes, allowMalformed: true);
  if (!truncated) return decoded;
  return '[p2wlan] current startup log exceeded $maxBytes bytes; '
      'showing its tail only.\n$decoded';
}
