import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import '../daemon/diagnostics_auth.dart';
import '../security/redactor.dart';

// Mobile log uploads must not make the Flutter UI hold several copies of a
// multi-megabyte, high-volume daemon log while it is being redacted and
// compressed. The tail is still large enough to include the recent failure
// timeline, while keeping Android memory pressure predictable.
const maxCurrentSessionLogBytesPerFile = 1 * 1024 * 1024;

class SessionLogFile {
  const SessionLogFile({required this.name, required this.content});

  final String name;
  final String content;
}

class CurrentSessionLogBundle {
  const CurrentSessionLogBundle({required this.files});

  final List<SessionLogFile> files;

  /// Collect the files from the platform-specific directory used by the
  /// running daemon. Android resolves this through the native Context because
  /// its private files directory is not exposed as a stable HOME path.
  static Future<CurrentSessionLogBundle> collectCurrentStartup({
    int maxBytesPerFile = maxCurrentSessionLogBytesPerFile,
  }) async {
    final directory = await resolveP2WlanLogDir();
    final separator = Platform.pathSeparator;
    // File reads and redaction are CPU/memory work from the UI's point of
    // view. Keep the platform channel lookup above on the main isolate, then
    // do the actual collection in a worker isolate.
    final serializedFiles = await Isolate.run(
      () => _collectCurrentStartupFiles(
        daemonLogPath: '${directory.path}${separator}p2wlan-daemon.log',
        clientLogPath: '${directory.path}${separator}p2wlan-client.log',
        maxBytesPerFile: maxBytesPerFile,
      ),
    );
    return CurrentSessionLogBundle(
      files: List.unmodifiable(
        serializedFiles.map(
          (file) =>
              SessionLogFile(name: file['name']!, content: file['content']!),
        ),
      ),
    );
  }

  /// Read only the two files that represent the current daemon startup.
  /// Rotated `.1` files are deliberately never consulted.
  static Future<CurrentSessionLogBundle> collect({
    required String daemonLogPath,
    required String clientLogPath,
    int maxBytesPerFile = maxCurrentSessionLogBytesPerFile,
    bool redactFiles = true,
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
      final rawContent = await _readCurrentFile(file, maxBytesPerFile);
      final content = redactFiles ? redactSensitive(rawContent) : rawContent;
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

Future<List<Map<String, String>>> _collectCurrentStartupFiles({
  required String daemonLogPath,
  required String clientLogPath,
  required int maxBytesPerFile,
}) async {
  final bundle = await CurrentSessionLogBundle.collect(
    daemonLogPath: daemonLogPath,
    clientLogPath: clientLogPath,
    maxBytesPerFile: maxBytesPerFile,
    // The upload encoder is the final redaction boundary. Keeping the file
    // raw here avoids doing the same expensive pass twice in worker isolates.
    redactFiles: false,
  );
  return bundle.files
      .map(
        (file) => <String, String>{'name': file.name, 'content': file.content},
      )
      .toList(growable: false);
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
