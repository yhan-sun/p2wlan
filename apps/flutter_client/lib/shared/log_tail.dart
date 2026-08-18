// Bounded tail reads for large files (daemon logs). Reading an entire log via
// `readAsLines()` makes peak memory proportional to file size; these helpers
// read only a bounded trailing window so a 100 MB log previews with the same
// memory cost as a small one.

import 'dart:convert';
import 'dart:io';

/// Read at most [maxBytes] from the end of [file] and return the last [lines]
/// complete lines, joined by `\n`. Memory is bounded by [maxBytes], never the
/// file size. A possibly-partial first line at the truncation boundary is
/// dropped. Returns `''` for a missing/empty file.
Future<String> tailLines(
  File file, {
  int lines = 120,
  int maxBytes = 256 * 1024,
}) async {
  if (!await file.exists()) return '';
  final raf = await file.open();
  List<int> chunk;
  int start;
  try {
    final end = await raf.length();
    if (end == 0) return '';
    start = end > maxBytes ? end - maxBytes : 0;
    await raf.setPosition(start);
    chunk = await raf.read(end - start);
  } finally {
    raf.closeSync();
  }
  // allowMalformed: a byte boundary can split a UTF-8 character; for a log
  // tail preview we'd rather show something than throw.
  final text = utf8.decode(chunk, allowMalformed: true);
  var allLines = text.split('\n');
  if (start > 0 && allLines.isNotEmpty) {
    // The first line was cut mid-line at the byte boundary; drop it.
    allLines.removeAt(0);
  }
  if (allLines.isNotEmpty && allLines.last.isEmpty) {
    // A trailing newline in the file should not count as a blank line.
    allLines.removeLast();
  }
  if (allLines.length > lines) {
    allLines.removeRange(0, allLines.length - lines);
  }
  return allLines.join('\n');
}
