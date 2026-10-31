import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';

import '../models/diagnostics_models.dart';
import '../platform/native_platform.dart';
import '../presentation/network_overview.dart';
import '../presentation/traffic_statistics.dart';
import '../rooms/room_api.dart';

class TrafficHistorySummary {
  const TrafficHistorySummary({
    required this.counters,
    required this.startedAt,
    required this.updatedAt,
  });

  final TrafficCounters counters;
  final DateTime startedAt;
  final DateTime updatedAt;
}

/// Locally observed diagnostic IP bytes, with checkpoints committed together
/// with totals. This owns no network state, requests, or polling lifecycle.
class TrafficHistoryStore extends ChangeNotifier {
  TrafficHistoryStore({
    File? file,
    this.persistent = true,
    DateTime Function()? now,
  }) : _storageFile = file,
       _now = now ?? DateTime.now;

  static const maxRecords = 4096;
  static const maxFileBytes = 2 * 1024 * 1024;
  static const saveDelay = Duration(seconds: 2);

  File? _storageFile;
  final bool persistent;
  final DateTime Function() _now;
  var _records = <String, _HistoryRecord>{};
  bool _loaded = false;
  bool _loading = false;
  bool _dirty = false;
  bool _capacityExceeded = false;
  bool _disposed = false;
  String? _error;
  Future<void>? _loadFuture;
  Future<void>? _writer;
  Timer? _saveTimer;

  bool get loaded => _loaded;
  bool get loading => _loading;
  bool get dirty => _dirty;
  bool get saving => _writer != null;
  String? get error =>
      _error ?? (_capacityExceeded ? 'traffic_history_capacity' : null);

  Future<void> load() {
    if (_disposed || _loaded) return Future<void>.value();
    return _loadFuture ??= _load().whenComplete(() => _loadFuture = null);
  }

  Future<void> _load() async {
    _loading = true;
    _error = null;
    _notify();
    try {
      var records = <String, _HistoryRecord>{};
      var capacityExceeded = false;
      if (persistent) {
        final file = _storageFile ??= await _defaultFile();
        if (await file.exists()) {
          if (await file.length() > maxFileBytes) throw const FormatException();
          final bytes = await file
              .openRead(0, maxFileBytes + 1)
              .fold<List<int>>([], (result, chunk) => result..addAll(chunk));
          if (bytes.length > maxFileBytes) throw const FormatException();
          final decoded = _decode(utf8.decode(bytes));
          records = decoded.records;
          capacityExceeded = decoded.capacityReached;
        }
      }
      if (_disposed) return;
      _records = records;
      _capacityExceeded = capacityExceeded;
      _loaded = true;
    } catch (_) {
      if (!_disposed) _error = 'traffic_history_load_failed';
    } finally {
      _loading = false;
      _notify();
    }
  }

  void observe({
    required AppSettings settings,
    required Iterable<NetworkScopeSnapshot> scopes,
  }) {
    if (_disposed || !_loaded || _loading) return;
    final account = _accountKey(settings);
    if (account == null) return;
    final next = Map<String, _HistoryRecord>.of(_records);
    final seen = <String>{};
    var changed = false;
    final at = max(0, _now().toUtc().millisecondsSinceEpoch);
    try {
      for (final scope in scopes) {
        final snapshot = scope.snapshot;
        if (!scope.isRunning ||
            snapshot == null ||
            snapshot.peerSnapshotStale ||
            snapshot.capturedRevision != snapshot.revision ||
            snapshot.stats.totalPeers != snapshot.peers.length ||
            snapshot.nodeId.trim().isEmpty ||
            snapshot.networkId.trim().isEmpty ||
            (!scope.isPrimary && scope.roomId != snapshot.networkId)) {
          continue;
        }
        final network = _hash(snapshot.networkId.trim());
        final local = _hash(snapshot.nodeId.trim());
        for (final item in scope.peers) {
          final peer = item.peer;
          final sent = peer.reportedBytesSent;
          final received = peer.reportedBytesReceived;
          if (!item.current ||
              peer.nodeId.trim().isEmpty ||
              sent == null ||
              received == null ||
              sent < 0 ||
              received < 0) {
            continue;
          }
          final remote = _hash(peer.nodeId.trim());
          final key = _recordKey(account, network, local, remote);
          if (!seen.add(key)) continue;
          final old = next[key];
          if (old == null && next.length >= maxRecords) {
            throw const FormatException();
          }
          final checkpoint = _Checkpoint.fromSnapshot(snapshot, sent, received);
          final record = old == null
              ? _HistoryRecord(
                  account: account,
                  network: network,
                  local: local,
                  remote: remote,
                  upload: 0,
                  download: 0,
                  started: at,
                  updated: at,
                  highestEpoch: checkpoint.epoch ?? 0,
                  checkpoint: checkpoint,
                )
              : old.advance(checkpoint, at);
          if (!identical(record, old)) {
            next[key] = record;
            changed = true;
          }
        }
      }
      if (!changed) return;
      _checkTotals(next);
      if (next.length > maxRecords ||
          utf8.encode(_encode(next, _capacityExceeded)).length > maxFileBytes) {
        _capacityFailure();
        return;
      }
    } on FormatException {
      _capacityFailure();
      return;
    }
    _records = next;
    _dirty = persistent;
    _scheduleSave();
    _notify();
  }

  void _capacityFailure() {
    _capacityExceeded = true;
    _dirty = persistent;
    _scheduleSave();
    _notify();
  }

  TrafficHistorySummary? summary({
    required AppSettings settings,
    String? networkId,
    String? peerId,
  }) {
    if (!_loaded) return null;
    final account = _accountKey(settings);
    if (account == null) return null;
    final network = networkId == null ? null : _hash(networkId.trim());
    final remote = peerId == null ? null : _hash(peerId.trim());
    final rows = _records.values.where(
      (row) =>
          row.account == account &&
          (network == null || row.network == network) &&
          (remote == null || row.remote == remote),
    );
    if (rows.isEmpty) return null;
    var sent = 0;
    var received = 0;
    var started = rows.first.started;
    var updated = rows.first.updated;
    for (final row in rows) {
      sent = _add(sent, row.upload);
      received = _add(received, row.download);
      started = min(started, row.started);
      updated = max(updated, row.updated);
    }
    return TrafficHistorySummary(
      counters: TrafficCounters(uploadBytes: sent, downloadBytes: received),
      startedAt: DateTime.fromMillisecondsSinceEpoch(started, isUtc: true),
      updatedAt: DateTime.fromMillisecondsSinceEpoch(updated, isUtc: true),
    );
  }

  void _scheduleSave() {
    if (!persistent || _writer != null || _saveTimer != null || _disposed) {
      return;
    }
    _saveTimer = Timer(saveDelay, () {
      _saveTimer = null;
      unawaited(flush());
    });
  }

  Future<void> flush() {
    _saveTimer?.cancel();
    _saveTimer = null;
    if (_writer case final writer?) return writer;
    if (_disposed || !_loaded || !_dirty || !persistent) {
      return Future<void>.value();
    }
    final completer = Completer<void>();
    _writer = completer.future;
    unawaited(_write(completer));
    return completer.future;
  }

  Future<void> _write(Completer<void> completer) async {
    try {
      do {
        _dirty = false;
        final content = _encode(_records, _capacityExceeded);
        try {
          final file = _storageFile ??= await _defaultFile();
          await _atomicWrite(file, content);
          if (_error == 'traffic_history_save_failed') _error = null;
        } catch (_) {
          _dirty = true;
          _error = 'traffic_history_save_failed';
          break;
        }
      } while (_dirty && !_disposed);
    } finally {
      _writer = null;
      completer.complete();
      _notify();
    }
  }

  void _notify() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    _saveTimer?.cancel();
    _saveTimer = null;
    super.dispose();
  }
}

class _Checkpoint {
  const _Checkpoint({
    required this.epoch,
    required this.weak,
    required this.uptime,
    required this.revision,
    required this.sent,
    required this.received,
    this.observed = true,
  });

  factory _Checkpoint.fromSnapshot(
    DiagnosticsSnapshot snapshot,
    int sent,
    int received,
  ) {
    final timeline = snapshot.raw['connection_timeline'];
    final correlation = timeline is Map ? timeline['correlation_id'] : null;
    final prefix = snapshot.nodeId.substring(0, min(8, snapshot.nodeId.length));
    final match = correlation is String
        ? RegExp('^${RegExp.escape(prefix)}-([0-9a-f]+)\$')
              .firstMatch(correlation)
        : null;
    final epoch = match == null ? null : int.tryParse(match[1]!, radix: 16);
    return _Checkpoint(
      epoch: epoch != null && epoch > 0 ? epoch : null,
      weak: _hash(
        jsonEncode([snapshot.processId, snapshot.runtimeIncarnation]),
      ),
      uptime: max(0, snapshot.uptimeMs),
      revision: max(0, snapshot.revision),
      sent: sent,
      received: received,
    );
  }

  final int? epoch;
  final String weak;
  final int uptime;
  final int revision;
  final int sent;
  final int received;
  final bool observed;

  _Checkpoint unverified() => _Checkpoint(
    epoch: epoch,
    weak: weak,
    uptime: uptime,
    revision: revision,
    sent: sent,
    received: received,
    observed: false,
  );

  bool sameValues(_Checkpoint other) =>
      epoch == other.epoch &&
      weak == other.weak &&
      uptime == other.uptime &&
      revision == other.revision &&
      sent == other.sent &&
      received == other.received;

  Map<String, Object?> toJson() => {
    'epoch': epoch,
    'weak': weak,
    'uptime': uptime,
    'revision': revision,
    'sent': sent,
    'received': received,
  };

  factory _Checkpoint.fromJson(Map<String, dynamic> value) => _Checkpoint(
    epoch: value['epoch'] == null ? null : _number(value['epoch']),
    weak: _digest(value['weak']),
    uptime: _number(value['uptime']),
    revision: _number(value['revision']),
    sent: _number(value['sent']),
    received: _number(value['received']),
    observed: false,
  );
}

class _HistoryRecord {
  const _HistoryRecord({
    required this.account,
    required this.network,
    required this.local,
    required this.remote,
    required this.upload,
    required this.download,
    required this.started,
    required this.updated,
    required this.highestEpoch,
    required this.checkpoint,
  });

  final String account;
  final String network;
  final String local;
  final String remote;
  final int upload;
  final int download;
  final int started;
  final int updated;
  final int highestEpoch;
  final _Checkpoint checkpoint;

  _HistoryRecord advance(_Checkpoint next, int at) {
    final epoch = next.epoch;
    if (epoch != null && epoch < highestEpoch) return this;
    if (checkpoint.observed && checkpoint.sameValues(next)) return this;
    final sameStrong = epoch != null && epoch == checkpoint.epoch;
    if (sameStrong &&
        (next.revision < checkpoint.revision ||
            next.uptime < checkpoint.uptime)) {
      return this;
    }
    final sameWeak =
        epoch == null &&
        checkpoint.epoch == null &&
        checkpoint.observed &&
        next.weak == checkpoint.weak &&
        next.uptime >= checkpoint.uptime &&
        next.revision >= checkpoint.revision;
    final newStrong = epoch != null && epoch > highestEpoch;
    if ((sameStrong || sameWeak) &&
        next.revision == checkpoint.revision &&
        next.uptime == checkpoint.uptime &&
        (next.sent < checkpoint.sent || next.received < checkpoint.received)) {
      return this;
    }
    // An unidentifiable restart and a delayed weak snapshot cannot be told
    // apart. Re-prime the following sample too, rather than count a rebound.
    final weakRegression =
        epoch == null &&
        checkpoint.epoch == null &&
        checkpoint.observed &&
        next.weak == checkpoint.weak &&
        (next.uptime < checkpoint.uptime ||
            next.revision < checkpoint.revision);
    final recordReset =
        (sameStrong || sameWeak) &&
        (next.sent < checkpoint.sent || next.received < checkpoint.received);
    int delta(int value, int previous) => newStrong || recordReset
        ? value
        : sameStrong || sameWeak
        ? value - previous
        : 0;
    return _HistoryRecord(
      account: account,
      network: network,
      local: local,
      remote: remote,
      upload: _add(upload, delta(next.sent, checkpoint.sent)),
      download: _add(download, delta(next.received, checkpoint.received)),
      started: started,
      updated: max(at, updated),
      highestEpoch: max(highestEpoch, epoch ?? 0),
      checkpoint: weakRegression ? next.unverified() : next,
    );
  }

  Map<String, Object?> toJson() => {
    'account': account,
    'network': network,
    'local': local,
    'remote': remote,
    'upload': upload,
    'download': download,
    'started': started,
    'updated': updated,
    'highest_epoch': highestEpoch,
    'checkpoint': checkpoint.toJson(),
  };

  factory _HistoryRecord.fromJson(Map<String, dynamic> value) {
    final record = _HistoryRecord(
      account: _digest(value['account']),
      network: _digest(value['network']),
      local: _digest(value['local']),
      remote: _digest(value['remote']),
      upload: _number(value['upload']),
      download: _number(value['download']),
      started: _number(value['started']),
      updated: _number(value['updated']),
      highestEpoch: _number(value['highest_epoch']),
      checkpoint: _Checkpoint.fromJson(
        Map<String, dynamic>.from(value['checkpoint'] as Map),
      ),
    );
    if (record.updated > 8640000000000000 ||
        record.updated < record.started ||
        record.highestEpoch < (record.checkpoint.epoch ?? 0)) {
      throw const FormatException();
    }
    return record;
  }
}

String? _accountKey(AppSettings settings) {
  try {
    final token = settings.authToken.split('.');
    if (token.length != 3) return null;
    final payload = jsonDecode(
      utf8.decode(base64Url.decode(base64Url.normalize(token[1]))),
    );
    final user = payload is Map ? payload['user_id'] : null;
    if (user is! String || user.isEmpty || user.length > 256) return null;
    return _hash(jsonEncode([roomControlServer(settings.controlServer), user]));
  } catch (_) {
    return null;
  }
}

String _hash(String value) => sha256.convert(utf8.encode(value)).toString();
String _recordKey(
  String account,
  String network,
  String local,
  String remote,
) => _hash(jsonEncode([account, network, local, remote]));

int _number(dynamic value) {
  if (value is! int || value < 0) throw const FormatException();
  return value;
}

String _digest(dynamic value) {
  if (value is! String || !RegExp(r'^[a-f0-9]{64}$').hasMatch(value)) {
    throw const FormatException();
  }
  return value;
}

int _add(int current, int increment) {
  if (increment < 0 || increment > 0x7fffffffffffffff - current) {
    throw const FormatException();
  }
  return current + increment;
}

String _encode(Map<String, _HistoryRecord> records, bool capacityReached) =>
    jsonEncode({
      'version': 1,
      'capacity_reached': capacityReached,
      'records': [for (final record in records.values) record.toJson()],
    });

({Map<String, _HistoryRecord> records, bool capacityReached}) _decode(
  String content,
) {
  final value = jsonDecode(content);
  if (value is! Map || value['version'] != 1 || value['records'] is! List) {
    throw const FormatException();
  }
  final rows = value['records'] as List;
  final capacity = value['capacity_reached'];
  if (value.containsKey('capacity_reached') && capacity is! bool) {
    throw const FormatException();
  }
  if (rows.length > TrafficHistoryStore.maxRecords) {
    throw const FormatException();
  }
  final records = <String, _HistoryRecord>{};
  for (final value in rows) {
    final record = _HistoryRecord.fromJson(
      Map<String, dynamic>.from(value as Map),
    );
    final key = _recordKey(
      record.account,
      record.network,
      record.local,
      record.remote,
    );
    if (records.containsKey(key)) throw const FormatException();
    records[key] = record;
  }
  _checkTotals(records);
  return (records: records, capacityReached: capacity == true);
}

void _checkTotals(Map<String, _HistoryRecord> records) {
  var upload = 0;
  var download = 0;
  for (final row in records.values) {
    upload = _add(upload, row.upload);
    download = _add(download, row.download);
  }
  _add(upload, download);
}

Future<void> _atomicWrite(File file, String content) async {
  await file.parent.create(recursive: true);
  final suffix = Random.secure().nextInt(1 << 32).toRadixString(16);
  final temporary = File('${file.path}.tmp-$suffix');
  try {
    await temporary.writeAsString(content, flush: true);
    if (Platform.isMacOS || Platform.isLinux) {
      final result = await Process.run('/bin/chmod', ['600', temporary.path]);
      if (result.exitCode != 0) {
        throw const FileSystemException('Cannot protect traffic history');
      }
    }
    await temporary.rename(file.path);
  } finally {
    if (await temporary.exists()) await temporary.delete();
  }
}

Future<File> _defaultFile() async {
  Directory? directory;
  if (usesNativeApplicationSupportDirectory) {
    directory = await resolveApplicationSupportDirectory();
  } else {
    final home = Platform.environment['HOME'];
    final appData = Platform.environment['APPDATA'];
    final xdg = Platform.environment['XDG_CONFIG_HOME'];
    if (Platform.isMacOS && home != null && home.isNotEmpty) {
      directory = Directory('$home/Library/Application Support/p2wlan-client');
    } else if (Platform.isWindows && appData != null && appData.isNotEmpty) {
      directory = Directory('$appData/p2wlan');
    } else if (xdg != null && xdg.isNotEmpty) {
      directory = Directory('$xdg/p2wlan');
    } else if (home != null && home.isNotEmpty) {
      directory = Directory('$home/.config/p2wlan');
    }
  }
  if (directory == null) {
    throw const FileSystemException('No persistent history directory');
  }
  return File('${directory.path}${Platform.pathSeparator}traffic-history.json');
}
