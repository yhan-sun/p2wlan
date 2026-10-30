import '../models/diagnostics_models.dart';

/// Read-only counters from the current retained connection records. These are
/// diagnostic IP-byte observations, not physical-link or billing counters.
class TrafficCounters {
  const TrafficCounters({this.uploadBytes, this.downloadBytes});

  factory TrafficCounters.fromPeer(PeerSnapshot peer) => TrafficCounters(
    uploadBytes: peer.reportedBytesSent,
    downloadBytes: peer.reportedBytesReceived,
  );

  factory TrafficCounters.fromSnapshot(DiagnosticsSnapshot snapshot) =>
      TrafficCounters(
        uploadBytes: snapshot.stats.reportedBytesSent,
        downloadBytes: snapshot.stats.reportedBytesReceived,
      );

  factory TrafficCounters.combine(Iterable<TrafficCounters> values) {
    final items = values.toList(growable: false);
    if (items.isEmpty) return const TrafficCounters();
    return TrafficCounters(
      uploadBytes: items.every((item) => item.uploadBytes != null)
          ? items.fold(0, (sum, item) => sum! + item.uploadBytes!)
          : null,
      downloadBytes: items.every((item) => item.downloadBytes != null)
          ? items.fold(0, (sum, item) => sum! + item.downloadBytes!)
          : null,
    );
  }

  final int? uploadBytes;
  final int? downloadBytes;
  bool get hasData => uploadBytes != null || downloadBytes != null;
  int? get totalBytes => uploadBytes == null || downloadBytes == null
      ? null
      : uploadBytes! + downloadBytes!;
}
