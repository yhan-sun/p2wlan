import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/presentation/traffic_statistics.dart';
import 'package:p2wlan_flutter_client/shared/formatters.dart';

void main() {
  test(
    'missing or malformed byte counters stay unknown, explicit zero stays zero',
    () {
      for (final value in [null, -1, 'invalid', 1.5, double.infinity, true]) {
        final peer = PeerSnapshot.fromJson({
          'bytes_sent': value,
          'bytes_received': 0,
        });
        expect(TrafficCounters.fromPeer(peer).uploadBytes, isNull);
        expect(TrafficCounters.fromPeer(peer).downloadBytes, 0);
        expect(TrafficCounters.fromPeer(peer).totalBytes, isNull);
        final snapshot = DiagnosticsSnapshot.fromJson({
          'stats': {'total_bytes_sent': value, 'total_bytes_received': 0},
          'uptime_ms': value,
        });
        expect(TrafficCounters.fromSnapshot(snapshot).uploadBytes, isNull);
        expect(snapshot.reportedUptimeMs, isNull);
      }
      for (final value in [0, '0', 0.0]) {
        final snapshot = DiagnosticsSnapshot.fromJson({
          'stats': {'total_bytes_sent': value, 'total_bytes_received': value},
          'uptime_ms': value,
        });
        expect(TrafficCounters.fromSnapshot(snapshot).totalBytes, 0);
        expect(snapshot.reportedUptimeMs, 0);
      }
    },
  );

  test('aggregation never presents partial or absent totals as complete', () {
    expect(TrafficCounters.combine([]).totalBytes, isNull);
    final incomplete = TrafficCounters.combine([
      const TrafficCounters(uploadBytes: 1024, downloadBytes: 2048),
      const TrafficCounters(uploadBytes: 512),
    ]);
    expect(incomplete.uploadBytes, 1536);
    expect(incomplete.downloadBytes, isNull);
    expect(incomplete.totalBytes, isNull);
    expect(
      TrafficCounters.combine([
        const TrafficCounters(uploadBytes: 1024, downloadBytes: 2048),
        const TrafficCounters(uploadBytes: 512, downloadBytes: 512),
      ]).totalBytes,
      4096,
    );
  });

  test('history byte units and elapsed time remain readable at boundaries', () {
    expect(formatOptionalBytes(null), '—');
    expect(formatOptionalBytes(-1), '—');
    expect(formatOptionalBytes(0), '0 B');
    expect(formatBytes(1 << 40), '1.0 TB');
    expect(formatBytes(1 << 50), '1.0 PB');
    expect(formatElapsedTime(null), '—');
    expect(formatElapsedTime(-1), '—');
    expect(formatElapsedTime(0), '0s');
    expect(formatElapsedTime(59999), '59s');
    expect(formatElapsedTime(60000), '1m 0s');
    expect(formatElapsedTime(3600000), '1h 0m');
    expect(formatElapsedTime(90000000, isZh: true), '1 天 1 小时');
  });
}
