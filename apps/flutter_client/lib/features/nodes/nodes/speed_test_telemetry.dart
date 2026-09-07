part of '../nodes_page.dart';

class SpeedTestTelemetry extends ChangeNotifier {
  SpeedTestTelemetry({required this.maxSamples});

  final int maxSamples;
  final _samples = <SpeedTestPoint>[];
  var _publishedSamples = const <SpeedTestPoint>[];
  int? _runId;
  var _disposed = false;
  PeerSnapshot? _lastPeer;
  int? _lastSampleElapsedMs;
  double _currentDownloadMbps = 0;
  double _currentUploadMbps = 0;
  double _chartMaxMbps = 10;
  int _lastScaleEvaluationMs = 0;
  int _elapsedMs = 0;
  int _downloadBytes = 0;
  int _uploadBytes = 0;
  int? _rttMs;
  SpeedTestResult? result;

  List<SpeedTestPoint> get samples => _publishedSamples;
  double get currentDownloadMbps => _currentDownloadMbps;
  double get currentUploadMbps => _currentUploadMbps;
  double get chartMaxMbps => _chartMaxMbps;
  int get elapsedMs => _elapsedMs;
  int get downloadBytes => _downloadBytes;
  int get uploadBytes => _uploadBytes;
  int? get rttMs => _rttMs;
  double get averageDownloadMbps => _averageMbps(_downloadBytes);
  double get averageUploadMbps => _averageMbps(_uploadBytes);

  void reset({required int runId, required PeerSnapshot peer}) {
    if (_disposed) return;
    _runId = runId;
    _samples.clear();
    _lastPeer = null;
    _lastSampleElapsedMs = null;
    _currentDownloadMbps = 0;
    _currentUploadMbps = 0;
    _chartMaxMbps = 10;
    _lastScaleEvaluationMs = 0;
    _elapsedMs = 0;
    _downloadBytes = 0;
    _uploadBytes = 0;
    _rttMs = peer.latencyMs;
    result = null;
    _append(const SpeedTestPoint(elapsedMs: 0, downloadMbps: 0, uploadMbps: 0));
    _publish();
  }

  bool _accepts(int runId) => !_disposed && runId == _runId && result == null;

  void tick(Duration elapsed, {required int runId}) {
    if (!_accepts(runId)) return;
    final next = elapsed.inMilliseconds.clamp(0, 10000);
    if (next <= _elapsedMs) return;
    _elapsedMs = next;
    notifyListeners();
  }

  void recordPeer(PeerSnapshot peer, Duration elapsed, {required int runId}) {
    if (!_accepts(runId)) return;
    final rawElapsedMs = elapsed.inMilliseconds;
    if (rawElapsedMs < 0 ||
        (_lastSampleElapsedMs != null &&
            rawElapsedMs <= _lastSampleElapsedMs!)) {
      return;
    }
    final previous = _lastPeer;
    final interval = rawElapsedMs - (_lastSampleElapsedMs ?? rawElapsedMs);
    final samePeer =
        previous != null &&
        previous.nodeId == peer.nodeId &&
        previous.virtualIp == peer.virtualIp;
    final sentDelta = peer.bytesSent - (previous?.bytesSent ?? peer.bytesSent);
    final receivedDelta =
        peer.bytesReceived - (previous?.bytesReceived ?? peer.bytesReceived);
    _currentUploadMbps = 0;
    _currentDownloadMbps = 0;
    if (samePeer && interval > 0 && sentDelta >= 0 && receivedDelta >= 0) {
      _currentUploadMbps = _bytesToMbps(sentDelta, interval);
      _currentDownloadMbps = _bytesToMbps(receivedDelta, interval);
      _uploadBytes += sentDelta;
      _downloadBytes += receivedDelta;
    }
    _lastPeer = peer;
    _lastSampleElapsedMs = rawElapsedMs;
    _elapsedMs = rawElapsedMs.clamp(0, 10000);
    _rttMs = peer.latencyMs ?? _rttMs;
    _append(
      SpeedTestPoint(
        elapsedMs: _elapsedMs,
        downloadMbps: _currentDownloadMbps,
        uploadMbps: _currentUploadMbps,
      ),
    );
    _maybeExpandScale(rawElapsedMs);
    _publish();
  }

  void recordResult(
    SpeedTestResult value,
    int? fallbackRttMs, {
    required int runId,
  }) {
    if (_disposed || (_runId != null && runId != _runId)) return;
    _runId = runId;
    result = value;
    _elapsedMs = value.durationMs.clamp(0, 10000);
    _currentDownloadMbps = value.downloadMbps;
    _currentUploadMbps = value.uploadMbps;
    _downloadBytes = value.downloadBytes;
    _uploadBytes = value.uploadBytes;
    _rttMs ??= fallbackRttMs;
    _append(
      SpeedTestPoint(
        elapsedMs: _elapsedMs,
        downloadMbps: value.downloadMbps,
        uploadMbps: value.uploadMbps,
      ),
    );
    _maybeExpandScale(_elapsedMs, force: true);
    _publish();
  }

  double _averageMbps(int bytes) => _bytesToMbps(bytes, _elapsedMs);

  static double _bytesToMbps(int bytes, int elapsedMs) {
    if (bytes <= 0 || elapsedMs <= 0) return 0;
    return bytes * 8 * 1000 / (elapsedMs * 1000000);
  }

  void _append(SpeedTestPoint point) {
    final previous = _samples.isEmpty ? null : _samples.last;
    if (previous != null && point.elapsedMs <= previous.elapsedMs) {
      _samples[_samples.length - 1] = point;
      return;
    }
    _samples.add(point);
    if (_samples.length > maxSamples) _samples.removeAt(0);
  }

  void _maybeExpandScale(int elapsedMs, {bool force = false}) {
    final peak = _samples.fold<double>(
      0,
      (maximum, sample) =>
          math.max(maximum, math.max(sample.downloadMbps, sample.uploadMbps)),
    );
    if (!peak.isFinite || peak <= 0) return;
    if (!force &&
        elapsedMs - _lastScaleEvaluationMs < 500 &&
        peak < _chartMaxMbps * 0.85) {
      return;
    }
    final target = _niceScale(peak);
    if (target > _chartMaxMbps) _chartMaxMbps = target;
    _lastScaleEvaluationMs = elapsedMs;
  }

  static double _niceScale(double value) {
    if (!value.isFinite || value <= 0) return 10;
    final magnitude = math
        .pow(10, (math.log(value) / math.ln10).floor())
        .toDouble();
    final normalized = value / magnitude;
    final step = normalized <= 1
        ? 1
        : normalized <= 2
        ? 2
        : normalized <= 5
        ? 5
        : 10;
    return math.max(1, step * magnitude);
  }

  void _publish() {
    if (_disposed) return;
    _publishedSamples = List.unmodifiable(_samples);
    notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }
}
