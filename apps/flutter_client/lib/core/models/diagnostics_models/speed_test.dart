part of '../diagnostics_models.dart';

class SpeedTestResult {
  SpeedTestResult({
    required this.peerVirtualIp,
    required this.durationMs,
    required this.downloadMbps,
    required this.uploadMbps,
    required this.downloadBytes,
    required this.uploadBytes,
  });

  final String peerVirtualIp;
  final int durationMs;
  final double downloadMbps;
  final double uploadMbps;
  final int downloadBytes;
  final int uploadBytes;

  factory SpeedTestResult.fromJson(JsonMap json) {
    return SpeedTestResult(
      peerVirtualIp: _string(json['peer_virtual_ip']),
      durationMs: _int(json['duration_ms']),
      downloadMbps: _double(json['download_mbps']),
      uploadMbps: _double(json['upload_mbps']),
      downloadBytes: _int(json['download_bytes']),
      uploadBytes: _int(json['upload_bytes']),
    );
  }
}
