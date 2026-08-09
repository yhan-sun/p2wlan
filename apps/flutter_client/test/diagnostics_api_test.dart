import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';

void main() {
  group('normalizeDiagnosticsUrl', () {
    test('keeps the diagnostics default status URL', () {
      expect(
        normalizeDiagnosticsUrl(defaultDiagnosticsUrl),
        defaultDiagnosticsUrl,
      );
    });

    test('trims whitespace and adds /status when no path is provided', () {
      expect(
        normalizeDiagnosticsUrl('  http://127.0.0.1:39277  '),
        'http://127.0.0.1:39277/status',
      );
    });

    test('normalizes root path to /status', () {
      expect(
        normalizeDiagnosticsUrl('http://localhost:39277/'),
        'http://localhost:39277/status',
      );
    });

    test('preserves an explicit status path and query', () {
      expect(
        normalizeDiagnosticsUrl('http://localhost:39277/status?probe=1'),
        'http://localhost:39277/status?probe=1',
      );
    });

    test('allows https loopback-compatible URLs for future IPC hardening', () {
      expect(
        normalizeDiagnosticsUrl('https://localhost:39277/status'),
        'https://localhost:39277/status',
      );
    });

    test('rejects diagnostics endpoints that would expose local control', () {
      expect(
        () => normalizeDiagnosticsUrl('http://0.0.0.0:39277/status'),
        throwsFormatException,
      );
      expect(
        () => normalizeDiagnosticsUrl('http://192.0.2.12:39277/status'),
        throwsFormatException,
      );
    });

    test('rejects missing URL, unsupported scheme, and missing host', () {
      expect(() => normalizeDiagnosticsUrl(''), throwsFormatException);
      expect(
        () => normalizeDiagnosticsUrl('ws://127.0.0.1:39277/status'),
        throwsFormatException,
      );
      expect(
        () => normalizeDiagnosticsUrl('http:///status'),
        throwsFormatException,
      );
    });
  });
}
