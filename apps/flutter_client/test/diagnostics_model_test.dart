import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/features/diagnostics/diagnostics_model.dart';

void main() {
  final strings = AppStrings.fromCode('en');

  Future<DiagnosticsSnapshot> loadFixture() async {
    final raw = await File('test/fixtures/status_connected.json')
        .readAsString();
    return DiagnosticsSnapshot.fromJson(
      jsonDecode(raw) as Map<String, dynamic>,
    );
  }

  DiagnosticsSnapshot mutate(
    DiagnosticsSnapshot snapshot,
    Map<String, dynamic> Function(Map<String, dynamic> raw) mutate,
  ) {
    final raw = jsonDecode(jsonEncode(snapshot.raw)) as Map<String, dynamic>;
    return DiagnosticsSnapshot.fromJson(mutate(raw));
  }

  Map<String, dynamic> clearPeerErrors(Map<String, dynamic> raw) {
    for (final peer in raw['peers'] as List<dynamic>) {
      (peer as Map<String, dynamic>)['direct']['last_error'] = null;
    }
    return raw;
  }

  DiagnosticsModel build({
    bool healthReachable = true,
    bool statusReachable = true,
    bool snapshotStale = false,
    DiagnosticsSnapshot? snapshot,
  }) {
    return buildDiagnosticsModel(
      strings: strings,
      healthReachable: healthReachable,
      statusReachable: statusReachable,
      snapshotStale: snapshotStale,
      snapshot: snapshot,
    );
  }

  group('buildDiagnosticsModel — overall state', () {
    test('healthy when nothing needs attention', () async {
      final snapshot = mutate(
        await loadFixture(),
        (raw) => clearPeerErrors(raw),
      );
      final model = build(snapshot: snapshot);
      expect(model.overall, DiagnosticOverall.healthy);
      expect(model.issues, isEmpty);
      expect(model.checks, hasLength(3));
    });

    test('stale when snapshot is old and no worse issue exists', () async {
      final snapshot = mutate(
        await loadFixture(),
        (raw) => clearPeerErrors(raw),
      );
      final model = build(snapshot: snapshot, snapshotStale: true);
      expect(model.overall, DiagnosticOverall.stale);
      expect(model.issues.single.kind, DiagnosticIssueKind.stale);
    });

    test('service unavailable when health and snapshot are gone', () async {
      final model = build(healthReachable: false, snapshot: null);
      expect(model.overall, DiagnosticOverall.unavailable);
      expect(model.issues.single.kind, DiagnosticIssueKind.serviceUnavailable);
    });

    test('status unavailable when health reachable but no snapshot', () async {
      final model = build(healthReachable: true, snapshot: null);
      expect(model.overall, DiagnosticOverall.attention);
      expect(model.issues.single.kind, DiagnosticIssueKind.statusUnavailable);
    });

    test('bad issue outranks staleness', () async {
      final snapshot = mutate(await loadFixture(), (raw) {
        raw['health']['reauth_required'] = true;
        return raw;
      });
      final model = build(snapshot: snapshot, snapshotStale: true);
      // The stale hero must never win over a real bad issue: attention wins,
      // even though the stale warning stays in the issues list.
      expect(model.overall, DiagnosticOverall.attention);
      expect(
        model.issues.map((i) => i.kind),
        contains(DiagnosticIssueKind.reauthRequired),
      );
    });
  });

  group('buildDiagnosticsModel — issue kinds', () {
    test('control disconnected maps to a plain explanation kind', () async {
      final snapshot = mutate(await loadFixture(), (raw) {
        raw['health']['control_connected'] = false;
        return raw;
      });
      final model = build(snapshot: snapshot);
      expect(
        model.issues.map((i) => i.kind),
        contains(DiagnosticIssueKind.controlDisconnected),
      );
    });

    test('reauth maps to reauthRequired', () async {
      final snapshot = mutate(await loadFixture(), (raw) {
        raw['health']['reauth_required'] = true;
        return raw;
      });
      final model = build(snapshot: snapshot);
      expect(
        model.issues.map((i) => i.kind),
        contains(DiagnosticIssueKind.reauthRequired),
      );
    });

    test('degraded service status maps to serviceHealth', () async {
      final snapshot = mutate(await loadFixture(), (raw) {
        raw['health']['status'] = 'degraded';
        return raw;
      });
      final model = build(snapshot: snapshot);
      expect(
        model.issues.map((i) => i.kind),
        contains(DiagnosticIssueKind.serviceHealth),
      );
    });

    test(
      'failing critical task maps to criticalTask and is redacted',
      () async {
        final snapshot = mutate(await loadFixture(), (raw) {
          (raw['health']['critical_tasks'] as List<dynamic>)[0]['error'] =
              'SocketException: token=SUPER_SECRET';
          return raw;
        });
        final model = build(snapshot: snapshot);
        final task = model.issues.firstWhere(
          (i) => i.kind == DiagnosticIssueKind.criticalTask,
        );
        expect(task.technicalDetail, isNotNull);
        expect(task.technicalDetail, isNot(contains('SUPER_SECRET')));
        expect(task.technicalDetail, contains('<redacted>'));
      },
    );

    test('relay error maps to relay with redacted technical detail', () async {
      final snapshot = mutate(await loadFixture(), (raw) {
        (raw['relay_selection'] as Map<String, dynamic>)['last_error'] =
            'relay down: ticket=SUPER_SECRET';
        return raw;
      });
      final model = build(snapshot: snapshot);
      final relay = model.issues.firstWhere(
        (i) => i.kind == DiagnosticIssueKind.relay,
      );
      expect(relay.technicalDetail, isNotNull);
      expect(relay.technicalDetail, isNot(contains('SUPER_SECRET')));
    });

    test('peer path warning maps to peerPath', () async {
      final snapshot = mutate(await loadFixture(), (raw) {
        (raw['peers'] as List<dynamic>)[0]['direct']['last_error'] = 'stale';
        return raw;
      });
      final model = build(snapshot: snapshot);
      expect(
        model.issues.map((i) => i.kind),
        contains(DiagnosticIssueKind.peerPath),
      );
    });
  });

  group('issue ordering', () {
    test('issues never include a healthy placeholder', () async {
      final snapshot = mutate(
        await loadFixture(),
        (raw) => clearPeerErrors(raw),
      );
      final model = build(snapshot: snapshot);
      expect(model.issues, isEmpty);
    });
  });
}
