/// Presentation layer for the Diagnostics page.
///
/// This file is deliberately UI-free: it derives the user-facing overall
/// state, health checks, and actionable issues from the raw `StatusStore`
/// facts. Widgets only render these values; unit tests can assert semantics
/// directly.
library;

import '../../app/app_strings.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/security/redactor.dart';

enum DiagnosticSeverity { good, warning, bad, neutral }

/// Lightweight presentation-level issue category. Drives the *safe* action a
/// user issue can offer (recheck, open devices, open settings) without
/// inventing an "auto fix" that has no real backend operation behind it.
enum DiagnosticIssueKind {
  /// Snapshot older than the freshness window → recheck.
  stale,

  /// Health endpoint unreachable, no snapshot → recheck.
  serviceUnavailable,

  /// Health reachable but status unavailable → recheck.
  statusUnavailable,

  /// Control plane requires a fresh credential → open settings.
  reauthRequired,

  /// Service reports a non-healthy status → explanation only.
  serviceHealth,

  /// A critical background task is failing → explanation only.
  criticalTask,

  /// Control plane disconnected → explanation only.
  controlDisconnected,

  /// Relay path failing → explanation only.
  relay,

  /// One or more peer paths need review → open devices.
  peerPath,
}

class DiagnosticCheck {
  const DiagnosticCheck({
    required this.title,
    required this.value,
    required this.severity,
    this.detail,
  });

  final String title;
  final String value;
  final DiagnosticSeverity severity;
  final String? detail;
}

class DiagnosticIssue {
  const DiagnosticIssue({
    required this.title,
    required this.detail,
    required this.severity,
    this.kind = DiagnosticIssueKind.serviceHealth,
    this.technicalDetail,
  });

  final String title;
  final String detail;
  final DiagnosticSeverity severity;

  /// Presentation category that selects a safe, real action (or none).
  final DiagnosticIssueKind kind;

  /// Redacted technical detail, shown only in the advanced section.
  final String? technicalDetail;
}

enum DiagnosticOverall { healthy, attention, unavailable, stale }

class DiagnosticsModel {
  const DiagnosticsModel({
    required this.overall,
    required this.title,
    required this.detail,
    required this.checks,
    required this.issues,
  });

  final DiagnosticOverall overall;
  final String title;
  final String detail;
  final List<DiagnosticCheck> checks;
  final List<DiagnosticIssue> issues;
}

/// Builds the complete user-facing diagnostics model from store facts.
///
/// State rules (never inferred from virtual IP / peer counts / relay alone),
/// evaluated in priority order:
///  - unavailable: no snapshot and the health endpoint is unreachable;
///  - attention (bad): any bad actionable issue (reauth, fatal task, ...)
///    outranks staleness so it is never hidden behind a stale banner;
///  - stale: an existing snapshot is older than the freshness window;
///  - attention: any remaining actionable issue (control plane disconnected,
///    status unavailable, path warnings, ...);
///  - healthy: nothing needs the user's attention.
DiagnosticsModel buildDiagnosticsModel({
  required AppStrings strings,
  required bool healthReachable,
  required bool statusReachable,
  required bool snapshotStale,
  required DiagnosticsSnapshot? snapshot,
}) {
  final checks = _buildChecks(
    strings: strings,
    healthReachable: healthReachable,
    snapshot: snapshot,
  );
  final issues = _buildIssues(
    strings: strings,
    healthReachable: healthReachable,
    statusReachable: statusReachable,
    snapshotStale: snapshotStale,
    snapshot: snapshot,
  );

  final DiagnosticOverall overall;
  if (!healthReachable && snapshot == null) {
    overall = DiagnosticOverall.unavailable;
  } else if (issues.any((issue) => issue.severity == DiagnosticSeverity.bad)) {
    // Actionable bad issues outrank staleness: reauth / fatal task etc. must
    // surface as "needs attention", never be hidden behind a stale banner.
    overall = DiagnosticOverall.attention;
  } else if (snapshotStale && snapshot != null) {
    overall = DiagnosticOverall.stale;
  } else if (issues.isNotEmpty) {
    overall = DiagnosticOverall.attention;
  } else {
    overall = DiagnosticOverall.healthy;
  }

  final (title, detail) = switch (overall) {
    DiagnosticOverall.healthy => (
      strings.overviewHealthyTitle,
      strings.overviewHealthyDetail,
    ),
    DiagnosticOverall.attention => (
      strings.overviewAttentionTitle,
      strings.overviewAttentionDetail,
    ),
    DiagnosticOverall.unavailable => (
      strings.overviewUnavailableTitle,
      strings.overviewUnavailableDetail,
    ),
    DiagnosticOverall.stale => (
      strings.overviewStaleTitle,
      strings.overviewStaleDetail,
    ),
  };

  return DiagnosticsModel(
    overall: overall,
    title: title,
    detail: detail,
    checks: checks,
    issues: issues,
  );
}

List<DiagnosticCheck> _buildChecks({
  required AppStrings strings,
  required bool healthReachable,
  required DiagnosticsSnapshot? snapshot,
}) {
  if (snapshot == null && !healthReachable) return const [];

  // Without a status snapshot we only know the health endpoint is reachable,
  // which is a fact, not "running normally": label it as such.
  final health = snapshot?.health;
  final serviceCheck = health == null
      ? DiagnosticCheck(
          title: strings.p2wlanService,
          value: !healthReachable ? strings.unavailable : strings.reachable,
          severity: !healthReachable
              ? DiagnosticSeverity.bad
              : DiagnosticSeverity.neutral,
        )
      : health.status.toLowerCase() == 'healthy'
      ? DiagnosticCheck(
          title: strings.p2wlanService,
          value: strings.runningNormally,
          severity: DiagnosticSeverity.good,
        )
      : DiagnosticCheck(
          title: strings.p2wlanService,
          value: strings.needsAction,
          severity: _fatalServiceStatus(health.status)
              ? DiagnosticSeverity.bad
              : DiagnosticSeverity.warning,
        );

  final controlCheck = snapshot == null
      ? DiagnosticCheck(
          title: strings.controlService,
          value: '—',
          severity: DiagnosticSeverity.neutral,
        )
      : health!.reauthRequired
      ? DiagnosticCheck(
          title: strings.controlService,
          value: strings.issueReauthTitle,
          severity: DiagnosticSeverity.bad,
        )
      : health.controlConnected
      ? DiagnosticCheck(
          title: strings.controlService,
          value: strings.connected,
          severity: DiagnosticSeverity.good,
        )
      : DiagnosticCheck(
          title: strings.controlService,
          value: strings.notConnected,
          severity: DiagnosticSeverity.warning,
        );

  final peers = snapshot?.peers ?? const <PeerSnapshot>[];
  final online = peers.where((peer) => peer.online).length;
  final pathWarnings = peers.where((peer) => peer.lastError != null).length;
  final devicesCheck = snapshot == null
      ? DiagnosticCheck(
          title: strings.deviceConnections,
          value: '—',
          severity: DiagnosticSeverity.neutral,
        )
      : peers.isEmpty
      ? DiagnosticCheck(
          title: strings.deviceConnections,
          value: strings.noOnlineDevices,
          severity: DiagnosticSeverity.neutral,
        )
      : pathWarnings > 0
      ? DiagnosticCheck(
          title: strings.deviceConnections,
          value: strings.devicesOnlineNeedsCheck(online, pathWarnings),
          severity: DiagnosticSeverity.warning,
        )
      : DiagnosticCheck(
          title: strings.deviceConnections,
          value: strings.devicesOnlineOk(online),
          severity: DiagnosticSeverity.good,
        );

  return [serviceCheck, controlCheck, devicesCheck];
}

List<DiagnosticIssue> _buildIssues({
  required AppStrings strings,
  required bool healthReachable,
  required bool statusReachable,
  required bool snapshotStale,
  required DiagnosticsSnapshot? snapshot,
}) {
  final issues = <DiagnosticIssue>[];

  if (snapshotStale && snapshot != null) {
    issues.add(
      DiagnosticIssue(
        title: strings.issueStaleDetail,
        detail: strings.staleSnapshotMessage,
        severity: DiagnosticSeverity.warning,
        kind: DiagnosticIssueKind.stale,
      ),
    );
  }

  if (!healthReachable && snapshot == null) {
    issues.add(
      DiagnosticIssue(
        title: strings.issueCannotReachService,
        detail: strings.issueCannotReachServiceDetail,
        severity: DiagnosticSeverity.bad,
        kind: DiagnosticIssueKind.serviceUnavailable,
      ),
    );
    return issues;
  }

  if (healthReachable && snapshot == null) {
    issues.add(
      DiagnosticIssue(
        title: strings.issueStatusUnavailableTitle,
        detail: strings.issueStatusUnavailableDetail,
        severity: DiagnosticSeverity.warning,
        kind: DiagnosticIssueKind.statusUnavailable,
      ),
    );
    return issues;
  }

  final health = snapshot!.health;

  if (health.reauthRequired) {
    issues.add(
      DiagnosticIssue(
        title: strings.issueReauthTitle,
        detail: strings.issueReauthDetail,
        severity: DiagnosticSeverity.bad,
        kind: DiagnosticIssueKind.reauthRequired,
        technicalDetail: _redactedReason(health),
      ),
    );
  }

  final serviceStatus = health.status.trim().toLowerCase();
  if (serviceStatus != 'healthy' && serviceStatus.isNotEmpty) {
    issues.add(
      DiagnosticIssue(
        title: strings.issueServiceStatusTitle,
        detail: strings.issueServiceStatusDetail,
        severity: _fatalServiceStatus(health.status)
            ? DiagnosticSeverity.bad
            : DiagnosticSeverity.warning,
        kind: DiagnosticIssueKind.serviceHealth,
        technicalDetail: _redactedReason(health),
      ),
    );
  }

  final failedTasks = health.criticalTasks
      .where((task) => task.error != null)
      .toList();
  if (failedTasks.isNotEmpty) {
    issues.add(
      DiagnosticIssue(
        title: strings.issueCriticalTaskTitle,
        detail: strings.issueCriticalTaskDetail,
        severity: DiagnosticSeverity.bad,
        kind: DiagnosticIssueKind.criticalTask,
        technicalDetail: failedTasks
            .map((task) => '${task.name}: ${redactSensitive(task.error!)}')
            .join('\n'),
      ),
    );
  }

  if (!health.controlConnected) {
    issues.add(
      DiagnosticIssue(
        title: strings.issueControlServerTitle,
        detail: strings.issueControlServerDetail,
        severity: DiagnosticSeverity.warning,
        kind: DiagnosticIssueKind.controlDisconnected,
      ),
    );
  }

  final relayError = snapshot.relaySelection.lastError?.trim();
  if (relayError != null && relayError.isNotEmpty) {
    issues.add(
      DiagnosticIssue(
        title: strings.issueRelayTitle,
        detail: strings.issueRelayDetail,
        severity: DiagnosticSeverity.warning,
        kind: DiagnosticIssueKind.relay,
        technicalDetail: redactSensitive(relayError),
      ),
    );
  }

  final pathWarnings = snapshot.peers
      .where((peer) => peer.lastError != null)
      .length;
  if (pathWarnings > 0) {
    issues.add(
      DiagnosticIssue(
        title: strings.devicesNeedPathReview(pathWarnings),
        detail: strings.issuePeerPathsDetail,
        severity: DiagnosticSeverity.warning,
        kind: DiagnosticIssueKind.peerPath,
      ),
    );
  }

  return issues;
}

bool _fatalServiceStatus(String status) {
  final normalized = status.trim().toLowerCase();
  return normalized == 'fatal' ||
      normalized == 'error' ||
      normalized == 'unhealthy' ||
      normalized == 'failed';
}

String? _redactedReason(HealthSnapshot health) {
  final reason = health.reason?.trim();
  if (reason == null || reason.isEmpty) return null;
  return redactSensitive(reason);
}
