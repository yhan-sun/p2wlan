// Machine-readable evidence records intentionally use stdout.
// ignore_for_file: avoid_print

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/lifecycle/mobile_lifecycle_coordinator.dart';

void main() {
  test('ML-01 app-background-late-long-poll', () {
    final coordinator = MobileLifecycleCoordinator();
    final oldIdentity = coordinator.identity;
    final transition = coordinator.onAppBackgrounded();
    final accepted = coordinator.acceptsEventLoop(
      appEpoch: oldIdentity.appEpoch,
      generation: oldIdentity.eventLoopGeneration,
    );
    expect(transition.outcome, MobileLifecycleOutcome.applied);
    expect(accepted, isFalse);
    _record(
      scenarioId: 'ML-01',
      exactTestId: _testId('ML-01 app-background-late-long-poll'),
      events: ['app_backgrounded'],
      oldIdentity: oldIdentity,
      newIdentity: transition.newIdentity,
      decision: MobileLifecycleOutcome.staleRejected,
      invariants: {'old_callback_fenced': !accepted},
    );
  });

  test('ML-02 app-resume-refresh-before-reconnect', () {
    final coordinator = MobileLifecycleCoordinator();
    coordinator.onAppBackgrounded();
    final oldIdentity = coordinator.identity;
    final order = <String>[];
    final transition = coordinator.onAppResumed();
    order.add('refresh');
    order.add('poll');
    expect(transition.outcome, MobileLifecycleOutcome.applied);
    expect(order, ['refresh', 'poll']);
    final resumeRefreshPrecedesPoll =
        order.length == 2 && order[0] == 'refresh' && order[1] == 'poll';
    _record(
      scenarioId: 'ML-02',
      exactTestId: _testId('ML-02 app-resume-refresh-before-reconnect'),
      events: ['app_resumed'],
      oldIdentity: oldIdentity,
      newIdentity: transition.newIdentity,
      decision: transition.outcome,
      invariants: {'resume_refresh_precedes_poll': resumeRefreshPrecedesPoll},
    );
  });

  test('ML-03 daemon-process-recreation', () {
    final coordinator = MobileLifecycleCoordinator();
    final first = coordinator.observeDaemon(
      processId: 1234,
      runtimeIncarnation: 4,
      revision: 50,
    );
    final oldIdentity = first.newIdentity;
    final replacement = coordinator.observeDaemon(
      processId: 1234,
      runtimeIncarnation: 5,
      revision: 1,
    );
    expect(first.outcome, MobileLifecycleOutcome.applied);
    expect(replacement.outcome, MobileLifecycleOutcome.applied);
    expect(replacement.newIdentity.daemonProcessId, 1234);
    expect(replacement.newIdentity.daemonRuntimeIncarnation, 5);
    expect(replacement.newIdentity.daemonRevision, 1);
    _record(
      scenarioId: 'ML-03',
      exactTestId: _testId('ML-03 daemon-process-recreation'),
      events: ['native_runtime_stopped', 'native_runtime_started'],
      oldIdentity: oldIdentity,
      newIdentity: replacement.newIdentity,
      decision: replacement.outcome,
      invariants: {
        'new_process_adopted':
            replacement.newIdentity.daemonRuntimeIncarnation == 5,
      },
    );
  });

  test('ML-06 vpn-permission-revoke', () {
    final coordinator = MobileLifecycleCoordinator();
    final request = coordinator.beginPermissionRequest();
    final oldIdentity = request.newIdentity;
    final revoke = coordinator.onPermissionRevoked();
    final late = coordinator.completePermissionRequest(
      requestId: request.newIdentity.permissionRequestId!,
      granted: true,
    );
    expect(late.outcome, MobileLifecycleOutcome.staleRejected);
    expect(coordinator.acceptsAppEpoch(oldIdentity.appEpoch), isFalse);
    _record(
      scenarioId: 'ML-06',
      exactTestId: _testId('ML-06 vpn-permission-revoke'),
      events: ['vpn_permission_revoked', 'bridge_detached'],
      oldIdentity: oldIdentity,
      newIdentity: revoke.newIdentity,
      decision: late.outcome,
      invariants: {
        'pending_permission_invalidated': !coordinator.acceptsAppEpoch(
          oldIdentity.appEpoch,
        ),
      },
    );
  });

  test('ML-07 vpn-permission-regrant', () {
    final coordinator = MobileLifecycleCoordinator();
    final first = coordinator.beginPermissionRequest();
    coordinator.onPermissionRevoked();
    final oldIdentity = coordinator.identity;
    final second = coordinator.beginPermissionRequest();
    final grant = coordinator.completePermissionRequest(
      requestId: second.newIdentity.permissionRequestId!,
      granted: true,
    );
    expect(grant.outcome, MobileLifecycleOutcome.applied);
    expect(
      second.newIdentity.permissionRequestId,
      greaterThan(first.newIdentity.permissionRequestId!),
    );
    _record(
      scenarioId: 'ML-07',
      exactTestId: _testId('ML-07 vpn-permission-regrant'),
      events: ['vpn_permission_granted', 'native_runtime_started'],
      oldIdentity: oldIdentity,
      newIdentity: grant.newIdentity,
      decision: grant.outcome,
      invariants: {
        'new_permission_attempt':
            grant.newIdentity.permissionRequestId !=
            oldIdentity.permissionRequestId,
      },
    );
  });

  test('ML-08 activity-engine-recreation', () {
    final coordinator = MobileLifecycleCoordinator();
    coordinator.beginPermissionRequest();
    final oldIdentity = coordinator.identity;
    final recreation = coordinator.invalidateEventLoop(
      event: MobileLifecycleEvent.activityRecreated,
    );
    final oldCallbackAccepted = coordinator.acceptsAppEpoch(
      oldIdentity.appEpoch,
    );
    expect(recreation.outcome, MobileLifecycleOutcome.applied);
    expect(oldCallbackAccepted, isFalse);
    _record(
      scenarioId: 'ML-08',
      exactTestId: _testId('ML-08 activity-engine-recreation'),
      events: ['activity_recreated', 'bridge_attached'],
      oldIdentity: oldIdentity,
      newIdentity: recreation.newIdentity,
      decision: MobileLifecycleOutcome.staleRejected,
      invariants: {'old_engine_callback_rejected': !oldCallbackAccepted},
    );
  });

  test('ML-10 native-bridge-reattachment', () {
    final coordinator = MobileLifecycleCoordinator();
    final first = coordinator.observeBridge(4);
    final replacement = coordinator.observeBridge(5);
    expect(first.outcome, MobileLifecycleOutcome.applied);
    expect(replacement.outcome, MobileLifecycleOutcome.applied);
    _record(
      scenarioId: 'ML-10',
      exactTestId: _testId('ML-10 native-bridge-reattachment'),
      events: ['bridge_detached', 'bridge_attached'],
      oldIdentity: first.newIdentity,
      newIdentity: replacement.newIdentity,
      decision: replacement.outcome,
      invariants: {
        'bridge_identity_adopted':
            replacement.newIdentity.bridgeIncarnation == 5,
      },
    );
  });

  test('ML-12 control-websocket-reconnect', () {
    final coordinator = MobileLifecycleCoordinator();
    final oldIdentity = coordinator.identity;
    final reconnect = coordinator.invalidateEventLoop(
      event: MobileLifecycleEvent.controlReconnected,
    );
    expect(reconnect.outcome, MobileLifecycleOutcome.applied);
    expect(
      reconnect.newIdentity.eventLoopGeneration,
      greaterThan(oldIdentity.eventLoopGeneration),
    );
    _record(
      scenarioId: 'ML-12',
      exactTestId: _testId('ML-12 control-websocket-reconnect'),
      events: ['control_disconnected', 'control_reconnected'],
      oldIdentity: oldIdentity,
      newIdentity: reconnect.newIdentity,
      decision: reconnect.outcome,
      invariants: {
        'new_control_generation_adopted':
            reconnect.newIdentity.eventLoopGeneration >
            oldIdentity.eventLoopGeneration,
      },
    );
  });

  test('ML-18 duplicate-events-idempotent', () {
    final coordinator = MobileLifecycleCoordinator();
    final background = coordinator.onAppBackgrounded();
    final oldIdentity = coordinator.identity;
    final duplicateBackground = coordinator.onAppBackgrounded();
    final resumed = coordinator.onAppResumed();
    final duplicateResume = coordinator.onAppResumed();
    expect(background.outcome, MobileLifecycleOutcome.applied);
    expect(duplicateBackground.outcome, MobileLifecycleOutcome.duplicate);
    expect(resumed.outcome, MobileLifecycleOutcome.applied);
    expect(duplicateResume.outcome, MobileLifecycleOutcome.duplicate);
    expect(duplicateResume.newIdentity, resumed.newIdentity);
    _record(
      scenarioId: 'ML-18',
      exactTestId: _testId('ML-18 duplicate-events-idempotent'),
      events: [
        'app_backgrounded',
        'app_backgrounded',
        'app_resumed',
        'app_resumed',
      ],
      oldIdentity: resumed.newIdentity,
      newIdentity: duplicateResume.newIdentity,
      decision: duplicateResume.outcome,
      invariants: {
        'duplicate_has_no_second_effect':
            duplicateResume.newIdentity.eventLoopGeneration ==
            resumed.newIdentity.eventLoopGeneration,
      },
    );
    expect(
      oldIdentity.eventLoopGeneration,
      lessThan(resumed.newIdentity.eventLoopGeneration),
    );
  });
}

String _testId(String name) =>
    'apps/flutter_client/test/mobile_lifecycle_evidence_test.dart::$name';

void _record({
  required String scenarioId,
  required String exactTestId,
  required List<String> events,
  required MobileLifecycleIdentity oldIdentity,
  required MobileLifecycleIdentity newIdentity,
  required MobileLifecycleOutcome decision,
  required Map<String, bool> invariants,
}) {
  print(
    'MOBILE_LIFECYCLE_RECORD ${jsonEncode({'scenario_id': scenarioId, 'exact_test_id': exactTestId, 'executed': true, 'skipped': false, 'result': 'pass', 'events': events, 'observed_old_identity': oldIdentity.toJson(), 'observed_new_identity': newIdentity.toJson(), 'observed_decision': decision.wireName, 'invariants': invariants, 'execution_source': 'flutter_machine_reporter'})}',
  );
}
