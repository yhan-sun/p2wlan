import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/lifecycle/mobile_lifecycle_coordinator.dart';

void main() {
  test('Dart vocabulary is checked against the canonical contract', () {
    final candidates = [
      File('../../contracts/mobile_lifecycle.json'),
      File('../contracts/mobile_lifecycle.json'),
    ];
    final contractFile = candidates.firstWhere((file) => file.existsSync());
    final contract = jsonDecode(contractFile.readAsStringSync()) as Map;
    final eventNames = (contract['events'] as List).cast<String>();
    final outcomeNames = (contract['outcomes'] as List).cast<String>();
    expect(
      MobileLifecycleEvent.values.map((event) => event.wireName).toList(),
      eventNames,
    );
    expect(
      MobileLifecycleOutcome.values.map((outcome) => outcome.wireName),
      outcomeNames,
    );
    expect(contract['schema_version'], 2);
  });

  test('background/resume epochs fence late work and duplicate callbacks', () {
    final coordinator = MobileLifecycleCoordinator();
    final background = coordinator.onAppBackgrounded();
    expect(background.outcome, MobileLifecycleOutcome.applied);
    expect(coordinator.acceptsEventLoop(appEpoch: 0, generation: 0), isFalse);
    expect(
      coordinator.onAppBackgrounded().outcome,
      MobileLifecycleOutcome.duplicate,
    );

    final resume = coordinator.onAppResumed();
    expect(resume.outcome, MobileLifecycleOutcome.applied);
    expect(
      coordinator.acceptsEventLoop(
        appEpoch: resume.newIdentity.appEpoch,
        generation: resume.newIdentity.eventLoopGeneration,
      ),
      isTrue,
    );
    expect(
      coordinator.onAppResumed().outcome,
      MobileLifecycleOutcome.duplicate,
    );
  });

  test(
    'permission revoke rejects the old result and regrant gets a new id',
    () {
      final coordinator = MobileLifecycleCoordinator();
      final request = coordinator.beginPermissionRequest();
      final requestId = request.newIdentity.permissionRequestId!;
      expect(
        coordinator.onPermissionRevoked().outcome,
        MobileLifecycleOutcome.applied,
      );
      expect(
        coordinator
            .completePermissionRequest(requestId: requestId, granted: true)
            .outcome,
        MobileLifecycleOutcome.staleRejected,
      );

      final newRequest = coordinator.beginPermissionRequest();
      expect(
        newRequest.newIdentity.permissionRequestId,
        greaterThan(requestId),
      );
      expect(
        coordinator
            .completePermissionRequest(
              requestId: newRequest.newIdentity.permissionRequestId!,
              granted: true,
            )
            .outcome,
        MobileLifecycleOutcome.applied,
      );
    },
  );

  test('concurrent permission request and duplicate completion are fenced', () {
    final coordinator = MobileLifecycleCoordinator();
    final request = coordinator.beginPermissionRequest();
    expect(
      coordinator.beginPermissionRequest().outcome,
      MobileLifecycleOutcome.failed,
    );
    expect(
      coordinator
          .completePermissionRequest(
            requestId: request.newIdentity.permissionRequestId!,
            granted: true,
          )
          .outcome,
      MobileLifecycleOutcome.applied,
    );
    final generation = coordinator.eventLoopGeneration;
    expect(
      coordinator
          .completePermissionRequest(
            requestId: request.newIdentity.permissionRequestId!,
            granted: true,
          )
          .outcome,
      MobileLifecycleOutcome.staleRejected,
    );
    expect(coordinator.eventLoopGeneration, generation);
  });

  test('old process, bridge and disposed callbacks cannot be adopted', () {
    final coordinator = MobileLifecycleCoordinator();
    expect(
      coordinator.observeDaemon(processId: 42, revision: 8).outcome,
      MobileLifecycleOutcome.applied,
    );
    expect(
      coordinator.observeDaemon(processId: 42, revision: 7).outcome,
      MobileLifecycleOutcome.staleRejected,
    );
    expect(
      coordinator.observeDaemon(processId: 43, revision: 1).outcome,
      MobileLifecycleOutcome.applied,
    );
    expect(
      coordinator.observeDaemon(processId: 42, revision: 11).outcome,
      MobileLifecycleOutcome.staleRejected,
    );
    expect(
      coordinator.observeBridge(4).outcome,
      MobileLifecycleOutcome.applied,
    );
    expect(
      coordinator.observeBridge(3).outcome,
      MobileLifecycleOutcome.staleRejected,
    );
    coordinator.dispose();
    expect(coordinator.onAppResumed().outcome, MobileLifecycleOutcome.failed);
  });

  test('Android transport is injectable at the production boundary', () async {
    final fake = _FakeAndroidVpnTransport();
    final diagnosticsApi = DiagnosticsApi();
    final controller = DaemonController(
      diagnosticsApi: diagnosticsApi,
      androidVpnTransport: fake,
    );
    addTearDown(diagnosticsApi.close);
    expect(identical(controller.androidVpnTransport, fake), isTrue);
    expect(await controller.androidVpnTransport.prepareVpn(), isTrue);
    expect(await controller.androidVpnTransport.start('{}'), isTrue);
    expect(await controller.androidVpnTransport.stop(), isTrue);
    expect(
      (await controller.androidVpnTransport.status()).bridgeIncarnation,
      2,
    );
  });
}

class _FakeAndroidVpnTransport implements AndroidVpnTransport {
  @override
  Future<bool> prepareVpn() async => true;

  @override
  Future<bool> start(String requestJson) async => true;

  @override
  Future<bool> stop() async => true;

  @override
  Future<AndroidVpnStatus> status() async => const AndroidVpnStatus(
    serviceRunning: true,
    nativeRunning: true,
    nativeReady: true,
    bridgeIncarnation: 2,
  );
}
