import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/platform/native_platform.dart';

Map<String, Object?> _vpnStatusSnapshot({
  int revision = 1,
  int updatedAtEpochMs = 1800000000000,
  String status = 'ready',
}) => {
  'schemaVersion': 2,
  'revision': revision,
  'updatedAtEpochMs': updatedAtEpochMs,
  'requestId': 'request-1',
  'operation': 'start',
  'settingsRevision': 7,
  'identity': {'instanceId': 'vpn-instance-1', 'generation': 2},
  'status': status,
  'code': 'ENGINE_READY',
};

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('p2wlan/platform');

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  group('NativePlatformBridge', () {
    test(
      'OHOS reads the current diagnostics credential on every request',
      () async {
        var current = 'a' * 64;
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, (call) async {
              expect(call.method, 'diagnosticsAuthToken');
              return current;
            });
        const bridge = NativePlatformBridge(
          operatingSystem: 'ohos',
          channel: channel,
        );
        expect(await bridge.readDiagnosticsAuthToken(), current);
        current = 'b' * 64;
        expect(await bridge.readDiagnosticsAuthToken(), current);
      },
    );

    test(
      'OHOS diagnostics fails closed for missing or malformed credentials',
      () async {
        Object? response;
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, (call) async => response);
        const bridge = NativePlatformBridge(
          operatingSystem: 'ohos',
          channel: channel,
        );
        for (final invalid in [
          null,
          '',
          'a' * 63,
          'a' * 65,
          'z' * 64,
          '${'a' * 64}\n',
        ]) {
          response = invalid;
          expect(await bridge.readDiagnosticsAuthToken(), isNull);
        }
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, (call) async {
              throw PlatformException(code: 'FILE_UNAVAILABLE');
            });
        expect(await bridge.readDiagnosticsAuthToken(), isNull);
      },
    );

    test(
      'desktop diagnostics does not read the Harmony credential bridge',
      () async {
        var calls = 0;
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, (call) async {
              calls++;
              return 'a' * 64;
            });
        const bridge = NativePlatformBridge(
          operatingSystem: 'linux',
          channel: channel,
        );
        expect(await bridge.readDiagnosticsAuthToken(), isNull);
        expect(calls, 0);
      },
    );

    test(
      'OHOS resolves its application-private persistent directory',
      () async {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(
              channel,
              (call) async => call.method == 'applicationSupportDirectory'
                  ? '/sandbox/files/p2wlan'
                  : null,
            );
        const bridge = NativePlatformBridge(
          operatingSystem: 'ohos',
          channel: channel,
        );

        final directory = await bridge.resolveApplicationSupportDirectory();

        expect(directory?.path, '/sandbox/files/p2wlan');
      },
    );

    test('unsupported OS does not call the native channel', () async {
      var calls = 0;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            calls++;
            return '/unexpected';
          });
      const bridge = NativePlatformBridge(
        operatingSystem: 'linux',
        channel: channel,
      );

      final directory = await bridge.resolveApplicationSupportDirectory();

      expect(directory, isNull);
      expect(calls, 0);
    });

    test('empty native path fails closed', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async => ' ');
      const bridge = NativePlatformBridge(
        operatingSystem: 'ohos',
        channel: channel,
      );

      await expectLater(
        bridge.resolveApplicationSupportDirectory(),
        throwsStateError,
      );
    });

    test('OHOS parses the native build-info result', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
            channel,
            (call) async => {
              'ok': true,
              'data': {
                'abiVersion': 1,
                'engineVersion': '0.1.163',
                'target': 'aarch64-unknown-linux-ohos',
                'arch': 'aarch64',
              },
            },
          );
      const bridge = NativePlatformBridge(
        operatingSystem: 'ohos',
        channel: channel,
      );

      final info = await bridge.queryNativeBuildInfo();

      expect(info.abiVersion, 1);
      expect(info.engineVersion, '0.1.163');
      expect(info.target, 'aarch64-unknown-linux-ohos');
      expect(info.arch, 'aarch64');
    });

    test(
      'structured native errors expose only an allowed stable code',
      () async {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(
              channel,
              (call) async => {
                'ok': false,
                'error': {
                  'code': 'NATIVE_LIBRARY_LOAD_FAILED',
                  'message': '/private/device/path',
                },
              },
            );
        const bridge = NativePlatformBridge(
          operatingSystem: 'ohos',
          channel: channel,
        );

        await expectLater(
          bridge.queryNativeBuildInfo(),
          throwsA(
            isA<NativeBuildInfoException>().having(
              (error) => error.code,
              'code',
              'NATIVE_LIBRARY_LOAD_FAILED',
            ),
          ),
        );
      },
    );

    test('invalid and mismatched native results fail closed', () async {
      const bridge = NativePlatformBridge(
        operatingSystem: 'ohos',
        channel: channel,
      );
      final messenger =
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

      messenger.setMockMethodCallHandler(
        channel,
        (call) async => {
          'ok': true,
          'data': {
            'abiVersion': 2,
            'engineVersion': '0.1.163',
            'target': 'aarch64-unknown-linux-ohos',
            'arch': 'aarch64',
          },
        },
      );
      await expectLater(
        bridge.queryNativeBuildInfo(),
        throwsA(
          isA<NativeBuildInfoException>().having(
            (error) => error.code,
            'code',
            'NATIVE_ABI_MISMATCH',
          ),
        ),
      );

      messenger.setMockMethodCallHandler(
        channel,
        (call) async => {
          'ok': true,
          'data': {
            'abiVersion': 1,
            'engineVersion': '',
            'target': 'aarch64-unknown-linux-ohos',
            'arch': 'aarch64',
          },
        },
      );
      await expectLater(
        bridge.queryNativeBuildInfo(),
        throwsA(
          isA<NativeBuildInfoException>().having(
            (error) => error.code,
            'code',
            'NATIVE_RESULT_INVALID',
          ),
        ),
      );
    });

    test('non-OHOS platforms never invoke the build-info channel', () async {
      var calls = 0;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            calls++;
            return null;
          });
      const bridge = NativePlatformBridge(
        operatingSystem: 'android',
        channel: channel,
      );

      await expectLater(bridge.queryNativeBuildInfo(), throwsUnsupportedError);

      expect(calls, 0);
    });
  });

  group('VpnEngineStatusBridge', () {
    const now = 1800000000000;

    VpnEngineStatusBridge createBridge({int Function()? nowEpochMs}) =>
        VpnEngineStatusBridge(
          operatingSystem: 'ohos',
          channel: channel,
          nowEpochMs: nowEpochMs ?? () => now,
        );

    test('parses the current versioned Extension snapshot', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
            channel,
            (call) async => {'ok': true, 'data': _vpnStatusSnapshot()},
          );

      final snapshot = await createBridge().read();

      expect(snapshot.schemaVersion, 2);
      expect(snapshot.revision, 1);
      expect(snapshot.status, 'ready');
      expect(snapshot.operation, 'start');
      expect(snapshot.settingsRevision, 7);
      expect(snapshot.identity?.instanceId, 'vpn-instance-1');
      expect(snapshot.identity?.generation, 2);
      expect(snapshot.code, 'ENGINE_READY');
    });

    test(
      'rejects snapshots older than 15 seconds and future timestamps',
      () async {
        final messenger =
            TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
        messenger.setMockMethodCallHandler(
          channel,
          (call) async => {
            'ok': true,
            'data': _vpnStatusSnapshot(updatedAtEpochMs: now - 15001),
          },
        );
        await expectLater(
          createBridge().read(),
          throwsA(
            isA<VpnEngineStatusException>().having(
              (error) => error.code,
              'code',
              'VPN_ENGINE_STATUS_STALE',
            ),
          ),
        );

        messenger.setMockMethodCallHandler(
          channel,
          (call) async => {
            'ok': true,
            'data': _vpnStatusSnapshot(updatedAtEpochMs: now + 1),
          },
        );
        await expectLater(
          createBridge().read(),
          throwsA(
            isA<VpnEngineStatusException>().having(
              (error) => error.code,
              'code',
              'VPN_ENGINE_STATUS_FUTURE',
            ),
          ),
        );
      },
    );

    test(
      'rejects a regressing revision within the same bridge instance',
      () async {
        var revision = 2;
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, (call) async {
              return {
                'ok': true,
                'data': _vpnStatusSnapshot(revision: revision),
              };
            });
        final bridge = createBridge();

        expect((await bridge.read()).revision, 2);
        revision = 1;
        await expectLater(
          bridge.read(),
          throwsA(
            isA<VpnEngineStatusException>().having(
              (error) => error.code,
              'code',
              'VPN_ENGINE_STATUS_REVISION_REGRESSION',
            ),
          ),
        );
      },
    );

    test(
      'rejects unknown fields and maps only stable host error codes',
      () async {
        final messenger =
            TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
        messenger.setMockMethodCallHandler(
          channel,
          (call) async => {
            'ok': true,
            'data': {..._vpnStatusSnapshot(), 'secret': 'must-not-pass'},
          },
        );
        await expectLater(
          createBridge().read(),
          throwsA(
            isA<VpnEngineStatusException>().having(
              (error) => error.code,
              'code',
              'VPN_ENGINE_STATUS_RESULT_INVALID',
            ),
          ),
        );

        messenger.setMockMethodCallHandler(
          channel,
          (call) async => {
            'ok': false,
            'error': {'code': 'VPN_ENGINE_STATUS_SNAPSHOT_READ_FAILED'},
          },
        );
        await expectLater(
          createBridge().read(),
          throwsA(
            isA<VpnEngineStatusException>().having(
              (error) => error.code,
              'code',
              'VPN_ENGINE_STATUS_SNAPSHOT_READ_FAILED',
            ),
          ),
        );

        messenger.setMockMethodCallHandler(
          channel,
          (call) async => {
            'ok': false,
            'error': {'code': 'PRIVATE_PATH_OR_EXCEPTION'},
          },
        );
        await expectLater(
          createBridge().read(),
          throwsA(
            isA<VpnEngineStatusException>().having(
              (error) => error.code,
              'code',
              'VPN_ENGINE_STATUS_RESULT_INVALID',
            ),
          ),
        );
      },
    );

    test('supports the first-start case when no status file exists', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
            channel,
            (call) async => {'ok': true, 'data': null},
          );

      expect(await createBridge().readMaybe(), isNull);
      await expectLater(
        createBridge().read(),
        throwsA(
          isA<VpnEngineStatusException>().having(
            (error) => error.code,
            'code',
            'VPN_ENGINE_STATUS_SNAPSHOT_READ_FAILED',
          ),
        ),
      );
    });

    test('does not invoke the status channel outside OHOS', () async {
      var calls = 0;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            calls++;
            return null;
          });
      final bridge = VpnEngineStatusBridge(
        operatingSystem: 'android',
        channel: channel,
        nowEpochMs: () => now,
      );

      await expectLater(bridge.read(), throwsUnsupportedError);
      expect(calls, 0);
    });
  });

  group('MethodChannelHarmonyVpnTransport', () {
    test('sends only correlated start and stop request fields', () async {
      final calls = <MethodCall>[];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            calls.add(call);
            return {
              'ok': true,
              'phase': call.method == 'startVpnV2'
                  ? 'start_requested'
                  : 'stop_requested',
            };
          });
      final transport = MethodChannelHarmonyVpnTransport(channel: channel);

      await transport.start('h-start-01', 41);
      await transport.stop(
        requestId: 'h-stop-02',
        expectedStatusRequestId: 'h-start-01',
        settingsRevision: 41,
        afterStatusRevision: 8,
      );

      expect(calls.map((call) => call.method), ['startVpnV2', 'stopVpnV2']);
      expect(calls[0].arguments, {
        'requestId': 'h-start-01',
        'settingsRevision': 41,
      });
      expect(calls[1].arguments, {
        'requestId': 'h-stop-02',
        'expectedStatusRequestId': 'h-start-01',
        'settingsRevision': 41,
        'afterStatusRevision': 8,
      });
      expect(calls.toString(), isNot(contains('authToken')));
      expect(calls.toString(), isNot(contains('networkId')));
    });

    test('rejects request acknowledgements with extra fields', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
            channel,
            (call) async => {
              'ok': true,
              'phase': 'start_requested',
              'secret': 'must-not-pass',
            },
          );
      final transport = MethodChannelHarmonyVpnTransport(channel: channel);

      await expectLater(
        transport.start('h-start-01', 41),
        throwsA(
          isA<PlatformException>().having(
            (error) => error.code,
            'code',
            'VPN_ABILITY_REQUEST_RESULT_INVALID',
          ),
        ),
      );
    });

    test(
      'bounds a pending start request and prevents duplicate system calls',
      () async {
        final pending = Completer<Object?>();
        var calls = 0;
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, (call) {
              calls++;
              if (calls == 1) return pending.future;
              return Future<Object?>.value({
                'ok': true,
                'phase': 'start_requested',
              });
            });
        final transport = MethodChannelHarmonyVpnTransport(
          channel: channel,
          startRequestTimeout: const Duration(milliseconds: 10),
        );

        await expectLater(
          transport.start('h-start-01', 41),
          throwsA(isA<TimeoutException>()),
        );
        await expectLater(
          transport.start('h-start-02', 42),
          throwsA(
            isA<PlatformException>().having(
              (error) => error.code,
              'code',
              'VPN_ABILITY_REQUEST_PENDING',
            ),
          ),
        );
        expect(calls, 1);

        pending.complete({'ok': true, 'phase': 'start_requested'});
        await Future<void>.delayed(Duration.zero);
        await transport.start('h-start-03', 43);
        expect(calls, 2);
      },
    );

    test(
      'bounds status reads without stacking unresolved channel calls',
      () async {
        final pending = Completer<Object?>();
        var calls = 0;
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, (call) {
              calls++;
              if (calls == 1) return pending.future;
              return Future<Object?>.value({'ok': true, 'data': null});
            });
        final transport = MethodChannelHarmonyVpnTransport(
          channel: channel,
          statusRequestTimeout: const Duration(milliseconds: 10),
        );

        await expectLater(transport.status(), throwsA(isA<TimeoutException>()));
        await expectLater(
          transport.status(),
          throwsA(
            isA<VpnEngineStatusException>().having(
              (error) => error.code,
              'code',
              'VPN_ENGINE_STATUS_QUERY_FAILED',
            ),
          ),
        );
        expect(calls, 1);

        pending.complete({'ok': true, 'data': null});
        await Future<void>.delayed(Duration.zero);
        expect(await transport.status(), isNull);
        expect(calls, 2);
      },
    );
  });
}
