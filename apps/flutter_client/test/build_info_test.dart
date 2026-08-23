import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/build_info.dart';

void main() {
  test('clean daemon identity accepts a matching clean client identity', () {
    const daemon = DaemonBuildInfo(
      appVersion: '0.1.134',
      daemonVersion: '0.1.134',
      gitCommit: 'abc',
      buildId: 'abc',
      dirty: false,
      diffHash: '',
      profile: 'release',
    );
    const client = ClientBuildInfo(
      appVersion: '0.1.134',
      gitCommit: 'abc',
      buildId: 'abc',
      dirtyValue: 'false',
      diffHash: '',
      profile: 'release',
    );
    expect(daemon.isComplete, isTrue);
    expect(client.mismatchWith(daemon), isNull);
  });

  test('dirty identity mismatch is reported before daemon startup', () {
    const daemon = DaemonBuildInfo(
      appVersion: '0.1.134',
      daemonVersion: '0.1.134',
      gitCommit: 'abc',
      buildId: 'abc-dirty-daemon',
      dirty: true,
      diffHash: 'daemon-diff',
      profile: 'debug',
    );
    const client = ClientBuildInfo(
      appVersion: '0.1.134',
      gitCommit: 'abc',
      buildId: 'abc-dirty-client',
      dirtyValue: 'true',
      diffHash: 'client-diff',
      profile: 'debug',
    );
    expect(client.mismatchWith(daemon), 'build_id');
  });
}
