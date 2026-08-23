/// Build identities embedded in the Flutter client and reported by the
/// daemon.  Release builds must provide the client values through
/// `--dart-define`; an unknown value is intentionally visible instead of
/// pretending that an un-stamped development binary is a release artifact.
library;

class ClientBuildInfo {
  const ClientBuildInfo({
    required this.appVersion,
    required this.gitCommit,
    required this.buildId,
    required this.dirtyValue,
    required this.diffHash,
    required this.profile,
  });

  static const current = ClientBuildInfo(
    appVersion: String.fromEnvironment(
      'P2WLAN_CLIENT_APP_VERSION',
      defaultValue: 'unknown',
    ),
    gitCommit: String.fromEnvironment(
      'P2WLAN_CLIENT_GIT_COMMIT',
      defaultValue: 'unknown',
    ),
    buildId: String.fromEnvironment(
      'P2WLAN_CLIENT_BUILD_ID',
      defaultValue: 'unknown',
    ),
    dirtyValue: String.fromEnvironment(
      'P2WLAN_CLIENT_DIRTY',
      defaultValue: 'unknown',
    ),
    diffHash: String.fromEnvironment(
      'P2WLAN_CLIENT_DIFF_HASH',
      defaultValue: 'unknown',
    ),
    profile: String.fromEnvironment(
      'P2WLAN_CLIENT_PROFILE',
      defaultValue: 'unknown',
    ),
  );

  final String appVersion;
  final String gitCommit;
  final String buildId;
  final String dirtyValue;
  final String diffHash;
  final String profile;

  bool? get dirty => switch (dirtyValue.toLowerCase()) {
    'true' => true,
    'false' => false,
    _ => null,
  };

  String get dirtyLabel => dirtyValue;

  /// Return the first identity mismatch, or null when the client and daemon
  /// can be treated as the same source build.  Unknown values fail closed.
  String? mismatchWith(DaemonBuildInfo daemon) {
    if (appVersion == 'unknown' || daemon.appVersion.isEmpty) {
      return 'app_version_unknown';
    }
    if (appVersion != daemon.appVersion ||
        (daemon.daemonVersion.isNotEmpty &&
            appVersion != daemon.daemonVersion)) {
      return 'app_version';
    }
    if (gitCommit == 'unknown' || daemon.gitCommit.isEmpty) {
      return 'git_commit_unknown';
    }
    if (gitCommit.toLowerCase() != daemon.gitCommit.toLowerCase()) {
      return 'git_commit';
    }
    if (buildId == 'unknown' || daemon.buildId.isEmpty) {
      return 'build_id_unknown';
    }
    if (buildId != daemon.buildId) return 'build_id';
    if (dirty == null || daemon.dirty == null) return 'dirty_unknown';
    if (dirty != daemon.dirty) return 'dirty';
    if (dirty == true && diffHash != daemon.diffHash) return 'diff_hash';
    if (profile == 'unknown' || daemon.profile.isEmpty) {
      return 'profile_unknown';
    }
    if (profile != daemon.profile) return 'profile';
    return null;
  }
}

class DaemonBuildInfo {
  const DaemonBuildInfo({
    required this.appVersion,
    required this.daemonVersion,
    required this.gitCommit,
    required this.buildId,
    required this.dirty,
    required this.diffHash,
    required this.profile,
    this.hasDiffHash = true,
  });

  factory DaemonBuildInfo.fromJson(Map<String, dynamic> json) {
    final dirtyValue = json['dirty'];
    final dirty = dirtyValue is bool
        ? dirtyValue
        : dirtyValue is String
        ? switch (dirtyValue.toLowerCase()) {
            'true' => true,
            'false' => false,
            _ => null,
          }
        : null;
    return DaemonBuildInfo(
      appVersion: _text(json['app_version']),
      daemonVersion: _text(json['daemon_version']),
      gitCommit: _text(json['git_commit']),
      buildId: _text(json['build_id']),
      dirty: dirty,
      diffHash: _text(json['diff_hash']),
      profile: _text(json['profile']),
      hasDiffHash: json.containsKey('diff_hash'),
    );
  }

  final String appVersion;
  final String daemonVersion;
  final String gitCommit;
  final String buildId;
  final bool? dirty;
  final String diffHash;
  final String profile;
  final bool hasDiffHash;

  String get dirtyLabel => dirty == null ? 'unknown' : dirty.toString();

  bool get isComplete =>
      appVersion.isNotEmpty &&
      daemonVersion.isNotEmpty &&
      gitCommit.isNotEmpty &&
      buildId.isNotEmpty &&
      dirty != null &&
      hasDiffHash &&
      profile.isNotEmpty;
}

String _text(Object? value) => value?.toString().trim() ?? '';
