/// Data types shared by the client update checker and its UI.
library;

enum UpdateCheckStatus {
  upToDate,
  updateAvailable,
  developmentBuild,
  invalidRelease,
  networkError,
}

enum UpdateCheckErrorCode {
  invalidCurrentVersion,
  invalidTag,
  invalidUrl,
  malformedResponse,
  timeout,
  httpStatus,
  responseTooLarge,
  transport,
}

/// A small, strict client release version. Server tags are intentionally not
/// representable by this parser.
class ClientReleaseVersion implements Comparable<ClientReleaseVersion> {
  ClientReleaseVersion._(this.major, this.minor, this.patch);

  static final _tagPattern = RegExp(r'^v([0-9]+)\.([0-9]+)\.([0-9]+)$');
  static final _appVersionPattern = RegExp(r'^([0-9]+)\.([0-9]+)\.([0-9]+)$');

  final int major;
  final int minor;
  final int patch;

  static ClientReleaseVersion? tryParseTag(String value) {
    final match = _tagPattern.firstMatch(value);
    if (match == null) return null;
    return _fromMatch(match);
  }

  static ClientReleaseVersion? tryParseAppVersion(String value) {
    final match = _appVersionPattern.firstMatch(value);
    if (match == null) return null;
    return _fromMatch(match);
  }

  static ClientReleaseVersion? _fromMatch(RegExpMatch match) {
    final major = int.tryParse(match.group(1)!);
    final minor = int.tryParse(match.group(2)!);
    final patch = int.tryParse(match.group(3)!);
    if (major == null || minor == null || patch == null) return null;
    return ClientReleaseVersion._(major, minor, patch);
  }

  String get appVersion => '$major.$minor.$patch';
  String get tag => 'v$appVersion';

  @override
  int compareTo(ClientReleaseVersion other) {
    final majorComparison = major.compareTo(other.major);
    if (majorComparison != 0) return majorComparison;
    final minorComparison = minor.compareTo(other.minor);
    if (minorComparison != 0) return minorComparison;
    return patch.compareTo(other.patch);
  }

  @override
  bool operator ==(Object other) {
    return other is ClientReleaseVersion && compareTo(other) == 0;
  }

  @override
  int get hashCode => Object.hash(major, minor, patch);

  @override
  String toString() => tag;
}

class UpdateInfo {
  const UpdateInfo({
    required this.version,
    required this.releaseUrl,
    this.name,
    this.publishedAt,
  });

  final ClientReleaseVersion version;
  final Uri releaseUrl;
  final String? name;
  final DateTime? publishedAt;
}

class UpdateCheckError {
  const UpdateCheckError(this.code, this.message, {this.statusCode});

  final UpdateCheckErrorCode code;
  final String message;
  final int? statusCode;

  @override
  String toString() {
    final status = statusCode == null ? '' : ' status=$statusCode';
    return 'UpdateCheckError(${code.name}$status): $message';
  }
}

class UpdateCheckResult {
  const UpdateCheckResult({
    required this.status,
    required this.currentAppVersion,
    this.currentVersion,
    this.update,
    this.error,
  });

  final UpdateCheckStatus status;
  final String currentAppVersion;
  final ClientReleaseVersion? currentVersion;
  final UpdateInfo? update;
  final UpdateCheckError? error;

  bool get hasUpdate =>
      status == UpdateCheckStatus.updateAvailable && update != null;
}

class UpdateHttpResponse {
  const UpdateHttpResponse({required this.statusCode, required this.body});

  final int statusCode;
  final List<int> body;
}

enum UpdateTransportErrorCode { timeout, responseTooLarge, transport }

class UpdateTransportException implements Exception {
  const UpdateTransportException(this.code, this.message);

  final UpdateTransportErrorCode code;
  final String message;

  @override
  String toString() => 'UpdateTransportException(${code.name}): $message';
}

abstract interface class UpdateHttpTransport {
  Future<UpdateHttpResponse> get(
    Uri uri, {
    required Map<String, String> headers,
    required Duration timeout,
    required int maxResponseBytes,
  });
}
