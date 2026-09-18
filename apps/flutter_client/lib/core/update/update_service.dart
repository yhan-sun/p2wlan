import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:url_launcher/url_launcher.dart';

import '../build_info.dart';
import 'update_models.dart';

typedef UpdateUrlLauncher = Future<bool> Function(Uri uri);

class UpdateService {
  UpdateService({
    UpdateHttpTransport? transport,
    UpdateUrlLauncher? launcher,
    String? currentAppVersion,
  }) : _transport = transport ?? IoUpdateHttpTransport(),
       _launcher = launcher ?? _launchExternalUrl,
       _currentAppVersionOverride = currentAppVersion;

  static const repositoryOwner = 'yhan-sun';
  static const repositoryName = 'p2wlan';
  static const requestTimeout = Duration(seconds: 5);
  static const maxResponseBytes = 256 * 1024;
  static final latestReleaseUri = Uri.parse(
    'https://api.github.com/repos/$repositoryOwner/$repositoryName/releases/latest',
  );

  final UpdateHttpTransport _transport;
  final UpdateUrlLauncher _launcher;
  final String? _currentAppVersionOverride;

  Future<UpdateCheckResult> check({String? appVersion}) async {
    final currentText =
        (appVersion ??
                _currentAppVersionOverride ??
                ClientBuildInfo.current.appVersion)
            .trim();
    if (currentText == 'unknown') {
      return UpdateCheckResult(
        status: UpdateCheckStatus.developmentBuild,
        currentAppVersion: currentText,
      );
    }

    final current = ClientReleaseVersion.tryParseAppVersion(currentText);
    if (current == null) {
      return UpdateCheckResult(
        status: UpdateCheckStatus.invalidRelease,
        currentAppVersion: currentText,
        error: const UpdateCheckError(
          UpdateCheckErrorCode.invalidCurrentVersion,
          'The current client version is not a release version.',
        ),
      );
    }

    final response = await _fetchLatest(currentText);
    if (response.error != null) {
      return UpdateCheckResult(
        status: UpdateCheckStatus.networkError,
        currentAppVersion: currentText,
        currentVersion: current,
        error: response.error,
      );
    }

    final body = response.body!;
    if (body.length > maxResponseBytes) {
      return UpdateCheckResult(
        status: UpdateCheckStatus.networkError,
        currentAppVersion: currentText,
        currentVersion: current,
        error: const UpdateCheckError(
          UpdateCheckErrorCode.responseTooLarge,
          'The release response exceeded the size limit.',
        ),
      );
    }

    final decoded = _decodeJson(body);
    if (decoded is! Map<String, dynamic>) {
      return UpdateCheckResult(
        status: UpdateCheckStatus.networkError,
        currentAppVersion: currentText,
        currentVersion: current,
        error: const UpdateCheckError(
          UpdateCheckErrorCode.malformedResponse,
          'The release response was not a JSON object.',
        ),
      );
    }

    final tagName = decoded['tag_name'];
    if (tagName is! String) {
      return UpdateCheckResult(
        status: UpdateCheckStatus.invalidRelease,
        currentAppVersion: currentText,
        currentVersion: current,
        error: const UpdateCheckError(
          UpdateCheckErrorCode.invalidTag,
          'The release did not contain a client tag.',
        ),
      );
    }
    final latest = ClientReleaseVersion.tryParseTag(tagName);
    if (latest == null) {
      return UpdateCheckResult(
        status: UpdateCheckStatus.invalidRelease,
        currentAppVersion: currentText,
        currentVersion: current,
        error: const UpdateCheckError(
          UpdateCheckErrorCode.invalidTag,
          'The release tag is not a client release tag.',
        ),
      );
    }

    final releaseUrl = _parseReleaseUrl(decoded['html_url'], latest);
    if (releaseUrl == null) {
      return UpdateCheckResult(
        status: UpdateCheckStatus.invalidRelease,
        currentAppVersion: currentText,
        currentVersion: current,
        error: const UpdateCheckError(
          UpdateCheckErrorCode.invalidUrl,
          'The release URL was not an allowed P2WLAN GitHub URL.',
        ),
      );
    }

    final update = UpdateInfo(
      version: latest,
      releaseUrl: releaseUrl,
      name: decoded['name'] is String ? decoded['name'] as String : null,
      publishedAt: _parseDate(decoded['published_at']),
    );
    return UpdateCheckResult(
      status: latest.compareTo(current) > 0
          ? UpdateCheckStatus.updateAvailable
          : UpdateCheckStatus.upToDate,
      currentAppVersion: currentText,
      currentVersion: current,
      update: update,
    );
  }

  Future<bool> openRelease(UpdateInfo update) async {
    if (!isAllowedReleaseUrl(update.releaseUrl, update.version)) return false;
    try {
      return await _launcher(update.releaseUrl);
    } on Object {
      return false;
    }
  }

  static bool isAllowedReleaseUrl(Uri uri, ClientReleaseVersion version) {
    return uri.scheme == 'https' &&
        uri.host == 'github.com' &&
        uri.userInfo.isEmpty &&
        (uri.port == 443 || uri.port == -1) &&
        uri.query.isEmpty &&
        uri.fragment.isEmpty &&
        uri.path ==
            '/$repositoryOwner/$repositoryName/releases/tag/${version.tag}';
  }

  Future<_FetchedResponse> _fetchLatest(String currentText) async {
    try {
      final response = await _transport
          .get(
            latestReleaseUri,
            headers: {
              'Accept': 'application/vnd.github+json',
              'User-Agent': 'P2WLAN/$currentText',
            },
            timeout: requestTimeout,
            maxResponseBytes: maxResponseBytes,
          )
          .timeout(requestTimeout);
      if (response.statusCode < 200 || response.statusCode >= 300) {
        return _FetchedResponse(
          error: UpdateCheckError(
            UpdateCheckErrorCode.httpStatus,
            'GitHub returned HTTP ${response.statusCode}.',
            statusCode: response.statusCode,
          ),
        );
      }
      return _FetchedResponse(body: response.body);
    } on UpdateTransportException catch (error) {
      return _FetchedResponse(error: _transportError(error));
    } on TimeoutException {
      return _FetchedResponse(
        error: const UpdateCheckError(
          UpdateCheckErrorCode.timeout,
          'The release request timed out.',
        ),
      );
    } on Object catch (error) {
      return _FetchedResponse(
        error: UpdateCheckError(
          UpdateCheckErrorCode.transport,
          'The release request failed: $error',
        ),
      );
    }
  }

  UpdateCheckError _transportError(UpdateTransportException error) {
    final code = switch (error.code) {
      UpdateTransportErrorCode.timeout => UpdateCheckErrorCode.timeout,
      UpdateTransportErrorCode.responseTooLarge =>
        UpdateCheckErrorCode.responseTooLarge,
      UpdateTransportErrorCode.transport => UpdateCheckErrorCode.transport,
    };
    return UpdateCheckError(code, error.message);
  }

  dynamic _decodeJson(List<int> body) {
    try {
      return jsonDecode(utf8.decode(body));
    } on Object {
      return null;
    }
  }

  Uri? _parseReleaseUrl(Object? raw, ClientReleaseVersion version) {
    if (raw is! String) return null;
    final uri = Uri.tryParse(raw.trim());
    if (uri == null || !isAllowedReleaseUrl(uri, version)) return null;
    return uri;
  }

  DateTime? _parseDate(Object? raw) {
    if (raw is! String) return null;
    return DateTime.tryParse(raw);
  }

  static Future<bool> _launchExternalUrl(Uri uri) {
    return launchUrl(uri, mode: LaunchMode.externalApplication);
  }
}

class _FetchedResponse {
  const _FetchedResponse({this.body, this.error});

  final List<int>? body;
  final UpdateCheckError? error;
}

class IoUpdateHttpTransport implements UpdateHttpTransport {
  @override
  Future<UpdateHttpResponse> get(
    Uri uri, {
    required Map<String, String> headers,
    required Duration timeout,
    required int maxResponseBytes,
  }) async {
    final client = HttpClient()
      ..connectionTimeout = timeout
      ..maxConnectionsPerHost = 1;
    try {
      final request = await client.getUrl(uri).timeout(timeout);
      request.followRedirects = false;
      for (final entry in headers.entries) {
        request.headers.set(entry.key, entry.value);
      }
      final response = await request.close().timeout(timeout);
      if (response.contentLength > maxResponseBytes) {
        throw const UpdateTransportException(
          UpdateTransportErrorCode.responseTooLarge,
          'The release response exceeded the size limit.',
        );
      }
      final body = <int>[];
      await for (final chunk in response.timeout(timeout)) {
        if (chunk.length > maxResponseBytes - body.length) {
          throw const UpdateTransportException(
            UpdateTransportErrorCode.responseTooLarge,
            'The release response exceeded the size limit.',
          );
        }
        body.addAll(chunk);
      }
      return UpdateHttpResponse(statusCode: response.statusCode, body: body);
    } on UpdateTransportException {
      rethrow;
    } on TimeoutException {
      throw const UpdateTransportException(
        UpdateTransportErrorCode.timeout,
        'The release request timed out.',
      );
    } on Object catch (error) {
      throw UpdateTransportException(
        UpdateTransportErrorCode.transport,
        'The release request failed: $error',
      );
    } finally {
      client.close(force: true);
    }
  }
}
