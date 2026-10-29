import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import '../../app/app_constants.dart';
import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/api/control_api.dart';
import '../../core/capabilities/platform_capabilities.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/widgets/windows_window_controls.dart';
import 'login_errors.dart';

class LoginPage extends StatefulWidget {
  const LoginPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    required this.onAuthenticated,
    this.capabilities,
    this.controlApi,
    this.onCancel,
    this.isReauthentication = false,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final VoidCallback onAuthenticated;
  final VoidCallback? onCancel;
  final bool isReauthentication;

  /// Platform capability override, primarily for tests. Defaults to the
  /// current platform when omitted.
  final PlatformCapabilities? capabilities;

  /// Auth client override, primarily for tests. When injected, this page does
  /// not take ownership and will not close it.
  final ControlApi? controlApi;

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  late final TextEditingController _controlServerController;
  late final TextEditingController _emailController;
  late final TextEditingController _passwordController;
  late final ControlApi _controlApi;
  late final bool _ownsControlApi;
  late final PlatformCapabilities _capabilities;

  var _register = false;
  var _submitting = false;
  var _showPassword = false;
  final _serverFocus = FocusNode();
  final _identifierFocus = FocusNode();
  final _passwordFocus = FocusNode();
  final _submissionErrorKey = GlobalKey();
  String? _serverError;
  String? _identifierError;
  String? _passwordError;
  _LoginError? _submissionError;

  @override
  void initState() {
    super.initState();
    _capabilities = widget.capabilities ?? PlatformCapabilities.current();
    _ownsControlApi = widget.controlApi == null;
    _controlApi = widget.controlApi ?? ControlApi();
    final settings = widget.settingsStore.settings;
    _controlServerController = TextEditingController(
      text: settings.controlServer,
    );
    _emailController = TextEditingController(
      text: settings.accountUsername.trim().isNotEmpty
          ? settings.accountUsername.trim()
          : settings.accountEmail.trim(),
    );
    _passwordController = TextEditingController();
  }

  @override
  void dispose() {
    if (_ownsControlApi) {
      _controlApi.close();
    }
    _controlServerController.dispose();
    _emailController.dispose();
    _passwordController.dispose();
    _serverFocus.dispose();
    _identifierFocus.dispose();
    _passwordFocus.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final desktopCopy = _capabilities.canActAsLocalVpnNode;
    final isZh = strings.isZh;
    return PopScope(
      canPop: !_submitting,
      child: Scaffold(
        body: Stack(
          children: [
            if (_usesWindowsWindowControls)
              const Positioned(
                top: 0,
                left: 0,
                right: WindowsWindowControls.width,
                height: 52,
                child: DragToMoveArea(child: SizedBox.expand()),
              ),
            Center(
              child: SingleChildScrollView(
                padding: EdgeInsets.symmetric(
                  horizontal: MediaQuery.sizeOf(context).width < 600 ? 20 : 28,
                  vertical: 28,
                ),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 480),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Row(
                        children: [
                          Container(
                            width: 42,
                            height: 42,
                            padding: const EdgeInsets.all(5),
                            decoration: BoxDecoration(
                              color: theme.colorScheme.surfaceContainerHighest,
                              borderRadius: BorderRadius.circular(12),
                              border: Border.all(
                                color: theme.colorScheme.outline,
                              ),
                            ),
                            child: Image.asset(
                              'assets/tray_icon.png',
                              fit: BoxFit.contain,
                            ),
                          ),
                          const SizedBox(width: AppTokens.space14),
                          Expanded(
                            child: Text(
                              p2wlanAppName,
                              style: TextStyle(
                                fontSize: 24,
                                fontWeight: FontWeight.w700,
                                color: theme.colorScheme.onSurface,
                              ),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 22),
                      if (widget.isReauthentication) ...[
                        Text(
                          isZh ? '重新登录' : 'Sign in again',
                          style: theme.textTheme.headlineSmall,
                        ),
                        const SizedBox(height: AppTokens.space8),
                      ],
                      Text(
                        widget.isReauthentication
                            ? (isZh
                                  ? '确认账号和服务器，恢复连接。'
                                  : 'Confirm your account and server to reconnect.')
                            : desktopCopy
                            ? strings.loginSubtitleDesktop
                            : strings.loginSubtitleMobile,
                        style: TextStyle(
                          fontSize: 15,
                          height: 1.35,
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                      const SizedBox(height: AppTokens.space20),
                      DecoratedBox(
                        decoration: BoxDecoration(
                          color: theme.colorScheme.surface,
                          border: Border.all(
                            color: isDark
                                ? theme.colorScheme.outline
                                : theme.colorScheme.outlineVariant,
                          ),
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: Padding(
                          padding: EdgeInsets.all(
                            MediaQuery.sizeOf(context).width < 600 ? 20 : 24,
                          ),
                          child: AutofillGroup(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.stretch,
                              children: [
                                TextField(
                                  key: const ValueKey('login-server'),
                                  controller: _controlServerController,
                                  style: TextStyle(
                                    fontSize: 14,
                                    height: 1.4,
                                    color: theme.colorScheme.onSurface,
                                  ),
                                  focusNode: _serverFocus,
                                  onChanged: (_) => _clearErrors(server: true),
                                  onSubmitted: (_) =>
                                      _identifierFocus.requestFocus(),
                                  decoration: InputDecoration(
                                    labelText: strings.loginServerAddress,
                                    helperText: _serverError == null
                                        ? strings.loginServerRequiredHelper
                                        : null,
                                    helperMaxLines: 3,
                                    errorText: _serverError,
                                    errorMaxLines: 3,
                                    prefixIcon: const Icon(
                                      Icons.dns_outlined,
                                      size: 20,
                                    ),
                                  ),
                                  keyboardType: TextInputType.url,
                                  textInputAction: TextInputAction.next,
                                  enabled: !_submitting,
                                ),
                                if (_serverError != null) ...[
                                  const SizedBox(height: AppTokens.space6),
                                  Text(
                                    _serverError ==
                                            strings.loginErrorInvalidServerTitle
                                        ? strings.loginErrorInvalidServerBody
                                        : strings.loginServerRequiredHelper,
                                    style: theme.textTheme.bodySmall?.copyWith(
                                      color: theme.colorScheme.error,
                                    ),
                                  ),
                                ],
                                const SizedBox(height: AppTokens.space12),
                                TextField(
                                  key: const ValueKey('login-identifier'),
                                  controller: _emailController,
                                  style: TextStyle(
                                    fontSize: 14,
                                    height: 1.4,
                                    color: theme.colorScheme.onSurface,
                                  ),
                                  focusNode: _identifierFocus,
                                  enabled: !_submitting,
                                  onChanged: (_) =>
                                      _clearErrors(identifier: true),
                                  decoration: InputDecoration(
                                    labelText: _register
                                        ? strings.email
                                        : strings.loginIdentifier,
                                    prefixIcon: const Icon(
                                      Icons.mail_outline,
                                      size: 20,
                                    ),
                                    errorText: _identifierError,
                                    errorMaxLines: 3,
                                  ),
                                  keyboardType: _register
                                      ? TextInputType.emailAddress
                                      : TextInputType.text,
                                  autofillHints: const [AutofillHints.email],
                                  textInputAction: TextInputAction.next,
                                  onSubmitted: (_) =>
                                      _passwordFocus.requestFocus(),
                                ),
                                const SizedBox(height: AppTokens.space12),
                                TextField(
                                  key: const ValueKey('login-password'),
                                  controller: _passwordController,
                                  style: TextStyle(
                                    fontSize: 14,
                                    height: 1.4,
                                    color: theme.colorScheme.onSurface,
                                  ),
                                  focusNode: _passwordFocus,
                                  enabled: !_submitting,
                                  onChanged: (_) =>
                                      _clearErrors(password: true),
                                  decoration: InputDecoration(
                                    labelText: strings.password,
                                    errorText: _passwordError,
                                    errorMaxLines: 3,
                                    prefixIcon: const Icon(
                                      Icons.key_outlined,
                                      size: 20,
                                    ),
                                    suffixIcon: IconButton(
                                      tooltip: _showPassword
                                          ? strings.hidePassword
                                          : strings.showPassword,
                                      onPressed: _submitting
                                          ? null
                                          : () => setState(
                                              () => _showPassword =
                                                  !_showPassword,
                                            ),
                                      icon: Icon(
                                        _showPassword
                                            ? Icons.visibility_off_outlined
                                            : Icons.visibility_outlined,
                                      ),
                                    ),
                                  ),
                                  obscureText: !_showPassword,
                                  autofillHints: [
                                    _register
                                        ? AutofillHints.newPassword
                                        : AutofillHints.password,
                                  ],
                                  textInputAction: TextInputAction.done,
                                  onSubmitted: (_) =>
                                      _submitting ? null : _submit(),
                                ),
                                const SizedBox(height: AppTokens.space16),
                                SizedBox(
                                  height: 48,
                                  child: FilledButton.icon(
                                    onPressed: _submitting ? null : _submit,
                                    icon: _submitting
                                        ? const SizedBox.square(
                                            dimension: 16,
                                            child: CircularProgressIndicator(
                                              strokeWidth: 2,
                                            ),
                                          )
                                        : const Icon(Icons.login_rounded),
                                    label: Text(
                                      _submitting
                                          ? (_register
                                                ? strings.creatingAccount
                                                : strings.signingIn)
                                          : (_register
                                                ? strings.createAccount
                                                : strings.signIn),
                                    ),
                                  ),
                                ),
                                if (!widget.isReauthentication)
                                  TextButton(
                                    onPressed: _submitting
                                        ? null
                                        : () => setState(() {
                                            _register = !_register;
                                            _serverError = null;
                                            _identifierError = null;
                                            _passwordError = null;
                                            _submissionError = null;
                                          }),
                                    child: Text(
                                      _register
                                          ? strings.alreadyHaveAccount
                                          : strings.noAccountYet,
                                    ),
                                  ),
                                if (widget.onCancel != null)
                                  TextButton(
                                    key: const ValueKey('login-cancel'),
                                    onPressed: _submitting
                                        ? null
                                        : widget.onCancel,
                                    child: Text(strings.cancel),
                                  ),
                              ],
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(height: AppTokens.space12),
                      ConstrainedBox(
                        constraints: const BoxConstraints(minHeight: 88),
                        child: _submissionError == null
                            ? const SizedBox.shrink()
                            : Semantics(
                                key: _submissionErrorKey,
                                liveRegion: true,
                                child: _LoginErrorBanner(
                                  error: _submissionError!,
                                ),
                              ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _clearErrors({
    bool server = false,
    bool identifier = false,
    bool password = false,
  }) {
    setState(() {
      if (server) _serverError = null;
      if (identifier) _identifierError = null;
      if (password) _passwordError = null;
      _submissionError = null;
    });
  }

  Future<void> _submit() async {
    if (_submitting) return;
    final strings = AppStringsScope.of(context);
    final email = _emailController.text.trim();
    final password = _passwordController.text;
    String? serverError;
    if (_controlServerController.text.trim().isEmpty) {
      serverError = strings.loginServerRequiredTitle;
    } else {
      try {
        normalizeControlServer(_controlServerController.text);
      } on FormatException {
        serverError = strings.loginErrorInvalidServerTitle;
      }
    }
    setState(() {
      _serverError = serverError;
      _identifierError = email.isEmpty ? strings.loginErrorEmailRequired : null;
      _passwordError = password.length < 6
          ? strings.loginErrorPasswordTooShort
          : null;
      _submissionError = null;
    });
    final invalidFocus = serverError != null
        ? _serverFocus
        : _identifierError != null
        ? _identifierFocus
        : _passwordError != null
        ? _passwordFocus
        : null;
    if (invalidFocus != null) {
      invalidFocus.requestFocus();
      return;
    }
    final sessionRevision = widget.statusStore.sessionRevision;
    final startingSettings = widget.settingsStore.settings;
    bool sessionIsCurrent() =>
        mounted &&
        widget.statusStore.sessionRevision == sessionRevision &&
        widget.settingsStore.settings.authToken == startingSettings.authToken &&
        widget.settingsStore.settings.controlServer ==
            startingSettings.controlServer;
    FocusManager.instance.primaryFocus?.unfocus();
    setState(() => _submitting = true);
    try {
      final session = await _controlApi.authenticate(
        mode: _register ? AuthMode.register : AuthMode.login,
        controlServer: _controlServerController.text,
        email: email,
        password: password,
      );
      if (!sessionIsCurrent()) return;
      final settings = widget.settingsStore.settings;
      final accountEmail = session.user?['email']?.toString().trim();
      final accountUsername = session.user?['username']?.toString().trim();
      final sameKnownAccount =
          session.controlServer == settings.controlServer &&
          (email.toLowerCase() == settings.accountEmail.toLowerCase() ||
              email == settings.accountUsername);
      final fallbackUsername = email.contains('@')
          ? (sameKnownAccount ? settings.accountUsername : '')
          : email;
      final deviceName = settings.deviceName.trim().isEmpty
          ? await resolveDefaultDeviceName()
          : settings.deviceName.trim();
      if (!sessionIsCurrent()) return;
      await widget.settingsStore.updateSettings(
        settings.copyWith(
          controlServer: session.controlServer,
          authToken: session.token,
          accountEmail: accountEmail == null || accountEmail.isEmpty
              ? (email.contains('@') ? email.trim().toLowerCase() : '')
              : accountEmail.toLowerCase(),
          accountUsername: accountUsername ?? fallbackUsername,
          deviceName: deviceName,
        ),
      );
      bool authenticatedSessionIsCurrent() =>
          mounted &&
          widget.settingsStore.settings.authToken == session.token &&
          widget.settingsStore.settings.controlServer == session.controlServer;
      if (!authenticatedSessionIsCurrent()) return;
      await widget.statusStore.refresh();
      if (authenticatedSessionIsCurrent()) widget.onAuthenticated();
    } catch (error) {
      if (mounted) {
        _presentError(
          error is AccountSessionChangeException
              ? _LoginError(
                  title: strings.loginFailedTitle,
                  body: strings.isZh ? error.message : 'Network operations are still finishing. Try signing in again shortly.',
                )
              : _errorTextFor(strings, error),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _submitting = false);
      }
    }
  }

  void _presentError(_LoginError error) {
    if (!mounted) return;
    setState(() => _submissionError = error);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final target = _submissionErrorKey.currentContext;
      if (!mounted || _submissionError != error || target == null) return;
      Scrollable.ensureVisible(
        target,
        alignment: 1,
        alignmentPolicy: ScrollPositionAlignmentPolicy.keepVisibleAtEnd,
        duration: MediaQuery.disableAnimationsOf(context)
            ? Duration.zero
            : AppTokens.durationMedium,
      );
    });
  }
}

_LoginError _errorTextFor(AppStrings strings, Object error) {
  switch (loginErrorKindOf(error)) {
    case LoginErrorKind.validation:
      return _LoginError(
        title: strings.loginFailedTitle,
        body: error is LoginValidationException
            ? error.message
            : strings.loginErrorEmailRequired,
      );
    case LoginErrorKind.authentication:
      return _LoginError(
        title: strings.loginFailedTitle,
        body: strings.loginErrorAuthenticationBody,
      );
    case LoginErrorKind.accountExists:
      return _LoginError(
        title: strings.loginFailedTitle,
        body: strings.loginErrorAccountExistsBody,
      );
    case LoginErrorKind.network:
      return _LoginError(
        title: strings.loginErrorNetworkTitle,
        body: strings.loginErrorNetworkBody,
      );
    case LoginErrorKind.timeout:
      return _LoginError(
        title: strings.loginErrorNetworkTitle,
        body: strings.loginErrorTimeoutBody,
      );
    case LoginErrorKind.server:
      return _LoginError(
        title: strings.loginFailedTitle,
        body: strings.loginErrorServerBody,
      );
    case LoginErrorKind.rateLimited:
      return _LoginError(
        title: strings.loginFailedTitle,
        body: strings.loginErrorRateLimitedBody,
      );
    case LoginErrorKind.registrationFailed:
      return _LoginError(
        title: strings.loginFailedTitle,
        body: strings.loginErrorRegistrationFailedBody,
      );
    case LoginErrorKind.unknown:
      return _LoginError(title: strings.loginErrorUnknownTitle);
  }
}

bool get _usesWindowsWindowControls => !kIsWeb && Platform.isWindows;

class _LoginError {
  const _LoginError({required this.title, this.body});

  final String title;
  final String? body;
}

class _LoginErrorBanner extends StatelessWidget {
  const _LoginErrorBanner({required this.error});

  final _LoginError error;

  @override
  Widget build(BuildContext context) {
    final c = P2WlanColors.of(context);
    final bg = c.dangerSurface;
    final border = c.dangerBorder;
    final text = c.dangerText;
    return DecoratedBox(
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
        border: Border.all(color: border),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              error.title,
              style: TextStyle(
                fontSize: 12,
                height: 1.35,
                fontWeight: FontWeight.w600,
                color: text,
              ),
            ),
            if (error.body != null) ...[
              const SizedBox(height: 2),
              Text(
                error.body!,
                style: TextStyle(fontSize: 12, height: 1.35, color: text),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
