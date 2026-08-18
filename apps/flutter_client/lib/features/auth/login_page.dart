import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import '../../app/app_constants.dart';
import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/api/control_api.dart';
import '../../core/capabilities/platform_capabilities.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import 'login_errors.dart';

class LoginPage extends StatefulWidget {
  const LoginPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    required this.onAuthenticated,
    this.capabilities,
    this.controlApi,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final VoidCallback onAuthenticated;

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
  var _showAdvanced = false;
  _LoginError? _error;

  @override
  void initState() {
    super.initState();
    _capabilities = widget.capabilities ?? PlatformCapabilities.current();
    _ownsControlApi = widget.controlApi == null;
    _controlApi = widget.controlApi ?? ControlApi();
    final settings = widget.settingsStore.settings;
    _controlServerController = TextEditingController(
      text: settings.controlServer.trim().isEmpty
          ? defaultControlServer
          : settings.controlServer,
    );
    _emailController = TextEditingController();
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
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final desktopCopy = _capabilities.canActAsLocalVpnNode;
    final usingCustomServer = _usesCustomServer;
    return Scaffold(
      body: Stack(
        children: [
          if (_usesWindowsWindowControls)
            const Positioned(
              top: 0,
              left: 0,
              right: 56,
              height: 52,
              child: DragToMoveArea(child: SizedBox.expand()),
            ),
          Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 460),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Row(
                      children: [
                        Container(
                          width: 46,
                          height: 46,
                          padding: const EdgeInsets.all(5),
                          decoration: BoxDecoration(
                            color: theme.colorScheme.surfaceContainerHighest,
                            borderRadius: BorderRadius.circular(
                              AppTokens.radiusMd,
                            ),
                            border: Border.all(
                              color: theme.colorScheme.outline,
                            ),
                          ),
                          child: Image.asset(
                            'assets/tray_icon.png',
                            fit: BoxFit.contain,
                          ),
                        ),
                        const SizedBox(width: 14),
                        Expanded(
                          child: Text(
                            p2wlanAppName,
                            style: TextStyle(
                              fontSize: 24,
                              fontWeight: FontWeight.w800,
                              color: theme.colorScheme.onSurface,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 22),
                    Text(
                      desktopCopy
                          ? strings.loginSubtitleDesktop
                          : strings.loginSubtitleMobile,
                      style: TextStyle(
                        fontSize: 15,
                        height: 1.35,
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                    const SizedBox(height: 20),
                    DecoratedBox(
                      decoration: BoxDecoration(
                        color: theme.colorScheme.surface,
                        border: Border.all(
                          color: isDark
                              ? theme.colorScheme.outline
                              : theme.colorScheme.outlineVariant,
                        ),
                        borderRadius: BorderRadius.circular(AppTokens.radiusLg),
                        boxShadow: isDark ? const [] : AppTokens.shadowBorder,
                      ),
                      child: Padding(
                        padding: const EdgeInsets.all(18),
                        child: AutofillGroup(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.stretch,
                            children: [
                              TextField(
                                controller: _emailController,
                                decoration: InputDecoration(
                                  labelText: strings.email,
                                  prefixIcon: const Icon(Icons.mail_outline),
                                ),
                                keyboardType: TextInputType.emailAddress,
                                autofillHints: const [AutofillHints.email],
                                textInputAction: TextInputAction.next,
                                onSubmitted: (_) =>
                                    _submitting ? null : _submit(),
                              ),
                              const SizedBox(height: 12),
                              TextField(
                                controller: _passwordController,
                                decoration: InputDecoration(
                                  labelText: strings.password,
                                  prefixIcon: const Icon(Icons.key_outlined),
                                  suffixIcon: IconButton(
                                    tooltip: _showPassword
                                        ? strings.hidePassword
                                        : strings.showPassword,
                                    onPressed: _submitting
                                        ? null
                                        : () => setState(
                                            () =>
                                                _showPassword = !_showPassword,
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
                              if (_error != null) ...[
                                const SizedBox(height: 12),
                                _LoginErrorBanner(error: _error!),
                              ],
                              const SizedBox(height: 16),
                              FilledButton.icon(
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
                              TextButton(
                                onPressed: _submitting
                                    ? null
                                    : () => setState(
                                        () => _register = !_register,
                                      ),
                                child: Text(
                                  _register
                                      ? strings.alreadyHaveAccount
                                      : strings.noAccountYet,
                                ),
                              ),
                              const Divider(height: 24),
                              _AdvancedDisclosure(
                                open: _showAdvanced,
                                onToggle: _submitting
                                    ? null
                                    : () => setState(
                                        () => _showAdvanced = !_showAdvanced,
                                      ),
                                title: strings.advancedOptions,
                                subtitle: strings.advancedOptionsSubtitle,
                                trailingHint: usingCustomServer
                                    ? strings.usingCustomServer
                                    : null,
                                child: Column(
                                  crossAxisAlignment:
                                      CrossAxisAlignment.stretch,
                                  children: [
                                    TextField(
                                      controller: _controlServerController,
                                      decoration: InputDecoration(
                                        labelText: strings.selfHostedServer,
                                        prefixIcon: const Icon(
                                          Icons.dns_outlined,
                                        ),
                                      ),
                                      keyboardType: TextInputType.url,
                                      textInputAction: TextInputAction.next,
                                      onSubmitted: (_) =>
                                          _submitting ? null : _submit(),
                                    ),
                                    const SizedBox(height: 12),
                                    Row(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.start,
                                      children: [
                                        Icon(
                                          Icons.offline_bolt_outlined,
                                          size: 18,
                                          color: theme
                                              .colorScheme
                                              .onSurfaceVariant,
                                        ),
                                        const SizedBox(width: 8),
                                        Expanded(
                                          child: Text(
                                            strings.manualOfflineModeHelper,
                                            style: TextStyle(
                                              fontSize: 12,
                                              height: 1.4,
                                              color: theme
                                                  .colorScheme
                                                  .onSurfaceVariant,
                                            ),
                                          ),
                                        ),
                                      ],
                                    ),
                                    const SizedBox(height: 12),
                                    OutlinedButton.icon(
                                      onPressed: _submitting
                                          ? null
                                          : _continueOffline,
                                      icon: const Icon(
                                        Icons.offline_bolt_outlined,
                                      ),
                                      label: Text(strings.continueOffline),
                                    ),
                                  ],
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
            ),
          ),
          if (_usesWindowsWindowControls)
            const Positioned(
              top: 6,
              right: 8,
              child: SafeArea(child: _LoginWindowCloseButton()),
            ),
        ],
      ),
    );
  }

  bool get _usesCustomServer {
    final saved = widget.settingsStore.settings.controlServer.trim();
    return saved.isNotEmpty && saved != defaultControlServer;
  }

  Future<void> _submit() async {
    if (_submitting) return;
    final strings = AppStringsScope.of(context);
    final email = _emailController.text.trim();
    final password = _passwordController.text;
    if (email.isEmpty) {
      setState(() {
        _error = _LoginError(
          title: strings.loginFailedTitle,
          body: strings.loginErrorEmailRequired,
        );
      });
      return;
    }
    if (password.length < 6) {
      setState(() {
        _error = _LoginError(
          title: strings.loginFailedTitle,
          body: strings.loginErrorPasswordTooShort,
        );
      });
      return;
    }
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      final session = await _controlApi.authenticate(
        mode: _register ? AuthMode.register : AuthMode.login,
        controlServer: _controlServerController.text,
        email: email,
        password: password,
      );
      final settings = widget.settingsStore.settings;
      final deviceName = settings.deviceName.trim().isEmpty
          ? await resolveDefaultDeviceName()
          : settings.deviceName.trim();
      await widget.settingsStore.updateSettings(
        settings.copyWith(
          controlServer: session.controlServer,
          authToken: session.token,
          deviceName: deviceName,
          manualMode: false,
        ),
      );
      await widget.statusStore.refresh();
      widget.onAuthenticated();
    } catch (error) {
      if (mounted) {
        setState(() => _error = _errorTextFor(strings, error));
      }
    } finally {
      if (mounted) {
        setState(() => _submitting = false);
      }
    }
  }

  Future<void> _continueOffline() async {
    if (_submitting) return;
    setState(() => _submitting = true);
    try {
      final settings = widget.settingsStore.settings;
      await widget.settingsStore.updateSettings(
        settings.copyWith(
          authToken: '',
          manualMode: true,
          deviceName: settings.deviceName.trim().isEmpty
              ? await resolveDefaultDeviceName()
              : settings.deviceName.trim(),
        ),
      );
      await widget.statusStore.refresh();
      widget.onAuthenticated();
    } finally {
      if (mounted) {
        setState(() => _submitting = false);
      }
    }
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

Future<void> _destroyWindow() async {
  await windowManager.setPreventClose(false);
  await windowManager.destroy();
}

class _LoginWindowCloseButton extends StatelessWidget {
  const _LoginWindowCloseButton();

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    return IconButton(
      tooltip: strings.closeWindow,
      style: IconButton.styleFrom(
        backgroundColor: theme.colorScheme.surface,
        foregroundColor: theme.colorScheme.onSurfaceVariant,
        side: BorderSide(color: theme.colorScheme.outlineVariant),
      ),
      onPressed: () => unawaited(_destroyWindow()),
      icon: const Icon(Icons.close_rounded),
    );
  }
}

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
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final bg = isDark ? AppTokens.colorDarkBadBg : AppTokens.colorBadBg;
    final border = isDark
        ? AppTokens.colorDarkBadBorder
        : AppTokens.colorBadBorder;
    final text = isDark ? AppTokens.colorDarkBadText : AppTokens.colorBadText;
    return DecoratedBox(
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
        border: Border.all(color: border),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
        child: Column(
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

class _AdvancedDisclosure extends StatelessWidget {
  const _AdvancedDisclosure({
    required this.open,
    required this.onToggle,
    required this.title,
    required this.subtitle,
    required this.child,
    this.trailingHint,
  });

  final bool open;
  final VoidCallback? onToggle;
  final String title;
  final String subtitle;
  final Widget child;
  final String? trailingHint;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        InkWell(
          onTap: onToggle,
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 10),
            child: Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        title,
                        style: TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                          color: theme.colorScheme.onSurface,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        subtitle,
                        style: TextStyle(
                          fontSize: 12,
                          height: 1.3,
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                      if (trailingHint != null) ...[
                        const SizedBox(height: 2),
                        Text(
                          trailingHint!,
                          style: TextStyle(
                            fontSize: 12,
                            height: 1.3,
                            color: theme.colorScheme.primary,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                Icon(
                  open ? Icons.expand_less_rounded : Icons.expand_more_rounded,
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ],
            ),
          ),
        ),
        if (open) ...[const SizedBox(height: 4), child],
        const SizedBox(height: 4),
        TextButton(
          onPressed: onToggle,
          child: Text(
            open ? strings.disclosureCollapse : strings.disclosureExpand,
          ),
        ),
      ],
    );
  }
}
