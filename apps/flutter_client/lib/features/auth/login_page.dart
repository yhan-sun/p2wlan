import 'package:flutter/material.dart';

import '../../app/app_constants.dart';
import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/api/control_api.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';

class LoginPage extends StatefulWidget {
  const LoginPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    required this.onAuthenticated,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final VoidCallback onAuthenticated;

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  late final TextEditingController _controlServerController;
  late final TextEditingController _emailController;
  late final TextEditingController _passwordController;
  final _controlApi = ControlApi();

  var _register = false;
  var _submitting = false;
  String? _error;
  String? _message;

  @override
  void initState() {
    super.initState();
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
    _controlApi.close();
    _controlServerController.dispose();
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 520),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  children: [
                    Container(
                      width: 44,
                      height: 44,
                      decoration: BoxDecoration(
                        color: AppTokens.colorNeutralBg,
                        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
                      ),
                      child: const Icon(
                        Icons.network_check_rounded,
                        color: AppTokens.colorAccent,
                      ),
                    ),
                    const SizedBox(width: 14),
                    const Expanded(
                      child: Text(
                        p2wlanAppName,
                        style: TextStyle(
                          fontSize: 24,
                          fontWeight: FontWeight.w800,
                          color: AppTokens.colorTextPrimary,
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 22),
                Text(
                  strings.isZh
                      ? '登录控制面后启动本机 TUN'
                      : 'Sign in to start the local TUN',
                  style: const TextStyle(
                    fontSize: 15,
                    height: 1.35,
                    color: AppTokens.colorTextSecondary,
                  ),
                ),
                const SizedBox(height: 20),
                DecoratedBox(
                  decoration: BoxDecoration(
                    color: AppTokens.colorSurface,
                    border: Border.all(color: AppTokens.colorBorderSubtle),
                    borderRadius: BorderRadius.circular(AppTokens.radiusLg),
                  ),
                  child: Padding(
                    padding: const EdgeInsets.all(18),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        TextField(
                          controller: _controlServerController,
                          decoration: InputDecoration(
                            labelText: strings.controlServer,
                            prefixIcon: const Icon(Icons.dns_outlined),
                          ),
                          keyboardType: TextInputType.url,
                        ),
                        const SizedBox(height: 12),
                        TextField(
                          controller: _emailController,
                          decoration: InputDecoration(
                            labelText: strings.isZh ? '邮箱' : 'Email',
                            prefixIcon: const Icon(Icons.mail_outline),
                          ),
                          keyboardType: TextInputType.emailAddress,
                          autofillHints: const [AutofillHints.email],
                        ),
                        const SizedBox(height: 12),
                        TextField(
                          controller: _passwordController,
                          decoration: InputDecoration(
                            labelText: strings.isZh ? '密码' : 'Password',
                            prefixIcon: const Icon(Icons.key_outlined),
                          ),
                          obscureText: true,
                          autofillHints: [
                            _register
                                ? AutofillHints.newPassword
                                : AutofillHints.password,
                          ],
                        ),
                        if (_error != null) ...[
                          const SizedBox(height: 12),
                          _InlineMessage(message: _error!, error: true),
                        ],
                        if (_message != null) ...[
                          const SizedBox(height: 12),
                          _InlineMessage(message: _message!, error: false),
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
                                ? (strings.isZh ? '认证中...' : 'Signing in...')
                                : _register
                                ? (strings.isZh
                                      ? '注册并继续'
                                      : 'Register and continue')
                                : (strings.isZh
                                      ? '登录并继续'
                                      : 'Sign in and continue'),
                          ),
                        ),
                        TextButton(
                          onPressed: _submitting
                              ? null
                              : () => setState(() => _register = !_register),
                          child: Text(
                            _register
                                ? (strings.isZh
                                      ? '已有账号，去登录'
                                      : 'I already have an account')
                                : (strings.isZh
                                      ? '没有账号，创建一个'
                                      : 'Create an account'),
                          ),
                        ),
                        const Divider(height: 24),
                        OutlinedButton.icon(
                          onPressed: _submitting ? null : _continueOffline,
                          icon: const Icon(Icons.offline_bolt_outlined),
                          label: Text(
                            strings.isZh
                                ? '继续使用手动/离线模式'
                                : 'Continue in manual/offline mode',
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Future<void> _submit() async {
    final strings = AppStringsScope.of(context);
    setState(() {
      _submitting = true;
      _error = null;
      _message = null;
    });
    try {
      final session = await _controlApi.authenticate(
        mode: _register ? AuthMode.register : AuthMode.login,
        controlServer: _controlServerController.text,
        email: _emailController.text,
        password: _passwordController.text,
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
      setState(() {
        _message = strings.isZh
            ? '控制面账号已认证，token 已保存。'
            : 'Control session saved.';
      });
      widget.onAuthenticated();
    } catch (error) {
      setState(() => _error = error.toString());
    } finally {
      if (mounted) {
        setState(() => _submitting = false);
      }
    }
  }

  Future<void> _continueOffline() async {
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
  }
}

class _InlineMessage extends StatelessWidget {
  const _InlineMessage({required this.message, required this.error});

  final String message;
  final bool error;

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: error ? AppTokens.colorBadBg : AppTokens.colorGoodBg,
        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
        border: Border.all(
          color: error ? AppTokens.colorBadBorder : AppTokens.colorGoodBorder,
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
        child: Text(
          message,
          style: TextStyle(
            fontSize: 12,
            height: 1.35,
            color: error ? AppTokens.colorBadText : AppTokens.colorGoodText,
          ),
        ),
      ),
    );
  }
}
