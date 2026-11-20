part of '../settings_page.dart';

/// Application: close-window behavior and per-user desktop login startup.
class _ApplicationSection extends StatelessWidget {
  const _ApplicationSection({required this.state, required this.strings});

  final _SettingsPageState state;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final saving = state._saving;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (state._startupRegistration.isSupported) ...[
          _StartupRegistrationPreference(
            registration: state._startupRegistration,
            strings: strings,
          ),
          if (!_usesDesktopSettings(context))
            const SizedBox(height: AppTokens.space16),
        ],
        if (state._capabilities.canConfigureWakeTarget)
          _WakeTargetPreference(
            store: state.widget.settingsStore,
            strings: strings,
          ),
        _PreferenceRow(
          showDivider: false,
          label: strings.closeBehavior,
          subtitle: strings.closeBehaviorHelper,
          trailing: AppSelect<String>(
            width: _settingsControlWidth,
            key: const ValueKey('settings-close-behavior-select'),
            menuTitle: strings.closeBehavior,
            value: state._closeBehavior,
            options: [
              AppSelectOption(
                value: 'keep-running',
                label: strings.closeBehaviorKeepRunning,
              ),
              AppSelectOption(
                value: 'stop-and-quit',
                label: strings.closeBehaviorStopAndQuit,
              ),
            ],
            onChanged: saving
                ? null
                : (value) =>
                      state._updateState(() => state._closeBehavior = value),
          ),
        ),
      ],
    );
  }
}

class _StartupRegistrationPreference extends StatefulWidget {
  const _StartupRegistrationPreference({
    required this.registration,
    required this.strings,
  });

  final StartupRegistration registration;
  final AppStrings strings;

  @override
  State<_StartupRegistrationPreference> createState() =>
      _StartupRegistrationPreferenceState();
}

class _StartupRegistrationPreferenceState
    extends State<_StartupRegistrationPreference> {
  var _enabled = false;
  var _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final enabled = await widget.registration.isEnabled();
      if (!mounted) return;
      setState(() {
        _enabled = enabled;
        _loading = false;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = _startupReadError(widget.strings);
      });
    }
  }

  Future<void> _setEnabled(bool enabled) async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      await widget.registration.setEnabled(enabled);
      final confirmed = await widget.registration.isEnabled();
      if (!mounted) return;
      setState(() {
        _enabled = confirmed;
        _loading = false;
        if (confirmed != enabled) {
          _error = _startupUpdateError(widget.strings);
        }
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = _startupUpdateError(widget.strings);
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final colors = P2WlanColors.of(context);
    final desktop = _usesDesktopSettings(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _PreferenceRow(
          label: _startupLabel(widget.strings),
          subtitle: _startupHelper(widget.strings),
          inlineControl: true,
          trailing: Switch(
            key: const ValueKey('settings-start-at-login-switch'),
            value: _enabled,
            onChanged: _loading ? null : _setEnabled,
            materialTapTargetSize: desktop
                ? MaterialTapTargetSize.shrinkWrap
                : null,
            inactiveThumbColor: desktop && !_loading ? colors.textMuted : null,
            trackOutlineColor: desktop
                ? WidgetStateProperty.resolveWith((states) {
                    if (states.contains(WidgetState.disabled) ||
                        states.contains(WidgetState.selected)) {
                      return null;
                    }
                    return colors.textMuted;
                  })
                : null,
          ),
        ),
        if (_error != null) ...[
          const SizedBox(height: 12),
          _SettingsErrorNotice(message: _error!),
        ],
      ],
    );
  }
}

String _startupLabel(AppStrings strings) =>
    strings.isZh ? '登录时启动 P2WLAN' : 'Launch P2WLAN at login';

String _startupHelper(AppStrings strings) => strings.isZh
    ? '登录桌面后启动；账号和本机配置就绪时自动连接。'
    : 'Launch at desktop sign-in and connect when your account and device are ready.';

String _startupReadError(AppStrings strings) => strings.isZh
    ? '无法读取系统登录自启设置。请检查当前用户权限后重试。'
    : 'Unable to read the desktop login-startup setting. Check the current user permissions and try again.';

String _startupUpdateError(AppStrings strings) => strings.isZh
    ? '无法更新系统登录自启设置。请检查当前用户权限后重试。'
    : 'Unable to update the desktop login-startup setting. Check the current user permissions and try again.';

class _WakeTargetPreference extends StatefulWidget {
  const _WakeTargetPreference({required this.store, required this.strings});

  final SettingsStore store;
  final AppStrings strings;

  @override
  State<_WakeTargetPreference> createState() => _WakeTargetPreferenceState();
}

class _WakeTargetPreferenceState extends State<_WakeTargetPreference> {
  bool _saving = false;

  Future<void> _save(bool value) async {
    setState(() => _saving = true);
    final strings = widget.strings;
    try {
      await widget.store.updateWakeAllowRemote(value);
      if (!mounted) return;
      showAppNotice(
        context,
        content: Text(strings.settingsSavedRestartRequired),
      );
    } catch (_) {
      if (!mounted) return;
      showAppNotice(
        context,
        content: Text(
          strings.isZh ? '无法保存远程开机设置。' : 'Could not save remote wake settings.',
        ),
      );
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final strings = widget.strings;
    return ListenableBuilder(
      listenable: widget.store,
      builder: (context, _) => _PreferenceRow(
        label: strings.isZh ? '允许本机远程开机' : 'Allow this PC to be woken remotely',
        subtitle: strings.isZh ? '登记本机的有线网卡，使同一局域网代理可以发送唤醒包。重启 P2WLAN 后生效。' : 'Register this PC’s wired adapter so an agent on its LAN can send a wake packet. Applies after P2WLAN restarts.',
        inlineControl: true,
        trailing: Switch(
          key: const ValueKey('settings-allow-remote-wake'),
          value: wakeAllowRemoteSetting(widget.store.settings) ?? false,
          onChanged: _saving ? null : _save,
        ),
      ),
    );
  }
}
