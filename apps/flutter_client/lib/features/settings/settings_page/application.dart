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
          const SizedBox(height: 16),
        ],
        _PreferenceRow(
          showDivider: false,
          label: strings.closeBehavior,
          subtitle: strings.closeBehaviorHelper,
          trailing: AppSelect<String>(
            width: 248,
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
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _PreferenceRow(
          label: _startupLabel(widget.strings),
          subtitle: _startupHelper(widget.strings),
          trailing: Switch(
            key: const ValueKey('settings-start-at-login-switch'),
            value: _enabled,
            onChanged: _loading ? null : _setEnabled,
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
    ? '登录桌面系统后启动应用，并在登录状态和首次配置有效时自动连接已配置的 P2WLAN 网络。'
    : 'Launches the desktop app at login and reconnects the configured P2WLAN network when the account and onboarding state are valid.';

String _startupReadError(AppStrings strings) => strings.isZh
    ? '无法读取系统登录自启设置。请检查当前用户权限后重试。'
    : 'Unable to read the desktop login-startup setting. Check the current user permissions and try again.';

String _startupUpdateError(AppStrings strings) => strings.isZh
    ? '无法更新系统登录自启设置。请检查当前用户权限后重试。'
    : 'Unable to update the desktop login-startup setting. Check the current user permissions and try again.';
