part of '../settings_page.dart';

/// Application: close-window behavior. Only reachable when the platform has a
/// system tray (the category is hidden otherwise).
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
        _error = widget.strings.startAtLoginUnavailable;
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
          _error = widget.strings.startAtLoginUpdateFailed;
        }
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = widget.strings.startAtLoginUpdateFailed;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _PreferenceRow(
          label: widget.strings.startAtLogin,
          subtitle: widget.strings.startAtLoginHelper,
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
