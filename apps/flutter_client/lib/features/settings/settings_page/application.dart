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
        _PreferenceRow(
          label: strings.closeBehavior,
          subtitle: strings.closeBehaviorHelper,
          trailing: AppSelect<String>(
            expanded: MediaQuery.sizeOf(context).width < 520,
            width: 248,
            key: const ValueKey('settings-close-behavior-select'),
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
