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
          trailing: DropdownButton<String>(
            key: ValueKey('close-behavior-${state._closeBehavior}'),
            value: state._closeBehavior,
            underline: const SizedBox.shrink(),
            items: [
              DropdownMenuItem(
                value: 'keep-running',
                child: Text(strings.closeBehaviorKeepRunning),
              ),
              DropdownMenuItem(
                value: 'stop-and-quit',
                child: Text(strings.closeBehaviorStopAndQuit),
              ),
            ],
            onChanged: saving
                ? null
                : (value) {
                    if (value != null) {
                      state._updateState(() => state._closeBehavior = value);
                    }
                  },
          ),
        ),
      ],
    );
  }
}
