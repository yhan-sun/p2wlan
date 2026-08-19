part of '../settings_page.dart';

/// General: device name (dirty, explicit save), language + appearance (both
/// immediate — they never participate in the dirty draft).
class _GeneralSection extends StatelessWidget {
  const _GeneralSection({required this.state, required this.strings});

  final _SettingsPageState state;
  final AppStrings strings;

  @override
  Widget build(BuildContext context) {
    final languageCode = state.widget.settingsStore.settings.languageCode;
    final themeCode = state.widget.settingsStore.settings.themeMode;
    final saving = state._saving;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _SettingsField(
          controller: state._deviceNameController,
          label: strings.deviceName,
          helper: strings.deviceNameHelper,
        ),
        const SizedBox(height: AppTokens.space6),
        _PreferenceRow(
          label: strings.language,
          subtitle: strings.languageHelper,
          trailing: DropdownButton<String>(
            key: ValueKey('language-$languageCode'),
            value: AppLanguage.fromCode(languageCode).code,
            underline: const SizedBox.shrink(),
            items: [
              for (final language in AppLanguage.values)
                DropdownMenuItem(
                  value: language.code,
                  child: Text(strings.languageLabel(language.code)),
                ),
            ],
            onChanged: saving
                ? null
                : (value) {
                    if (value != null) state._saveLanguage(value);
                  },
          ),
        ),
        _PreferenceRow(
          label: strings.themeMode,
          subtitle: strings.themeModeHelper,
          trailing: DropdownButton<String>(
            key: ValueKey('theme-$themeCode'),
            value: AppThemeMode.fromCode(themeCode).code,
            underline: const SizedBox.shrink(),
            items: [
              DropdownMenuItem(
                value: AppThemeMode.system.code,
                child: Text(strings.themeSystem),
              ),
              DropdownMenuItem(
                value: AppThemeMode.light.code,
                child: Text(strings.themeLight),
              ),
              DropdownMenuItem(
                value: AppThemeMode.dark.code,
                child: Text(strings.themeDark),
              ),
            ],
            onChanged: saving
                ? null
                : (value) {
                    if (value != null) state._saveThemeMode(value);
                  },
          ),
        ),
      ],
    );
  }
}
