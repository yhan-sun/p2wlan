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
          textInputAction: TextInputAction.done,
          onSubmitted: saving
              ? null
              : (_) => state._saveCategory(SettingsCategory.general),
        ),
        const SizedBox(height: AppTokens.space6),
        _PreferenceRow(
          label: strings.language,
          subtitle: strings.languageHelper,
          trailing: AppSelect<String>(
            expanded: MediaQuery.sizeOf(context).width < 520,
            key: const ValueKey('settings-language-select'),
            menuTitle: strings.language,
            value: AppLanguage.fromCode(languageCode).code,
            options: [
              for (final language in AppLanguage.values)
                AppSelectOption(
                  value: language.code,
                  label: strings.languageLabel(language.code),
                ),
            ],
            onChanged: saving ? null : (value) => state._saveLanguage(value),
          ),
        ),
        _PreferenceRow(
          label: strings.themeMode,
          subtitle: strings.themeModeHelper,
          trailing: AppSelect<String>(
            expanded: MediaQuery.sizeOf(context).width < 520,
            key: const ValueKey('settings-theme-select'),
            menuTitle: strings.themeMode,
            value: AppThemeMode.fromCode(themeCode).code,
            options: [
              AppSelectOption(
                value: AppThemeMode.system.code,
                label: strings.themeSystem,
                icon: Icons.brightness_auto_outlined,
              ),
              AppSelectOption(
                value: AppThemeMode.light.code,
                label: strings.themeLight,
                icon: Icons.light_mode_outlined,
              ),
              AppSelectOption(
                value: AppThemeMode.dark.code,
                label: strings.themeDark,
                icon: Icons.dark_mode_outlined,
              ),
            ],
            onChanged: saving ? null : (value) => state._saveThemeMode(value),
          ),
        ),
      ],
    );
  }
}
