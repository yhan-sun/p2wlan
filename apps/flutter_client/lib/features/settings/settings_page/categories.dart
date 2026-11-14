part of '../settings_page.dart';

/// Second-level settings categories. These are NOT product navigation —
/// they are content navigation inside the Settings section, so they live
/// outside [P2WlanSection].
enum SettingsCategory {
  general,
  accountNetwork,
  advancedNetwork,
  developer;

  /// User-facing label in the given locale.
  String label(AppStrings strings) {
    return switch (this) {
      SettingsCategory.general => strings.settingsSectionGeneral,
      SettingsCategory.accountNetwork => strings.settingsSectionAccountNetwork,
      SettingsCategory.advancedNetwork =>
        strings.settingsSectionAdvancedNetwork,
      SettingsCategory.developer => strings.settingsSectionDeveloperDiagnostics,
    };
  }

  IconData get icon {
    return switch (this) {
      SettingsCategory.general => Icons.tune_rounded,
      SettingsCategory.accountNetwork => Icons.admin_panel_settings_outlined,
      SettingsCategory.advancedNetwork => Icons.router_outlined,
      SettingsCategory.developer => Icons.info_outline_rounded,
    };
  }
}

/// Categories to show for a given capability set. Categories without a real
/// capability are hidden entirely — never rendered as a row of disabled pages.
List<SettingsCategory> visibleSettingsCategories(PlatformCapabilities caps) {
  final categories = <SettingsCategory>[
    SettingsCategory.general,
    SettingsCategory.accountNetwork,
  ];
  if (caps.canActAsLocalVpnNode) {
    categories.add(SettingsCategory.advancedNetwork);
  }
  categories.add(SettingsCategory.developer);
  return categories;
}

/// Keep at least 500px for details before adding secondary navigation.
const _settingsDesktopSidebarBreakpoint = 800.0;
const _settingsTouchSidebarBreakpoint = 880.0;

bool _usesDesktopSettings(BuildContext context) =>
    AppTokens.isDesktopPlatform(Theme.of(context).platform);

enum _SettingsLayout { expanded, rootDetail }
