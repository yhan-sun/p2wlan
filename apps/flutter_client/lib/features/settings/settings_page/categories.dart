part of '../settings_page.dart';

/// Second-level settings categories. These are NOT product navigation —
/// they are content navigation inside the Settings section, so they live
/// outside [P2WlanSection].
enum SettingsCategory {
  general,
  accountNetwork,
  application,
  advancedNetwork,
  developer;

  /// User-facing label in the given locale.
  String label(AppStrings strings) {
    return switch (this) {
      SettingsCategory.general => strings.settingsSectionGeneral,
      SettingsCategory.accountNetwork => strings.settingsSectionAccountNetwork,
      SettingsCategory.application => strings.settingsCategoryApplication,
      SettingsCategory.advancedNetwork =>
        strings.settingsSectionAdvancedNetwork,
      SettingsCategory.developer => strings.settingsSectionDeveloperDiagnostics,
    };
  }

  IconData get icon {
    return switch (this) {
      SettingsCategory.general => Icons.tune_rounded,
      SettingsCategory.accountNetwork => Icons.admin_panel_settings_outlined,
      SettingsCategory.application => Icons.desktop_windows_outlined,
      SettingsCategory.advancedNetwork => Icons.router_outlined,
      SettingsCategory.developer => Icons.code_rounded,
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
  if (caps.canUseSystemTray) {
    categories.add(SettingsCategory.application);
  }
  if (caps.canActAsLocalVpnNode) {
    categories.add(SettingsCategory.advancedNetwork);
  }
  if (caps.canControlLocalDaemon) {
    categories.add(SettingsCategory.developer);
  }
  return categories;
}

/// Desktop keeps the category rail down to the smallest supported window. The
/// global desktop sidebar and the settings rail are deliberately allowed to
/// coexist in a narrow two-pane layout; individual preference rows stack when
/// the detail column gets tight. Touch platforms retain the larger breakpoint
/// so a tablet still gets the same full-screen category route as a phone.
const _settingsDesktopSidebarBreakpoint = 520.0;
const _settingsTouchSidebarBreakpoint = 880.0;

enum _SettingsLayout { expanded, rootDetail }
