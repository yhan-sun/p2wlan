import 'package:flutter/material.dart';

/// User-level sections of the P2WLAN client.
///
/// Information architecture:
///
///   Desktop primary:  Home / Devices / Troubleshooting / Settings
///   Mobile primary:   Home / Devices / Settings
///
/// Troubleshooting carries the full technical surface (route verification,
/// repair, daemon restart, permissions, logs, raw data) behind its Advanced
/// section — there is intentionally no separate Tunnels section.
///
/// "Hide complexity, don't remove capability."
enum P2WlanSection {
  home(Icons.home_outlined),
  devices(Icons.hub_outlined),
  troubleshooting(Icons.monitor_heart_outlined),
  settings(Icons.settings_outlined);

  const P2WlanSection(this.icon);

  final IconData icon;

  /// Primary user-level destinations, in display order.
  static const List<P2WlanSection> primary = [
    home,
    devices,
    troubleshooting,
    settings,
  ];

  /// Permanent compact (phone) bottom-bar destinations — exactly three.
  /// Troubleshooting is deliberately absent: it is entered from the shell
  /// overflow menu today and from Home's "check issues" path.
  static const List<P2WlanSection> mobilePrimary = [home, devices, settings];

  /// Desktop sidebar grouping.
  static const List<List<P2WlanSection>> sidebarGroups = [
    [home, devices],
    [troubleshooting],
    [settings],
  ];
}
