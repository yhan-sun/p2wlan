import 'package:flutter/material.dart';

/// User-level sections of the P2WLAN client.
///
/// Information architecture:
///
///   Desktop primary:  Home / Devices / Troubleshooting / Settings
///   Mobile primary:   Home / Devices / Settings
///
/// `tunnels` is an implementation-detail section (TUN interface, UDP bind,
/// overlay routes, MTU, lifecycle). It stays fully functional and routable,
/// but is deliberately NOT part of the primary navigation; later phases
/// surface it from Troubleshooting → Advanced diagnostics.
///
/// "Hide complexity, don't remove capability."
enum P2WlanSection {
  home(Icons.home_outlined),
  devices(Icons.hub_outlined),
  troubleshooting(Icons.monitor_heart_outlined),
  settings(Icons.settings_outlined),
  tunnels(Icons.cable_outlined);

  const P2WlanSection(this.icon);

  final IconData icon;

  /// Primary user-level destinations, in display order.
  static const List<P2WlanSection> primary = [
    home,
    devices,
    troubleshooting,
    settings,
  ];

  /// Sections not shown in the primary navigation but still routable.
  /// [P2WlanSection.tunnels] is the only secondary section today.
  static const List<P2WlanSection> secondary = [tunnels];

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
