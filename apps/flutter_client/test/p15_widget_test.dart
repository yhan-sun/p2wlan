import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/features/dashboard/dashboard_page.dart';
import 'package:p2wlan_flutter_client/features/diagnostics/diagnostics_page.dart';
import 'package:p2wlan_flutter_client/features/nodes/nodes_page.dart';
import 'package:p2wlan_flutter_client/features/settings/settings_page.dart';
import 'package:p2wlan_flutter_client/features/tunnels/tunnels_page.dart';

part 'p15_widget/dashboard_tests.dart';
part 'p15_widget/settings_tests.dart';
part 'p15_widget/nodes_tests.dart';
part 'p15_widget/tunnels_tests.dart';
part 'p15_widget/diagnostics_tests.dart';
part 'p15_widget/helpers.dart';

void main() {
  _registerDashboardTests();
  _registerSettingsTests();
  _registerNodesTests();
  _registerTunnelsTests();
  _registerDiagnosticsTests();
}
