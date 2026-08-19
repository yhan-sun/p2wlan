import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/app/app_theme.dart';
import 'package:p2wlan_flutter_client/app/navigation.dart';
import 'package:p2wlan_flutter_client/app/p2wlan_colors.dart';
import 'package:p2wlan_flutter_client/core/api/control_api.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/capabilities/permission_preflight.dart';
import 'package:p2wlan_flutter_client/core/capabilities/platform_capabilities.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/features/dashboard/dashboard_page.dart';
import 'package:p2wlan_flutter_client/features/diagnostics/diagnostics_page.dart';
import 'package:p2wlan_flutter_client/features/auth/login_page.dart';
import 'package:p2wlan_flutter_client/features/nodes/nodes_page.dart';
import 'package:p2wlan_flutter_client/features/onboarding/onboarding_page.dart';
import 'package:p2wlan_flutter_client/features/settings/settings_page.dart';
import 'package:p2wlan_flutter_client/shared/widgets/app_nav_rail.dart';
import 'package:p2wlan_flutter_client/shared/widgets/desktop_sidebar.dart';
import 'package:p2wlan_flutter_client/shared/widgets/status_badge.dart';

part 'p15_widget/dashboard_tests.dart';
part 'p15_widget/settings_tests.dart';
part 'p15_widget/nodes_tests.dart';
part 'p15_widget/nodes_shell_tests.dart';
part 'p15_widget/network_tests.dart';
part 'p15_widget/diagnostics_tests.dart';
part 'p15_widget/troubleshooting_shell_tests.dart';
part 'p15_widget/design_system_tests.dart';
part 'p15_widget/localization_tests.dart';
part 'p15_widget/final_regression_tests.dart';
part 'p15_widget/helpers.dart';

void main() {
  _registerDashboardTests();
  _registerSettingsTests();
  _registerNodesTests();
  _registerNodesShellTests();
  _registerNetworkTests();
  _registerDiagnosticsTests();
  _registerTroubleshootingShellTests();
  _registerDesignSystemTests();
  _registerLocalizationTests();
  _registerFinalRegressionTests();
}
