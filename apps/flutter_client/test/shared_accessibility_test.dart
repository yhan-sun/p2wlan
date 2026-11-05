import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/app/app_theme.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/presentation/network_overview.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/shared/widgets/app_select.dart';
import 'package:p2wlan_flutter_client/shared/widgets/network_scope_picker.dart';
import 'package:p2wlan_flutter_client/shared/widgets/status_badge.dart';

void main() {
  for (final dark in [false, true]) {
    for (final scale in [1.0, 2.0]) {
      testWidgets('phone controls are accessible dark=$dark text=$scale', (
        tester,
      ) async {
        debugDefaultTargetPlatformOverride = TargetPlatform.android;
        await tester.binding.setSurfaceSize(const Size(390, 844));
        addTearDown(() => tester.binding.setSurfaceSize(null));
        final semantics = tester.ensureSemantics();
        try {
          final settings = SettingsStore(
            tokenRepository: InMemorySecureTokenRepository(),
          );
          final status = StatusStore(
            settingsStore: settings,
            diagnosticsApi: DiagnosticsApi(),
            enableEventPolling: false,
          );
          addTearDown(() {
            status.dispose();
            settings.dispose();
          });

          await tester.pumpWidget(
            AppStringsScope(
              strings: AppStrings.fromCode('en'),
              child: MaterialApp(
                theme: dark ? AppTheme.darkTheme : AppTheme.lightTheme,
                home: Scaffold(
                  body: Builder(
                    builder: (context) => MediaQuery(
                      data: MediaQuery.of(context)
                          .copyWith(textScaler: TextScaler.linear(scale)),
                      child: ListView(
                        padding: const EdgeInsets.all(16),
                        children: [
                          NetworkScopePicker(
                            overview: NetworkOverview.read(status),
                            selectedId: null,
                            onChanged: (_) {},
                          ),
                          const SizedBox(height: 12),
                          AppSelect<String>(
                            expanded: true,
                            menuTitle: 'Theme mode',
                            value: 'system',
                            options: const [
                              AppSelectOption(
                                value: 'system',
                                label: 'Follow system',
                              ),
                              AppSelectOption(value: 'dark', label: 'Dark'),
                            ],
                            onChanged: (_) {},
                          ),
                          const SizedBox(height: 12),
                          const TextField(
                            decoration: InputDecoration(
                              labelText: 'Device name',
                              hintText: 'Enter a device name',
                              helperText: 'Visible to other room members.',
                            ),
                          ),
                          const SizedBox(height: 12),
                          const Wrap(
                            spacing: 8,
                            runSpacing: 8,
                            children: [
                              StatusBadge(
                                label: 'Connected',
                                tone: StatusTone.good,
                              ),
                              StatusBadge(
                                label: 'Check needed',
                                tone: StatusTone.warn,
                              ),
                              StatusBadge(
                                label: 'Failed',
                                tone: StatusTone.bad,
                              ),
                              StatusBadge(label: 'Stopped'),
                            ],
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ),
          );
          await tester.pumpAndSettle();
          await expectLater(tester, meetsGuideline(androidTapTargetGuideline));
          await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
          await expectLater(tester, meetsGuideline(textContrastGuideline));

          await tester.tap(find.byType(OutlinedButton));
          await tester.pumpAndSettle();
          await expectLater(tester, meetsGuideline(androidTapTargetGuideline));
          await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
          expect(tester.takeException(), isNull);
        } finally {
          semantics.dispose();
          debugDefaultTargetPlatformOverride = null;
        }
      });
    }
  }
}
