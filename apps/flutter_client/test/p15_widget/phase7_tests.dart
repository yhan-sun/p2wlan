part of '../p15_widget_test.dart';

/// Phase 7 strict responsive, text-scale, and accessibility closure.
///
/// All tests in this file use strict `expect(tester.takeException(), isNull)`
/// — no layout error is tolerated.  If a RenderFlex overflow surfaces, the
/// test fails and the underlying widget must be fixed.
void _registerPhase7Tests() {
  // ──────────────────────────────────────────────────────────────────────
  // 7.1  Settings error ownership: errors must not leak across categories.
  // ──────────────────────────────────────────────────────────────────────

  group('Phase 7 error ownership', () {
    testWidgets(
      'Account save failure does not show error on General category',
      (tester) async {
        await _pumpSettings(tester, api: _FakeDiagnosticsApi(health: false));

        // Trigger a validation error on Account & Network.
        await _openCategory(tester, 'Account & Network');
        await tester.enterText(
          _settingsTextField('Control server'),
          'ftp://ctrl.example',
        );
        await tester.pump();
        await _tapSave(tester);

        // Error is visible on Account & Network.
        expect(find.textContaining('must use http or https'), findsOneWidget);

        // Switch to General — error must NOT appear.
        await _openCategory(tester, 'General');
        expect(find.textContaining('must use http or https'), findsNothing);
        expect(tester.takeException(), isNull);
      },
    );

    testWidgets('Account validation error persists when returning to Account', (
      tester,
    ) async {
      await _pumpSettings(tester, api: _FakeDiagnosticsApi(health: false));

      await _openCategory(tester, 'Account & Network');
      await tester.enterText(
        _settingsTextField('Control server'),
        'ftp://ctrl.example',
      );
      await tester.pump();
      await _tapSave(tester);
      expect(find.textContaining('must use http or https'), findsOneWidget);

      // Leave to General, then come back — error should still be there.
      await _openCategory(tester, 'General');
      await _openCategory(tester, 'Account & Network');
      expect(find.textContaining('must use http or https'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('Successful save clears the category error', (tester) async {
      final stores = await _pumpSettings(
        tester,
        api: _FakeDiagnosticsApi(health: false),
      );

      await _openCategory(tester, 'Account & Network');
      // Enter invalid URL → save → error.
      await tester.enterText(
        _settingsTextField('Control server'),
        'ftp://ctrl.example',
      );
      await tester.pump();
      await _tapSave(tester);
      expect(find.textContaining('must use http or https'), findsOneWidget);

      // Fix the URL → save → error gone.
      await tester.enterText(
        _settingsTextField('Control server'),
        'https://ctrl.example',
      );
      await tester.pump();
      await _tapSave(tester);
      await _waitFor(
        tester,
        () =>
            stores.settingsStore.settings.controlServer ==
            'https://ctrl.example',
      );
      expect(find.textContaining('must use http or https'), findsNothing);
      expect(tester.takeException(), isNull);
    });

    testWidgets(
      'Developer diagnostics error stays scoped to Developer category',
      (tester) async {
        await _pumpSettings(tester, api: _FakeDiagnosticsApi(health: false));

        // Trigger a Developer diagnostics URL validation error.
        await _openCategory(tester, 'Developer & Diagnostics');
        await tester.enterText(
          _settingsTextField('Diagnostics URL'),
          'ftp://127.0.0.1:39277',
        );
        await tester.pump();
        await _tapSave(tester);

        // Error visible on Developer.
        expect(
          find.text('Diagnostics URL must use http or https'),
          findsOneWidget,
        );

        // Switch to Advanced Network — error must not leak.
        await _openCategory(tester, 'Advanced Network');
        expect(
          find.text('Diagnostics URL must use http or https'),
          findsNothing,
        );
        expect(tester.takeException(), isNull);
      },
    );
  });

  // ──────────────────────────────────────────────────────────────────────
  // 7.2  Settings leave guard: dirty discard dialog.
  // ──────────────────────────────────────────────────────────────────────

  group('Phase 7 leave guard', () {
    testWidgets('dirty Settings → Continue editing → stays on Settings', (
      tester,
    ) async {
      final stores = await _pumpSettingsShell(tester, const Size(900, 1000));
      addTearDown(stores.dispose);

      // Make a category dirty.
      await tester.tap(find.text('Advanced Network').last);
      await tester.pumpAndSettle();
      await tester.enterText(_settingsTextField('MTU'), '1280');
      await tester.pump();
      expect(find.text('Unsaved changes'), findsOneWidget);

      // Try to navigate to Home via sidebar.
      await tester.tap(find.text('Home'));
      await tester.pumpAndSettle();

      // Discard dialog appears.
      expect(find.text('Discard changes'), findsOneWidget);
      expect(find.text('Continue editing'), findsOneWidget);

      // Continue editing → stay on Settings.
      await tester.tap(find.text('Continue editing'));
      await tester.pumpAndSettle();
      expect(find.text('Unsaved changes'), findsOneWidget);
      expect(find.text('Interface name'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('dirty Settings → tap Home → Discard → navigates to Home', (
      tester,
    ) async {
      final stores = await _pumpSettingsShell(tester, const Size(900, 1000));
      addTearDown(stores.dispose);

      await tester.tap(find.text('Advanced Network').last);
      await tester.pumpAndSettle();
      await tester.enterText(_settingsTextField('MTU'), '1280');
      await tester.pump();
      expect(find.text('Unsaved changes'), findsOneWidget);

      await tester.tap(find.text('Home'));
      await tester.pumpAndSettle();
      expect(find.text('Discard changes'), findsOneWidget);

      // Discard → navigate to Home.
      await tester.tap(find.text('Discard changes'));
      await tester.pumpAndSettle();
      expect(find.text('Unsaved changes'), findsNothing);
      expect(find.text('Interface name'), findsNothing);
      expect(tester.takeException(), isNull);
    });

    testWidgets('clean Settings → tap Home → no dialog, navigates directly', (
      tester,
    ) async {
      final stores = await _pumpSettingsShell(tester, const Size(900, 1000));
      addTearDown(stores.dispose);

      // No dirty state.
      expect(find.text('Unsaved changes'), findsNothing);

      await tester.tap(find.text('Home'));
      await tester.pumpAndSettle();

      // No dialog.
      expect(find.text('Discard changes'), findsNothing);
      expect(find.text('Continue editing'), findsNothing);
      expect(tester.takeException(), isNull);
    });

    testWidgets('mobile bottom nav: dirty Settings → Discard → navigates', (
      tester,
    ) async {
      final stores = await _pumpSettingsShell(
        tester,
        const Size(390, 844),
        capabilities: PlatformCapabilities.fromPlatform('android'),
      );
      addTearDown(stores.dispose);

      // Open a category and dirty it.
      await tester.tap(find.text('Account & Network'));
      await tester.pumpAndSettle();
      await tester.enterText(
        _settingsTextField('Control server'),
        'https://ctrl.example',
      );
      await tester.pump();
      expect(find.text('Unsaved changes'), findsOneWidget);

      // Tap Home in bottom nav.
      final homeBottom = find.descendant(
        of: find.byType(NavigationBar),
        matching: find.text('Home'),
      );
      expect(homeBottom, findsOneWidget);
      await tester.tap(homeBottom);
      await tester.pumpAndSettle();

      // Discard dialog.
      expect(find.text('Discard changes'), findsOneWidget);
      await tester.tap(find.text('Discard changes'));
      await tester.pumpAndSettle();
      expect(find.text('Unsaved changes'), findsNothing);
      expect(tester.takeException(), isNull);
    });

    testWidgets(
      'mobile overflow menu: dirty Settings → Troubleshooting guard',
      (tester) async {
        final stores = await _pumpSettingsShell(
          tester,
          const Size(390, 844),
          capabilities: PlatformCapabilities.fromPlatform('android'),
        );
        addTearDown(stores.dispose);

        // Dirty a category.
        await tester.tap(find.text('Account & Network'));
        await tester.pumpAndSettle();
        await tester.enterText(
          _settingsTextField('Control server'),
          'https://ctrl.example',
        );
        await tester.pump();
        expect(find.text('Unsaved changes'), findsOneWidget);

        // Open the mobile overflow menu and tap Troubleshooting.
        await tester.tap(find.byIcon(Icons.more_horiz_rounded));
        await tester.pumpAndSettle();
        // The overflow menu shows Troubleshooting.
        final tsItem = find.text('Troubleshooting');
        expect(tsItem, findsWidgets);
        await tester.tap(tsItem.last);
        await tester.pumpAndSettle();

        // Guard dialog appears.
        expect(find.text('Discard changes'), findsOneWidget);
        expect(find.text('Continue editing'), findsOneWidget);

        // Discard → navigate to Troubleshooting.
        await tester.tap(find.text('Discard changes'));
        await tester.pumpAndSettle();
        expect(find.text('Unsaved changes'), findsNothing);
        expect(tester.takeException(), isNull);
      },
    );

    testWidgets('language switch does not trigger leave guard', (tester) async {
      final stores = await _pumpSettingsShell(tester, const Size(900, 1000));
      addTearDown(stores.dispose);

      // Switch language — immediate save, no dirty bar, no guard on leave.
      await tester.tap(find.text('General'));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('language-en')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('简体中文').last);
      await tester.pump();
      await _waitFor(
        tester,
        () => stores.settingsStore.settings.languageCode == 'zh-Hans',
      );
      await _waitForSaveComplete(tester, const ValueKey('theme-system'));

      // Navigate to Home — no guard (language is immediate, not dirty).
      // UI is now in Chinese after language switch, so Home is '首页'.
      await tester.tap(find.text('首页'));
      await tester.pumpAndSettle();
      expect(find.text('Discard changes'), findsNothing);
      expect(find.text('放弃更改'), findsNothing);
      expect(tester.takeException(), isNull);
    });

    // ───────────────────────────────────────────────────────────────────
    // Expanded desktop (1280) Settings leave guard via DesktopSidebar.
    // ───────────────────────────────────────────────────────────────────

    // In the expanded desktop layout (1280×800) the _SaveBar lives at the
    // bottom of the category detail ListView and may be outside the viewport.
    // The leave-guard is driven by the onDirtyChanged callback (not by the
    // SaveBar's visibility), so the guard dialog fires regardless. Tests
    // therefore verify the guard dialog and dirty draft state rather than
    // the SaveBar's off-screen Text widget.

    testWidgets('expanded desktop: dirty Settings → sidebar Home → guard', (
      tester,
    ) async {
      final stores = await _pumpSettingsShell(
        tester,
        const Size(1280, 800),
        capabilities: PlatformCapabilities.fromPlatform('macos'),
      );
      addTearDown(stores.dispose);

      // Verify we're on expanded layout with DesktopSidebar.
      expect(find.byType(DesktopSidebar), findsOneWidget);
      expect(find.byType(NavigationBar), findsNothing);

      // Open Advanced Network and dirty it.
      await tester.tap(find.text('Advanced Network').last);
      await tester.pumpAndSettle();
      await tester.enterText(_settingsTextField('MTU'), '1280');
      await tester.pump();
      // The dirty state is tracked via onDirtyChanged regardless of whether
      // the SaveBar is in the viewport.

      // Click Home in the DesktopSidebar.
      final sidebarHome = find.descendant(
        of: find.byType(DesktopSidebar),
        matching: find.text('Home'),
      );
      expect(sidebarHome, findsOneWidget);
      await tester.tap(sidebarHome);
      await tester.pumpAndSettle();

      // Discard dialog appears — the leave guard fired.
      expect(find.text('Discard changes'), findsOneWidget);
      expect(find.text('Continue editing'), findsOneWidget);

      // Continue editing → stay on Settings. The guard dialog is dismissed
      // and we're back on the Advanced Network detail page. The dirty draft
      // persists (the MTU field still shows the edited value).
      await tester.tap(find.text('Continue editing'));
      await tester.pumpAndSettle();
      expect(find.text('Interface name'), findsOneWidget);
      // The MTU field still holds the unsaved draft value.
      expect(
        tester.widget<TextField>(_settingsTextField('MTU')).controller?.text,
        '1280',
      );
      expect(tester.takeException(), isNull);
    });

    testWidgets('expanded desktop: dirty Settings → Discard → navigates Home, '
        'draft cleared on return', (tester) async {
      final stores = await _pumpSettingsShell(
        tester,
        const Size(1280, 800),
        capabilities: PlatformCapabilities.fromPlatform('macos'),
      );
      addTearDown(stores.dispose);

      // Dirty Advanced Network.
      await tester.tap(find.text('Advanced Network').last);
      await tester.pumpAndSettle();
      await tester.enterText(_settingsTextField('MTU'), '1280');
      await tester.pump();

      // Navigate via sidebar Home → Discard.
      final sidebarHome = find.descendant(
        of: find.byType(DesktopSidebar),
        matching: find.text('Home'),
      );
      await tester.tap(sidebarHome);
      await tester.pumpAndSettle();
      // The guard fired because onDirtyChanged set _settingsDirty.
      expect(find.text('Discard changes'), findsOneWidget);
      await tester.tap(find.text('Discard changes'));
      await tester.pumpAndSettle();

      // We're on Home now — no unsaved changes, no dirty bar.
      expect(find.text('Unsaved changes'), findsNothing);
      expect(find.text('Interface name'), findsNothing);

      // Navigate back to Settings — the old SettingsPage was disposed,
      // so the draft should not exist.
      final sidebarSettings = find.descendant(
        of: find.byType(DesktopSidebar),
        matching: find.text('Settings'),
      );
      await tester.tap(sidebarSettings);
      await tester.pumpAndSettle();
      expect(find.text('Unsaved changes'), findsNothing);
      // The MTU field should show the persisted value, not '1280'.
      final mtuField = _settingsTextField('MTU');
      if (mtuField.evaluate().isNotEmpty) {
        expect(
          tester.widget<TextField>(mtuField).controller?.text,
          isNot('1280'),
        );
      }
      expect(tester.takeException(), isNull);
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // 7.3  Responsive matrix: strict — no layout error at any size.
  // ──────────────────────────────────────────────────────────────────────

  group('Phase 7 responsive matrix', () {
    // Mobile platform sizes (compact, phone bottom-bar navigation).
    for (final entry in const <(Size, TargetPlatform)>[
      (Size(360, 800), TargetPlatform.android),
      (Size(390, 844), TargetPlatform.iOS),
      (Size(844, 390), TargetPlatform.android),
    ]) {
      final size = entry.$1;
      final platform = entry.$2;
      testWidgets('shell ${size.width.toInt()}x${size.height.toInt()} '
          '${platform.name} renders without layout error', (tester) async {
        await _pumpStrictShell(tester, size, platform: platform);
        expect(tester.takeException(), isNull);
      });
    }

    // Compact desktop: rail, never phone bottom-bar.
    for (final platform in [TargetPlatform.windows, TargetPlatform.linux]) {
      testWidgets('500x700 ${platform.name} compact desktop renders without '
          'BottomNavigation', (tester) async {
        await _pumpStrictShell(
          tester,
          const Size(500, 700),
          platform: platform,
        );
        expect(find.byType(NavigationBar), findsNothing);
        expect(find.byType(AppNavRail), findsOneWidget);
        expect(tester.takeException(), isNull);
      });
    }

    // macOS expanded.
    testWidgets(
      '1280x800 macOS expanded renders DesktopSidebar without layout error',
      (tester) async {
        await _pumpStrictShell(
          tester,
          const Size(1280, 800),
          platform: TargetPlatform.macOS,
        );
        expect(find.byType(DesktopSidebar), findsOneWidget);
        expect(find.byType(NavigationBar), findsNothing);
        expect(tester.takeException(), isNull);
      },
    );

    // Medium and expanded desktop sizes.
    for (final size in const [
      Size(700, 1000),
      Size(900, 1000),
      Size(1024, 768),
      Size(1200, 800),
      Size(1280, 800),
      Size(1440, 900),
      Size(1920, 1080),
    ]) {
      testWidgets(
        'shell ${size.width.toInt()}x${size.height.toInt()} renders without '
        'layout error',
        (tester) async {
          await _pumpStrictShell(tester, size);
          expect(tester.takeException(), isNull);
        },
      );
    }
  });

  // ──────────────────────────────────────────────────────────────────────
  // 7.4  Text-scale accessibility: strict — no overflow at large scales.
  // ──────────────────────────────────────────────────────────────────────

  group('Phase 7 text scale', () {
    // 360×800 at various text scales — the smallest phone size.
    for (final scale in [1.0, 1.3, 1.5]) {
      testWidgets('360x800 scale $scale Home renders without layout error', (
        tester,
      ) async {
        await _pumpStrictShell(
          tester,
          const Size(360, 800),
          platform: TargetPlatform.android,
          textScale: scale,
        );
        expect(tester.takeException(), isNull);
        // Verify mobile bottom navigation has exactly 3 destinations.
        final navBar = tester.widget<NavigationBar>(find.byType(NavigationBar));
        expect(navBar.destinations.length, 3);
      });
    }

    // 390×844 — four-page real-shell coverage at 1.3 and 1.5.
    for (final scale in [1.3, 1.5]) {
      testWidgets('390x844 scale $scale Home renders without layout error', (
        tester,
      ) async {
        await _pumpStrictShell(
          tester,
          const Size(390, 844),
          platform: TargetPlatform.iOS,
          textScale: scale,
        );
        expect(tester.takeException(), isNull);
      });

      testWidgets('390x844 scale $scale Devices renders without layout error', (
        tester,
      ) async {
        await _pumpStrictShell(
          tester,
          const Size(390, 844),
          platform: TargetPlatform.iOS,
          textScale: scale,
          section: P2WlanSection.devices,
        );
        expect(tester.takeException(), isNull);
      });

      testWidgets(
        '390x844 scale $scale Troubleshooting renders without layout error',
        (tester) async {
          await _pumpStrictShell(
            tester,
            const Size(390, 844),
            platform: TargetPlatform.iOS,
            textScale: scale,
            section: P2WlanSection.troubleshooting,
          );
          expect(tester.takeException(), isNull);
        },
      );

      testWidgets(
        '390x844 scale $scale Settings renders without layout error',
        (tester) async {
          await _pumpStrictShell(
            tester,
            const Size(390, 844),
            platform: TargetPlatform.iOS,
            textScale: scale,
            section: P2WlanSection.settings,
          );
          expect(tester.takeException(), isNull);
        },
      );
    }

    // Desktop text-scale coverage.
    for (final scale in [1.3, 1.5]) {
      testWidgets('1280x900 scale $scale renders without layout error', (
        tester,
      ) async {
        await _pumpStrictShell(tester, const Size(1280, 900), textScale: scale);
        expect(tester.takeException(), isNull);
      });
    }
  });

  // ──────────────────────────────────────────────────────────────────────
  // 7.5  Page coverage at normal scale — strict, no layout error.
  // ──────────────────────────────────────────────────────────────────────

  group('Phase 7 page coverage', () {
    for (final dark in [false, true]) {
      for (final entry in <String, Widget Function(_Stores)>{
        'Dashboard': (s) => DashboardPage(
          settingsStore: s.settingsStore,
          statusStore: s.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
        ),
        'Nodes': (s) => NodesPage(
          settingsStore: s.settingsStore,
          statusStore: s.statusStore,
          controlApi: _FakeControlApi(),
        ),
        'Settings': (s) => SettingsPage(
          settingsStore: s.settingsStore,
          statusStore: s.statusStore,
          onLogout: () {},
          capabilities: PlatformCapabilities.fromPlatform('macos'),
        ),
        'Diagnostics': (s) => DiagnosticsPage(
          statusStore: s.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      }.entries) {
        for (final size in const [
          Size(390, 844),
          Size(700, 1000),
          Size(1280, 900),
        ]) {
          testWidgets('$entry ${size.width.toInt()}x${size.height.toInt()} '
              '${dark ? 'dark' : 'light'}', (tester) async {
            await tester.binding.setSurfaceSize(size);
            addTearDown(() => tester.binding.setSurfaceSize(null));
            final stores = await _smokeStores(tester);
            addTearDown(stores.dispose);
            await tester.pumpWidget(
              _DesignSystemHost(dark: dark, child: entry.value(stores)),
            );
            await tester.pumpAndSettle();
            expect(tester.takeException(), isNull);
          });
        }
      }
    }
  });

  // ──────────────────────────────────────────────────────────────────────
  // 7.6  Settings category detail at large text scale — strict.
  //
  // Phase 7.1 covered the shell-level Settings root at 1.3/1.5 but never
  // entered a real category detail. These tests pump the full P2WlanShell,
  // navigate to Settings, open a category, and verify strict no-overflow at
  // 1.5× text scale.
  //
  // The helper [_pumpSettingsShell] accepts a [textScale] parameter that
  // wraps the shell in a [MediaQuery] with a linear text scaler at initial
  // pump time, so the platform override, capabilities, and navigation state
  // are all consistent — no re-pump is needed.
  // ──────────────────────────────────────────────────────────────────────

  group('Phase 7.2 Settings detail large text', () {
    testWidgets(
      '390x844 iOS scale 1.5 Account & Network detail renders without overflow',
      (tester) async {
        final stores = await _pumpSettingsShell(
          tester,
          const Size(390, 844),
          capabilities: PlatformCapabilities.fromPlatform('ios'),
          textScale: 1.5,
        );
        addTearDown(stores.dispose);

        // Open the Account & Network category.
        await tester.tap(find.text('Account & Network'));
        await tester.pumpAndSettle();

        // Verify key Account fields are present (possibly off-screen →
        // scroll into view).
        await tester.ensureVisible(find.text('Control server'));
        expect(find.text('Control server'), findsOneWidget);
        await tester.ensureVisible(find.text('Network ID'));
        expect(find.text('Network ID'), findsOneWidget);
        await tester.ensureVisible(find.text('Requested virtual IP'));
        expect(find.text('Requested virtual IP'), findsOneWidget);
        // Credential section is visible.
        expect(find.text('Authentication'), findsOneWidget);
        expect(tester.takeException(), isNull);
      },
    );

    testWidgets(
      '390x844 scale 1.5 Advanced Network detail renders without overflow',
      (tester) async {
        // Advanced Network requires canActAsLocalVpnNode == true. On macOS
        // the shell uses the rail layout at 390px (_isDesktopShell is true),
        // and Settings uses the rootDetail layout (< 880px breakpoint).
        const caps = PlatformCapabilities(
          canControlLocalDaemon: true,
          canRequestElevation: true,
          canVerifyRoutes: true,
          canRepairRoutes: true,
          canOpenLocalLogs: true,
          canCreateSupportBundle: true,
          canUseSystemTray: true,
          canActAsLocalVpnNode: true,
          canManageRemoteDevices: true,
        );
        final stores = await _pumpSettingsShell(
          tester,
          const Size(390, 844),
          capabilities: caps,
          textScale: 1.5,
        );
        addTearDown(stores.dispose);

        // Open the Advanced Network category.
        await tester.tap(find.text('Advanced Network'));
        await tester.pumpAndSettle();

        // Verify Advanced Network fields are reachable via scroll.
        await tester.ensureVisible(find.text('Manual/offline mode'));
        expect(find.text('Manual/offline mode'), findsOneWidget);
        await tester.ensureVisible(find.text('Interface name'));
        expect(find.text('Interface name'), findsOneWidget);
        await tester.ensureVisible(find.text('MTU'));
        expect(find.text('MTU'), findsOneWidget);
        await tester.ensureVisible(find.text('Overlay CIDR'));
        expect(find.text('Overlay CIDR'), findsOneWidget);
        await tester.ensureVisible(find.text('UDP bind'));
        expect(find.text('UDP bind'), findsOneWidget);
        await tester.ensureVisible(find.text('Socket pool'));
        expect(find.text('Socket pool'), findsOneWidget);
        await tester.ensureVisible(find.text('Relay candidates'));
        expect(find.text('Relay candidates'), findsOneWidget);
        expect(tester.takeException(), isNull);
      },
    );

    testWidgets(
      '390x844 scale 1.5 Advanced Network Save bar remains reachable',
      (tester) async {
        const caps = PlatformCapabilities(
          canControlLocalDaemon: true,
          canRequestElevation: true,
          canVerifyRoutes: true,
          canRepairRoutes: true,
          canOpenLocalLogs: true,
          canCreateSupportBundle: true,
          canUseSystemTray: true,
          canActAsLocalVpnNode: true,
          canManageRemoteDevices: true,
        );
        tester.view.physicalSize = const Size(390, 844);
        tester.view.devicePixelRatio = 1;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);

        final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
        final clean = _mutateSnapshot(snapshot, _clearPeerErrors);
        final stores = (await tester.runAsync(
          () => _makeStores(
            api: _FakeDiagnosticsApi(health: true, snapshot: clean),
          ),
        ))!;
        addTearDown(stores.dispose);
        await stores.statusStore.refresh();

        await tester.pumpWidget(
          _TestApp(
            child: MediaQuery(
              data: MediaQueryData(textScaler: TextScaler.linear(1.5)),
              child: SettingsPage(
                settingsStore: stores.settingsStore,
                statusStore: stores.statusStore,
                capabilities: caps,
                onLogout: () {},
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();

        // Open the Advanced Network category.
        await tester.tap(find.text('Advanced Network'));
        await tester.pumpAndSettle();

        // Modify a safe field (MTU) to produce unsaved changes.
        final mtuField = _settingsTextField('MTU');
        expect(mtuField, findsOneWidget);
        await tester.ensureVisible(mtuField);
        await tester.pumpAndSettle();
        await tester.enterText(mtuField, '1280');
        await tester.pump();

        // Verify the text was actually entered.
        expect(tester.widget<TextField>(mtuField).controller?.text, '1280');

        // In a narrow viewport at 1.5× text scale, the _SaveBar (added only
        // when dirty) is below the viewport + cache extent and may not be
        // built yet. Scroll down until it appears, then verify reachability.
        // Find the Scrollable that contains the MTU field (the category
        // detail's ListView).
        final detailScrollable = find.ancestor(
          of: mtuField,
          matching: find.byType(Scrollable),
        );
        expect(detailScrollable, findsOneWidget);
        var scrollAttempts = 0;
        while (find
                .byKey(const Key('settings-save-button'))
                .evaluate()
                .isEmpty &&
            scrollAttempts < 30) {
          await tester.drag(detailScrollable, const Offset(0, -400));
          await tester.pump();
          scrollAttempts++;
        }

        // The dirty bar with "Unsaved changes" appears.
        expect(find.text('Unsaved changes'), findsOneWidget);

        // The Save button must be reachable — either already visible or
        // reachable via scroll/ensureVisible. It must NOT be clipped or
        // permanently unreachable.
        final saveButton = find.byKey(const Key('settings-save-button'));
        expect(saveButton, findsOneWidget);
        await tester.ensureVisible(saveButton);
        await tester.pumpAndSettle();
        // After ensureVisible, the Save button is on-screen.
        expect(
          tester.getCenter(saveButton).dy,
          lessThanOrEqualTo(
            tester.view.physicalSize.height / tester.view.devicePixelRatio,
          ),
        );
        expect(tester.getCenter(saveButton).dy, greaterThanOrEqualTo(0.0));
        expect(tester.takeException(), isNull);
      },
    );

    testWidgets(
      '360x800 scale 1.5 Account & Network detail renders without overflow',
      (tester) async {
        final stores = await _pumpSettingsShell(
          tester,
          const Size(360, 800),
          capabilities: PlatformCapabilities.fromPlatform('android'),
          textScale: 1.5,
        );
        addTearDown(stores.dispose);

        // Open the Account & Network category.
        await tester.tap(find.text('Account & Network'));
        await tester.pumpAndSettle();

        await tester.ensureVisible(find.text('Control server'));
        expect(find.text('Control server'), findsOneWidget);
        await tester.ensureVisible(find.text('Network ID'));
        expect(find.text('Network ID'), findsOneWidget);
        await tester.ensureVisible(find.text('Requested virtual IP'));
        expect(find.text('Requested virtual IP'), findsOneWidget);
        expect(find.text('Authentication'), findsOneWidget);
        expect(tester.takeException(), isNull);
      },
    );
  });
}

/// Pumps the full [P2WlanShell] at [size] with strict exception checking.
///
/// When [platform] is set, [debugDefaultTargetPlatformOverride] is used so
/// the shell's `_isDesktopShell` logic resolves correctly for desktop vs
/// mobile platforms.
///
/// When [textScale] > 1.0, wraps the shell in a [MediaQuery] with a linear
/// text scaler to exercise large-text accessibility.
///
/// When [section] is provided, the shell is pumped and then navigated to
/// that section via the shell's own navigation (bottom bar, rail, or sidebar).
Future<void> _pumpStrictShell(
  WidgetTester tester,
  Size size, {
  TargetPlatform? platform,
  double textScale = 1.0,
  P2WlanSection? section,
}) async {
  // Reset the element tree so a previous pump's shell state does not leak.
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.binding.setSurfaceSize(size);
  addTearDown(() => tester.binding.setSurfaceSize(null));

  if (platform != null) {
    debugDefaultTargetPlatformOverride = platform;
    // Must be reset before the test body ends — the framework's
    // _verifyInvariants asserts that foundation debug variables are unset
    // before it runs addTearDown callbacks.
  }

  final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
  final clean = _mutateSnapshot(snapshot, _clearPeerErrors);
  final stores = (await tester.runAsync(
    () => _makeStores(api: _FakeDiagnosticsApi(health: true, snapshot: clean)),
  ))!;
  addTearDown(stores.dispose);
  await stores.statusStore.refresh();

  final platformCapabilities = platform != null
      ? PlatformCapabilities.fromPlatform(platform.name)
      : PlatformCapabilities.fromPlatform('macos');

  Widget shell = P2WlanShell(
    settingsStore: stores.settingsStore,
    statusStore: stores.statusStore,
    capabilities: platformCapabilities,
  );

  if (textScale != 1.0) {
    shell = MediaQuery(
      data: MediaQueryData(textScaler: TextScaler.linear(textScale)),
      child: shell,
    );
  }

  await tester.pumpWidget(_DesignSystemHost(dark: false, child: shell));
  await tester.pumpAndSettle();

  // Navigate to the requested section if not Home.
  if (section != null && section != P2WlanSection.home) {
    // Try sidebar first (expanded desktop), then rail (medium), then
    // bottom nav (compact mobile).
    final sidebarFinder = find.descendant(
      of: find.byType(DesktopSidebar),
      matching: find.text(
        section.name == 'troubleshooting'
            ? 'Troubleshooting'
            : section.name[0].toUpperCase() + section.name.substring(1),
      ),
    );
    final railFinder = find.descendant(
      of: find.byType(AppNavRail),
      matching: find.text(
        section.name == 'troubleshooting'
            ? 'Troubleshooting'
            : section.name[0].toUpperCase() + section.name.substring(1),
      ),
    );
    final bottomFinder = find.descendant(
      of: find.byType(NavigationBar),
      matching: find.text(
        section.name == 'troubleshooting'
            ? 'Troubleshooting'
            : section.name[0].toUpperCase() + section.name.substring(1),
      ),
    );

    // For Troubleshooting on mobile (not in bottom nav), use overflow menu.
    if (section == P2WlanSection.troubleshooting &&
        sidebarFinder.evaluate().isEmpty &&
        railFinder.evaluate().isEmpty &&
        bottomFinder.evaluate().isEmpty) {
      // Mobile: open the overflow menu.
      final menu = find.byType(PopupMenuButton);
      if (menu.evaluate().isNotEmpty) {
        await tester.tap(menu);
        await tester.pumpAndSettle();
        await tester.tap(find.text('Troubleshooting').last);
        await tester.pumpAndSettle();
      }
    } else {
      final target = sidebarFinder.evaluate().isNotEmpty
          ? sidebarFinder
          : railFinder.evaluate().isNotEmpty
          ? railFinder
          : bottomFinder;
      if (target.evaluate().isNotEmpty) {
        await tester.ensureVisible(target);
        await tester.pumpAndSettle();
        await tester.tap(target);
        await tester.pumpAndSettle();
      }
    }
  }

  // Reset before returning — the framework's _verifyInvariants asserts that
  // foundation debug variables are unset before it runs addTearDown callbacks.
  debugDefaultTargetPlatformOverride = null;
}
