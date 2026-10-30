part of '../p15_widget_test.dart';

void _registerSettingsMotionTests() {
  testWidgets(
    'Settings preserves field and save action focus when reduced motion changes',
    (tester) async {
      addTearDown(
        tester.platformDispatcher.clearAccessibilityFeaturesTestValue,
      );
      await _pumpSettings(
        tester,
        api: _FakeDiagnosticsApi(health: false),
        physicalSize: const Size(800, 900),
      );
      await _openCategory(tester, 'General');
      final device = _settingsTextField('Device name');
      await tester.enterText(device, 'Preserved motion draft');
      await tester.pumpAndSettle();
      final fieldState = tester.state(device);
      final controller = tester.widget<TextField>(device).controller!;
      final slot = find.byKey(const Key('settings-save-slot'));
      final save = find.byKey(const Key('settings-save-button'));
      final undo = find.byKey(const Key('settings-undo-button'));
      final saveState = tester.state(save);
      for (final target in [device, save, undo]) {
        final node = target == device
            ? tester.widget<TextField>(device).focusNode!
            : Focus.of(
                tester.element(
                  find
                      .descendant(
                        of: target,
                        matching: find.byType(GestureDetector),
                      )
                      .first,
                ),
              );
        node.requestFocus();
        await tester.pump();
        expect(node.hasPrimaryFocus, isTrue);
        for (final reduced in [true, false]) {
          tester.platformDispatcher.accessibilityFeaturesTestValue =
              FakeAccessibilityFeatures(disableAnimations: reduced);
          await tester.pump();
          expect(node.hasPrimaryFocus, isTrue);
          expect(tester.state(device), same(fieldState));
          expect(tester.state(save), same(saveState));
          expect(controller.text, 'Preserved motion draft');
          expect(
            find.descendant(of: slot, matching: find.byType(AnimatedSize)),
            reduced ? findsNothing : findsOneWidget,
          );
          expect(tester.takeException(), isNull);
        }
      }
      await tester.tap(undo);
      await tester.pumpAndSettle();
      expect(save, findsNothing);
      expect(tester.getSize(slot).height, 0);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'Settings motion keeps only the current form during rapid switches',
    (tester) async {
      await _pumpSettings(
        tester,
        api: _FakeDiagnosticsApi(health: false),
        physicalSize: const Size(1280, 900),
      );
      final device = _settingsTextField('Device name');
      await tester.enterText(device, 'Preserved device draft');
      await tester.pumpAndSettle();
      final controller = tester.widget<TextField>(device).controller;
      final rail = find.byKey(const Key('settings-category-rail'));
      Future<void> select(String label) async {
        await tester.tap(find.descendant(of: rail, matching: find.text(label)));
        await tester.pump(const Duration(milliseconds: 40));
      }

      await select('Account & Connection');
      expect(device, findsNothing);
      expect(_settingsTextField('Control server'), findsOneWidget);
      await select('Advanced Network');
      expect(_settingsTextField('Control server'), findsNothing);
      expect(_settingsTextField('MTU'), findsOneWidget);
      await select('General');
      expect(_settingsTextField('MTU'), findsNothing);
      expect(tester.widget<TextField>(device).controller, same(controller));
      expect(controller!.text, 'Preserved device draft');
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'Settings save slot eases size and removes stale actions immediately',
    (tester) async {
      final repository = _PausedSettingsTokenRepository();
      addTearDown(repository.release);
      await _pumpSettings(
        tester,
        api: _FakeDiagnosticsApi(health: false),
        tokenRepository: repository,
        physicalSize: const Size(800, 900),
      );
      await _openCategory(tester, 'General');
      final slot = find.byKey(const Key('settings-save-slot'));
      expect(tester.getSize(slot).height, 0);
      await tester.enterText(_settingsTextField('Device name'), 'Edited demo');
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 70));
      final intermediateHeight = tester.getSize(slot).height;
      await tester.pumpAndSettle();
      expect(intermediateHeight, greaterThan(0));
      expect(intermediateHeight, lessThan(tester.getSize(slot).height));
      final save = find.byKey(const Key('settings-save-button'));
      final saveSize = tester.getSize(save);
      repository.pauseNextWrite();
      await _tapSave(tester);
      await _waitFor(tester, () => repository.waiting);
      expect(tester.getSize(save), saveSize);
      expect(tester.widget<FilledButton>(save).onPressed, isNull);
      repository.release(fail: true);
      await _waitFor(
        tester,
        () => find
            .text(AppStrings.fromCode('en').settingsSaveFailed)
            .evaluate()
            .isNotEmpty,
      );
      expect(tester.getSize(save), saveSize);
      await tester.tap(find.byKey(const Key('settings-undo-button')));
      await tester.pump();
      expect(save, findsNothing);
      expect(tester.getSize(slot).height, greaterThan(0));
      await tester.pumpAndSettle();
      expect(tester.getSize(slot).height, 0);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'Settings categories expose one keyboard action and clear focus feedback',
    (tester) async {
      final semantics = tester.ensureSemantics();
      try {
        await _pumpSettings(
          tester,
          api: _FakeDiagnosticsApi(health: false),
          physicalSize: const Size(790, 900),
        );
        final card = find.byKey(
          const ValueKey('settings-category-card-general'),
        );
        final mouse = await tester.createGesture(kind: PointerDeviceKind.mouse);
        addTearDown(mouse.removePointer);
        await mouse.addPointer(location: Offset.zero);
        await mouse.moveTo(tester.getCenter(card));
        await tester.pumpAndSettle();
        Material surface() => tester.widget<Material>(
          find.ancestor(of: card, matching: find.byType(Material)).first,
        );
        final colors = P2WlanColors.of(tester.element(card));
        expect(surface().color, colors.hoverSurface);
        final gesture = find
            .descendant(of: card, matching: find.byType(GestureDetector))
            .first;
        Focus.of(tester.element(gesture)).requestFocus();
        await tester.pumpAndSettle();
        final border = (surface().shape! as RoundedRectangleBorder).side;
        expect(
          border.color,
          Theme.of(tester.element(card)).colorScheme.primary,
        );
        expect(border.width, 1.5);
        final target = find.bySemanticsLabel(RegExp('^General'));
        expect(target, findsOneWidget);
        final data = tester.getSemantics(target).getSemanticsData();
        expect(data.flagsCollection.isButton, isTrue);
        expect(data.flagsCollection.isFocused, Tristate.isTrue);
        expect(data.hasAction(SemanticsAction.tap), isTrue);
        await tester.sendKeyEvent(LogicalKeyboardKey.enter);
        await tester.pump();
        expect(_settingsTextField('Device name'), findsOneWidget);
        expect(card, findsNothing);
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
      } finally {
        semantics.dispose();
      }
    },
  );

  testWidgets(
    'Settings reduced motion opens mobile detail and save feedback immediately',
    (tester) async {
      tester.platformDispatcher.accessibilityFeaturesTestValue =
          const FakeAccessibilityFeatures(disableAnimations: true);
      addTearDown(
        tester.platformDispatcher.clearAccessibilityFeaturesTestValue,
      );
      await _pumpSettings(
        tester,
        api: _FakeDiagnosticsApi(health: false),
        capabilities: PlatformCapabilities.fromPlatform('android'),
        physicalSize: const Size(390, 844),
      );
      await tester.tap(
        find.byKey(const ValueKey('settings-category-card-general')),
      );
      await tester.pump();
      final page = find.byKey(const Key('settings-mobile-category-page'));
      expect(page, findsOneWidget);
      final route = ModalRoute.of(tester.element(page))! as PageRoute<void>;
      expect(route.transitionDuration, Duration.zero);
      expect(route.reverseTransitionDuration, Duration.zero);
      await tester.enterText(_settingsTextField('Device name'), 'Mobile draft');
      await tester.pump();
      final slot = find.byKey(const Key('settings-save-slot'));
      expect(
        find.descendant(of: slot, matching: find.byType(AnimatedSize)),
        findsNothing,
      );
      expect(
        find.byKey(const Key('settings-save-button')).hitTestable(),
        findsOneWidget,
      );
      await tester.tap(find.byKey(const Key('settings-mobile-category-back')));
      await tester.pump();
      await tester.pump();
      expect(page, findsNothing);
      expect(
        find.byKey(const ValueKey('settings-category-card-general')),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
    },
  );
}
