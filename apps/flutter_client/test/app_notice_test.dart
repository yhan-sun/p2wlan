import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/shared/widgets/app_notice.dart';

void main() {
  testWidgets('notice is upper center, replaces previous and dismisses', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) => TextButton(
              onPressed: () =>
                  showAppNotice(context, content: const Text('Saved')),
              child: const Text('Show'),
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('Show'));
    await tester.pumpAndSettle();
    expect(tester.getCenter(find.text('Saved')).dy, lessThan(200));
    expect(find.byType(SnackBar), findsNothing);
    await tester.tap(find.text('Show'));
    await tester.pumpAndSettle();
    expect(find.text('Saved'), findsOneWidget);
    await tester.tap(find.byIcon(Icons.close_rounded));
    await tester.pumpAndSettle();
    expect(find.text('Saved'), findsNothing);
    await tester.tap(find.text('Show'));
    await tester.pumpAndSettle();
    await tester.pump(const Duration(seconds: 4));
    await tester.pumpAndSettle();
    expect(find.text('Saved'), findsNothing);
  });

  testWidgets('notice enters in 180ms and closes in 110ms', (tester) async {
    final context = await _pumpHost(tester);
    showAppNotice(context, content: const Text('Animated'));
    await tester.pump();
    expect(_opacity(tester, 'Animated'), 0);
    await tester.pump(const Duration(milliseconds: 90));
    expect(_opacity(tester, 'Animated'), inExclusiveRange(0, 1));
    await tester.pump(const Duration(milliseconds: 90));
    expect(_opacity(tester, 'Animated'), 1);

    final close = tester.widget<IconButton>(find.byType(IconButton));
    close.onPressed!();
    close.onPressed!(); // Repeated close requests share one exit.
    await tester.pump();
    expect(find.text('Animated'), findsOneWidget);
    await tester.pump(const Duration(milliseconds: 55));
    expect(_opacity(tester, 'Animated'), inExclusiveRange(0, 1));
    await tester.pump(const Duration(milliseconds: 55));
    expect(_opacity(tester, 'Animated'), 0);
    // Flutter reports the completed simulation on the tick after its duration.
    await tester.pump(const Duration(milliseconds: 1));
    expect(find.text('Animated'), findsNothing);
    await tester.pump(const Duration(seconds: 4));
    expect(tester.takeException(), isNull);
  });

  testWidgets('timeout exits once and never affects the next notice', (
    tester,
  ) async {
    final context = await _pumpHost(tester);
    showAppNotice(
      context,
      content: const Text('Timed'),
      duration: const Duration(seconds: 1),
    );
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 180));
    await tester.pump(const Duration(milliseconds: 820));
    expect(find.text('Timed'), findsOneWidget);
    await tester.pump(const Duration(milliseconds: 55));
    expect(_opacity(tester, 'Timed'), inExclusiveRange(0, 1));

    showAppNotice(context, content: const Text('Next'));
    await tester.pump();
    expect(find.text('Timed'), findsNothing);
    expect(find.text('Next'), findsOneWidget);
    await tester.pump(const Duration(milliseconds: 180));
    expect(_opacity(tester, 'Next'), 1);
    expect(find.byIcon(Icons.close_rounded), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('rapid replacement cancels old entrance, timer and exit', (
    tester,
  ) async {
    final context = await _pumpHost(tester);
    for (var i = 0; i < 20; i++) {
      showAppNotice(
        context,
        content: Text('Pending $i'),
        duration: const Duration(milliseconds: 250),
      );
    }
    await tester.pump();
    expect(find.text('Pending 19'), findsOneWidget);
    expect(find.byIcon(Icons.close_rounded), findsOneWidget);
    await tester.pump(const Duration(milliseconds: 60));
    showAppNotice(
      context,
      content: const Text('Entering'),
      duration: const Duration(milliseconds: 250),
    );
    await tester.pump();
    expect(find.text('Pending 19'), findsNothing);
    await tester.pump(const Duration(milliseconds: 60));
    tester.widget<IconButton>(find.byType(IconButton)).onPressed!();
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 40));
    showAppNotice(context, content: const Text('Current'));
    await tester.pump();
    expect(find.text('Entering'), findsNothing);
    await tester.pumpAndSettle();
    await tester.pump(const Duration(seconds: 1));
    expect(find.text('Current'), findsOneWidget);
    expect(find.byIcon(Icons.close_rounded), findsOneWidget);
    await tester.tap(find.byIcon(Icons.close_rounded));
    await tester.pumpAndSettle();
    expect(find.text('Current'), findsNothing);
    expect(tester.binding.transientCallbackCount, 0);
    expect(tester.takeException(), isNull);
  });

  testWidgets('reduced motion shows and dismisses immediately', (tester) async {
    final reduced = ValueNotifier(true);
    addTearDown(reduced.dispose);
    final context = await _pumpHost(tester, reduced: reduced);
    showAppNotice(context, content: const Text('Immediate'));
    await tester.pump();
    expect(_opacity(tester, 'Immediate'), 1);
    final transform = tester.widget<Transform>(
      find
          .ancestor(
            of: find.text('Immediate'),
            matching: find.byType(Transform),
          )
          .first,
    );
    expect(transform.transform.getTranslation().y, 0);
    expect(tester.binding.transientCallbackCount, 0);
    tester.widget<IconButton>(find.byType(IconButton)).onPressed!();
    await tester.pump();
    expect(find.text('Immediate'), findsNothing);

    showAppNotice(
      context,
      content: const Text('Immediate timeout'),
      duration: const Duration(seconds: 1),
    );
    await tester.pump();
    await tester.pump(const Duration(seconds: 1));
    expect(find.text('Immediate timeout'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('enabling reduced motion finishes an active entrance or exit', (
    tester,
  ) async {
    final reduced = ValueNotifier(false);
    addTearDown(reduced.dispose);
    final context = await _pumpHost(tester, reduced: reduced);
    showAppNotice(context, content: const Text('Changing'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 30));
    reduced.value = true;
    await tester.pump();
    expect(_opacity(tester, 'Changing'), 1);
    expect(tester.binding.transientCallbackCount, 0);

    reduced.value = false;
    await tester.pump();
    tester.widget<IconButton>(find.byType(IconButton)).onPressed!();
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 30));
    reduced.value = true;
    await tester.pump();
    await tester.pump(); // Overlay removal requested during dependency rebuild.
    expect(find.text('Changing'), findsNothing);
    expect(tester.binding.transientCallbackCount, 0);
    expect(tester.takeException(), isNull);
  });

  testWidgets('overlay disposal cancels an active timer or exit', (
    tester,
  ) async {
    for (final closing in [false, true]) {
      final context = await _pumpHost(tester);
      showAppNotice(context, content: const Text('Unmounting'));
      await tester.pumpAndSettle();
      if (closing) {
        tester.widget<IconButton>(find.byType(IconButton)).onPressed!();
        await tester.pump();
      }
      await tester.pumpWidget(const SizedBox());
      // Calls retained by an unmounted caller are harmless too.
      showAppNotice(context, content: const Text('Stale caller'));
      await tester.pump(const Duration(seconds: 5));
      expect(find.text('Stale caller'), findsNothing);
      expect(tester.binding.transientCallbackCount, 0);
      expect(tester.takeException(), isNull);
    }
  });

  testWidgets('notice content keeps its intrinsic height', (tester) async {
    await tester.binding.setSurfaceSize(const Size(800, 640));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) => TextButton(
              onPressed: () => showAppNotice(
                context,
                content: DecoratedBox(
                  decoration: const BoxDecoration(color: Colors.red),
                  // Deliberately leave the Column at its default max size to
                  // ensure the notice constrains arbitrary caller content.
                  child: Column(
                    children: [const Text('无法登录'), const Text('控制服务器返回了错误')],
                  ),
                ),
              ),
              child: const Text('Show'),
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('Show'));
    await tester.pumpAndSettle();

    final banner = find
        .ancestor(
          of: find.text('控制服务器返回了错误'),
          matching: find.byType(DecoratedBox),
        )
        .last;
    expect(tester.getRect(banner).height, lessThan(120));
  });
}

Future<BuildContext> _pumpHost(
  WidgetTester tester, {
  ValueNotifier<bool>? reduced,
}) async {
  await tester.pumpWidget(
    MaterialApp(
      builder: (context, child) => reduced == null
          ? MediaQuery(
              data: MediaQuery.of(context).copyWith(disableAnimations: false),
              child: child!,
            )
          : ValueListenableBuilder<bool>(
              valueListenable: reduced,
              child: child,
              builder: (context, disabled, child) => MediaQuery(
                data: MediaQuery.of(context)
                    .copyWith(disableAnimations: disabled),
                child: child!,
              ),
            ),
      home: const Scaffold(body: Text('Host')),
    ),
  );
  return tester.element(find.text('Host'));
}

double _opacity(WidgetTester tester, String text) => tester
    .widget<Opacity>(
      find.ancestor(of: find.text(text), matching: find.byType(Opacity)).first,
    )
    .opacity;
