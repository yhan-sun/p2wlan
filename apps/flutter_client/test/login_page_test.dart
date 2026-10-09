import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/app/app_theme.dart';
import 'package:p2wlan_flutter_client/app/app_tokens.dart';
import 'package:p2wlan_flutter_client/core/api/control_api.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/capabilities/platform_capabilities.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/features/auth/login_page.dart';

void main() {
  testWidgets('Login page uses dark surfaces in dark theme', (tester) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);

    await tester.pumpWidget(
      MaterialApp(
        theme: AppTheme.lightTheme,
        darkTheme: AppTheme.darkTheme,
        themeMode: ThemeMode.dark,
        home: AppStringsScope(
          strings: AppStrings.fromCode(
            stores.settingsStore.settings.languageCode,
          ),
          child: LoginPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
            onAuthenticated: () {},
          ),
        ),
      ),
    );

    final decoratedColors = tester
        .widgetList<DecoratedBox>(find.byType(DecoratedBox))
        .map((box) => box.decoration)
        .whereType<BoxDecoration>()
        .map((decoration) => decoration.color)
        .whereType<Color>();
    final inputDecorations = tester
        .widgetList<InputDecorator>(find.byType(InputDecorator))
        .map((decorator) => decorator.decoration);

    expect(decoratedColors, contains(AppTokens.colorDarkSurface));
    expect(decoratedColors, isNot(contains(AppTokens.colorSurface)));
    expect(inputDecorations, hasLength(3));
    expect(
      inputDecorations.map((decoration) => decoration.fillColor),
      everyElement(AppTokens.colorDarkSurface),
    );
  });

  testWidgets('first launch keeps the required server field visible', (
    tester,
  ) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);

    await _pumpLogin(tester, stores);

    expect(find.text('Email or username'), findsOneWidget);
    expect(find.text('Password'), findsOneWidget);
    expect(find.text('Sign in'), findsOneWidget);
    expect(find.text("Don't have an account? Create one"), findsOneWidget);
    expect(find.text('Advanced options'), findsNothing);
    expect(find.text('Server address (required)'), findsOneWidget);
    expect(find.text('Continue in manual / offline mode'), findsNothing);
  });

  testWidgets('sign in requires an explicitly configured control server', (
    tester,
  ) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);
    final fake = _FakeControlApi();

    await _pumpLogin(tester, stores, controlApi: fake);
    await tester.enterText(
      find.byKey(const ValueKey('login-identifier')),
      'a@example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-password')),
      'secret123',
    );
    await tester.tap(find.text('Sign in'));
    await tester.pumpAndSettle();

    expect(fake.authenticateCalls, 0);
    expect(find.text('Server address required'), findsOneWidget);
    expect(
      find.textContaining('Enter a server address and sign in'),
      findsWidgets,
    );
  });

  testWidgets('saved custom server is indicated and used', (tester) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);
    final fake = _FakeControlApi();
    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(
          controlServer: 'https://custom.example.com',
        ),
      ),
    );

    await _pumpLogin(tester, stores, controlApi: fake);

    expect(
      tester
          .widget<TextField>(find.byKey(const ValueKey('login-server')))
          .controller!
          .text,
      'https://custom.example.com',
    );

    await tester.enterText(
      find.byKey(const ValueKey('login-identifier')),
      'a@example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-password')),
      'secret123',
    );
    await tester.tap(find.text('Sign in'));
    await _waitFor(tester, () => fake.authenticateCalls == 1);

    expect(fake.lastControlServer, 'https://custom.example.com');
  });

  testWidgets('register switch keeps email and uses newPassword hint', (
    tester,
  ) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);

    await _pumpLogin(tester, stores);
    await tester.enterText(
      find.byKey(const ValueKey('login-identifier')),
      'a@example.com',
    );
    await tester.tap(find.text("Don't have an account? Create one"));
    await tester.pumpAndSettle();

    expect(find.text('Create account'), findsOneWidget);
    expect(find.text('Already have an account? Sign in'), findsOneWidget);
    expect(
      tester
          .widget<TextField>(find.byKey(const ValueKey('login-password')))
          .autofillHints,
      contains(AutofillHints.newPassword),
    );

    await tester.tap(find.text('Already have an account? Sign in'));
    await tester.pumpAndSettle();
    expect(
      tester
          .widget<TextField>(find.byKey(const ValueKey('login-identifier')))
          .controller!
          .text,
      'a@example.com',
    );
  });

  testWidgets('password visibility toggles with tooltip', (tester) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);

    await _pumpLogin(tester, stores);
    final passwordField = find.byKey(const ValueKey('login-password'));
    expect(tester.widget<TextField>(passwordField).obscureText, isTrue);

    await tester.tap(find.byIcon(Icons.visibility_outlined));
    await tester.pumpAndSettle();
    expect(tester.widget<TextField>(passwordField).obscureText, isFalse);
    expect(find.byTooltip('Hide password'), findsOneWidget);

    await tester.tap(find.byIcon(Icons.visibility_off_outlined));
    await tester.pumpAndSettle();
    expect(tester.widget<TextField>(passwordField).obscureText, isTrue);
    expect(find.byTooltip('Show password'), findsOneWidget);
  });

  testWidgets('desktop platforms get local-node subtitle copy', (tester) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);

    await _pumpLogin(
      tester,
      stores,
      capabilities: PlatformCapabilities.fromPlatform('macos'),
    );

    expect(
      find.text('Sign in to connect this device to your P2WLAN network.'),
      findsOneWidget,
    );
    expect(find.textContaining('view and manage'), findsNothing);
    expect(find.textContaining('TUN'), findsNothing);
  });

  testWidgets('iOS keeps the remote-management subtitle copy', (tester) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);

    await _pumpLogin(
      tester,
      stores,
      capabilities: PlatformCapabilities.fromPlatform('ios'),
    );

    expect(
      find.text('Sign in to view and manage your P2WLAN network and devices.'),
      findsOneWidget,
    );
    expect(find.textContaining('TUN'), findsNothing);
  });

  testWidgets('English UI shows English text for Chinese API errors', (
    tester,
  ) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);
    final fake = _FakeControlApi(error: const ControlApiException('邮箱或密码错误'));

    await _pumpLogin(
      tester,
      stores,
      controlApi: fake,
      controlServer: 'https://control.example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-identifier')),
      'a@example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-password')),
      'secret123',
    );
    await tester.tap(find.text('Sign in'));
    await _waitFor(tester, () => fake.authenticateCalls == 1);
    await tester.pumpAndSettle();

    expect(find.text('Sign in failed'), findsOneWidget);
    expect(find.text('Incorrect email or password.'), findsOneWidget);
    expect(find.textContaining('邮箱'), findsNothing);
  });

  testWidgets('network failures map to reachability message', (tester) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);
    final fake = _FakeControlApi(
      error: const ControlApiException('无法连接控制服务器：无法连接'),
    );

    await _pumpLogin(
      tester,
      stores,
      controlApi: fake,
      controlServer: 'https://control.example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-identifier')),
      'a@example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-password')),
      'secret123',
    );
    await tester.tap(find.text('Sign in'));
    await _waitFor(tester, () => fake.authenticateCalls == 1);
    await tester.pumpAndSettle();

    expect(find.text('Cannot reach control server'), findsOneWidget);
    expect(
      find.text('Check your network or the self-hosted server address.'),
      findsOneWidget,
    );
    expect(find.textContaining('无法连接'), findsNothing);
  });

  testWidgets('unknown errors never surface raw exception text', (
    tester,
  ) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);
    final fake = _FakeControlApi(error: Exception('Something broke'));

    await _pumpLogin(
      tester,
      stores,
      controlApi: fake,
      controlServer: 'https://control.example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-identifier')),
      'a@example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-password')),
      'secret123',
    );
    await tester.tap(find.text('Sign in'));
    await _waitFor(tester, () => fake.authenticateCalls == 1);
    await tester.pumpAndSettle();

    expect(find.text('Sign in failed. Please try again.'), findsOneWidget);
    expect(find.textContaining('Something broke'), findsNothing);
  });

  testWidgets('client-side validation blocks empty email and short password', (
    tester,
  ) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);
    final fake = _FakeControlApi();

    await _pumpLogin(
      tester,
      stores,
      controlApi: fake,
      controlServer: 'https://control.example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-identifier')),
      'a@example.com',
    );
    await tester.tap(find.text('Sign in'));
    await tester.pumpAndSettle();
    expect(find.text('Password must be at least 6 characters'), findsOneWidget);
    expect(fake.authenticateCalls, 0);

    await tester.enterText(find.byKey(const ValueKey('login-identifier')), '');
    await tester.enterText(
      find.byKey(const ValueKey('login-password')),
      'secret123',
    );
    await tester.tap(find.text('Sign in'));
    await tester.pumpAndSettle();
    expect(find.text('Enter your email or username'), findsOneWidget);
    expect(fake.authenticateCalls, 0);
  });

  testWidgets('Chinese UI shows Chinese auth error', (tester) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);
    final fake = _FakeControlApi(error: const ControlApiException('邮箱或密码错误'));

    await _pumpLogin(
      tester,
      stores,
      controlApi: fake,
      controlServer: 'https://control.example.com',
      languageCode: 'zh-Hans',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-identifier')),
      'a@example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-password')),
      'secret123',
    );
    await tester.tap(find.text('登录'));
    await _waitFor(tester, () => fake.authenticateCalls == 1);
    await tester.pumpAndSettle();

    expect(find.text('邮箱或密码不正确。'), findsOneWidget);
  });

  testWidgets('successful sign in saves session without rendering the token', (
    tester,
  ) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);
    var authenticated = 0;
    final fake = _FakeControlApi(
      session: const AuthSession(
        token: 'test-token',
        controlServer: 'https://cs.example.com',
        user: {'email': 'account@example.com', 'username': 'pyu'},
      ),
    );

    await _pumpLogin(
      tester,
      stores,
      controlApi: fake,
      controlServer: 'https://control.example.com',
      onAuthenticated: () {
        authenticated += 1;
      },
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-identifier')),
      'a@example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-password')),
      'secret123',
    );
    await tester.tap(find.text('Sign in'));
    await _waitFor(tester, () => authenticated == 1);
    await tester.pumpAndSettle();

    final settings = stores.settingsStore.settings;
    expect(settings.authToken, 'test-token');
    expect(settings.controlServer, 'https://cs.example.com');
    expect(settings.accountEmail, 'account@example.com');
    expect(settings.accountUsername, 'pyu');
    expect(settings.toJson(), isNot(contains('manualMode')));
    expect(authenticated, 1);
    expect(find.textContaining('test-token'), findsNothing);
  });

  testWidgets('no offline action can authenticate an unconfigured client', (
    tester,
  ) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);
    final fake = _FakeControlApi();
    var authenticated = 0;
    await _pumpLogin(
      tester,
      stores,
      controlApi: fake,
      onAuthenticated: () => authenticated += 1,
    );
    expect(find.text('Continue in manual / offline mode'), findsNothing);
    expect(find.text('Advanced options'), findsNothing);
    expect(find.byIcon(Icons.offline_bolt_outlined), findsNothing);
    await tester.tap(find.text('Sign in'));
    await tester.pumpAndSettle();
    expect(find.text('Server address required'), findsOneWidget);
    expect(fake.authenticateCalls, 0);
    expect(authenticated, 0);
    expect(stores.settingsStore.settings.authToken, isEmpty);
  });

  testWidgets('duplicate taps do not submit twice', (tester) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);
    final fake = _FakeControlApi(completer: Completer<AuthSession>());
    var authenticated = 0;

    await _pumpLogin(
      tester,
      stores,
      controlApi: fake,
      controlServer: 'https://control.example.com',
      onAuthenticated: () {
        authenticated += 1;
      },
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-identifier')),
      'a@example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-password')),
      'secret123',
    );
    await tester.tap(find.text('Sign in'));
    await tester.pump();

    final button = tester.widget<FilledButton>(
      find.ancestor(
        of: find.text('Signing in...'),
        matching: find.byType(FilledButton),
      ),
    );
    expect(button.onPressed, isNull);
    await tester.tap(find.byType(FilledButton), warnIfMissed: false);
    await tester.pump();
    expect(fake.authenticateCalls, 1);

    fake.completer!.complete(
      const AuthSession(
        token: 'test-token',
        controlServer: 'https://control.example.com',
      ),
    );
    await _waitFor(tester, () => authenticated == 1);
    await tester.pump();
    expect(fake.authenticateCalls, 1);
  });

  testWidgets('login error keeps the submit button in the same vertical slot', (
    tester,
  ) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);
    final fake = _FakeControlApi(
      error: const ControlApiException('请求过于频繁，请稍后再试'),
    );

    await _pumpLogin(
      tester,
      stores,
      controlApi: fake,
      controlServer: 'https://control.example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-identifier')),
      'pyu',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-password')),
      'secret123',
    );
    final before = tester.getTopLeft(find.byType(FilledButton)).dy;
    await tester.tap(find.text('Sign in'));
    await _waitFor(tester, () => fake.authenticateCalls == 1);
    await tester.pumpAndSettle();

    final after = tester.getTopLeft(find.byType(FilledButton)).dy;
    expect(after, before);
    expect(
      find.text('Too many attempts. Please try again later.'),
      findsOneWidget,
    );
  });

  testWidgets('disposing the page mid-submit does not throw', (tester) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);
    final fake = _FakeControlApi(completer: Completer<AuthSession>());

    await _pumpLogin(
      tester,
      stores,
      controlApi: fake,
      controlServer: 'https://control.example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-identifier')),
      'a@example.com',
    );
    await tester.enterText(
      find.byKey(const ValueKey('login-password')),
      'secret123',
    );
    await tester.tap(find.text('Sign in'));
    await tester.pump();

    await tester.pumpWidget(const SizedBox.shrink());
    fake.completer!.complete(
      const AuthSession(
        token: 'test-token',
        controlServer: 'https://control.example.com',
      ),
    );
    await tester.runAsync(
      () => Future<void>.delayed(const Duration(milliseconds: 20)),
    );
    await tester.pump();

    expect(tester.takeException(), isNull);
  });

  testWidgets('invalid custom control server is rejected before authenticate', (
    tester,
  ) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);
    final fake = _FakeControlApi();

    await _pumpLogin(tester, stores, controlApi: fake);
    await _enterInvalidServerAndSubmit(tester, 'abc.com');
    expect(find.text('Invalid control server address'), findsOneWidget);
    expect(
      find.text(
        'Enter a complete HTTP or HTTPS URL, for example https://example.com',
      ),
      findsOneWidget,
    );
    expect(fake.authenticateCalls, 0);

    await _enterInvalidServerAndSubmit(tester, 'ftp://example.com');
    expect(find.text('Invalid control server address'), findsOneWidget);
    expect(fake.authenticateCalls, 0);
  });

  testWidgets(
    'login persistence failure stays on the configured sign-in page',
    (tester) async {
      final tempDir = await tester.runAsync(
        () => Directory.systemTemp.createTemp('p2wlan_login_test_'),
      );
      addTearDown(() {
        tempDir?.deleteSync(recursive: true);
      });
      final settingsStore = SettingsStore(
        settingsFile: File('${tempDir!.path}/settings.json'),
        tokenRepository: _ThrowingTokenRepository(),
      );
      await tester.runAsync(settingsStore.load);
      final diagnosticsApi = _OfflineDiagnosticsApi();
      final statusStore = StatusStore(
        settingsStore: settingsStore,
        diagnosticsApi: diagnosticsApi,
        daemonController: _FakeDaemonController(diagnosticsApi),
      );
      addTearDown(() {
        statusStore.dispose();
        settingsStore.dispose();
      });
      var authenticated = 0;

      await _pumpLogin(
        tester,
        _Stores(tempDir, settingsStore, statusStore),
        controlServer: 'https://control.example.com',
        controlApi: _FakeControlApi(),
        onAuthenticated: () {
          authenticated += 1;
        },
      );
      await tester.enterText(
        find.byKey(const ValueKey('login-identifier')),
        'a@example.com',
      );
      await tester.enterText(
        find.byKey(const ValueKey('login-password')),
        'secret123',
      );
      await tester.tap(find.text('Sign in'));
      await _waitFor(
        tester,
        () => find
            .text('Sign in failed. Please try again.')
            .evaluate()
            .isNotEmpty,
      );
      expect(authenticated, 0);
      expect(find.textContaining('token write failed'), findsNothing);
      expect(find.text('Continue in manual / offline mode'), findsNothing);
      expect(find.byKey(const ValueKey('login-server')), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );

  for (final size in const [Size(390, 844), Size(700, 1000), Size(1280, 900)]) {
    testWidgets('layout fits ${size.width.toInt()}x${size.height.toInt()}', (
      tester,
    ) async {
      final stores = (await tester.runAsync(_makeStores))!;
      addTearDown(stores.dispose);

      await tester.binding.setSurfaceSize(size);
      addTearDown(() => tester.binding.setSurfaceSize(null));

      await _pumpLogin(
        tester,
        stores,
        capabilities: PlatformCapabilities.fromPlatform('macos'),
      );
      expect(tester.takeException(), isNull);

      expect(tester.takeException(), isNull);
    });
  }
}

Future<void> _pumpLogin(
  WidgetTester tester,
  _Stores stores, {
  PlatformCapabilities? capabilities,
  ControlApi? controlApi,
  String? controlServer,
  String languageCode = 'en',
  VoidCallback? onAuthenticated,
}) async {
  if (controlServer != null) {
    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(controlServer: controlServer),
      ),
    );
  }
  await tester.pumpWidget(
    MaterialApp(
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      themeMode: ThemeMode.light,
      home: AppStringsScope(
        strings: AppStrings.fromCode(languageCode),
        child: LoginPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: capabilities,
          controlApi: controlApi,
          onAuthenticated: onAuthenticated ?? () {},
        ),
      ),
    ),
  );
}

Future<void> _enterInvalidServerAndSubmit(
  WidgetTester tester,
  String server,
) async {
  final serverField = find.byKey(const ValueKey('login-server'));
  await tester.ensureVisible(serverField);
  await tester.pump();
  await tester.enterText(serverField, server);
  await tester.enterText(
    find.byKey(const ValueKey('login-identifier')),
    'a@example.com',
  );
  await tester.enterText(
    find.byKey(const ValueKey('login-password')),
    'secret123',
  );
  final signIn = find.text('Sign in');
  await tester.ensureVisible(signIn);
  await tester.pumpAndSettle();
  await tester.tap(signIn);
  await tester.pumpAndSettle();
}

Future<void> _waitFor(WidgetTester tester, bool Function() condition) async {
  for (var i = 0; i < 100; i++) {
    if (condition()) return;
    await tester.runAsync(
      () => Future<void>.delayed(const Duration(milliseconds: 10)),
    );
    await tester.pump();
  }
  fail('Condition not met after polling.');
}

class _FakeControlApi extends ControlApi {
  _FakeControlApi({this.session, this.error, this.completer});

  final AuthSession? session;
  final Object? error;
  final Completer<AuthSession>? completer;

  int authenticateCalls = 0;
  AuthMode? lastMode;
  String? lastControlServer;
  String? lastEmail;
  String? lastPassword;

  @override
  Future<AuthSession> authenticate({
    required AuthMode mode,
    required String controlServer,
    required String email,
    required String password,
  }) async {
    authenticateCalls += 1;
    lastMode = mode;
    lastControlServer = controlServer;
    lastEmail = email;
    lastPassword = password;
    if (completer != null) return completer!.future;
    if (error != null) throw error!;
    return session ?? AuthSession(token: 'token', controlServer: controlServer);
  }
}

class _ThrowingTokenRepository implements SecureTokenRepository {
  @override
  Future<String?> read() async => null;

  @override
  Future<void> write(String token) async {
    if (token.trim().isNotEmpty) {
      throw const SecureTokenStorageException('token write failed');
    }
  }

  @override
  Future<void> clear() async {}
}

class _FakeDaemonController extends DaemonController {
  _FakeDaemonController(DiagnosticsApi api) : super(diagnosticsApi: api);

  @override
  Future<DaemonCommandResult> start(AppSettings settings) async {
    return const DaemonCommandResult(ok: true, message: 'fake start');
  }

  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) async {
    return const DaemonCommandResult(
      ok: true,
      message: 'fake stop',
      graceful: true,
    );
  }
}

Future<_Stores> _makeStores() async {
  final tempDir = await Directory.systemTemp.createTemp('p2wlan_login_test_');
  final settingsStore = SettingsStore(
    settingsFile: File('${tempDir.path}/settings.json'),
    tokenRepository: InMemorySecureTokenRepository(),
  );
  await settingsStore.load();
  final api = _OfflineDiagnosticsApi();
  final statusStore = StatusStore(
    settingsStore: settingsStore,
    diagnosticsApi: api,
    daemonController: _FakeDaemonController(api),
  );
  return _Stores(tempDir, settingsStore, statusStore);
}

class _Stores {
  const _Stores(this.tempDir, this.settingsStore, this.statusStore);

  final Directory tempDir;
  final SettingsStore settingsStore;
  final StatusStore statusStore;

  void dispose() {
    statusStore.dispose();
    settingsStore.dispose();
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  }
}

class _OfflineDiagnosticsApi implements DiagnosticsApi {
  @override
  void cancelSpeedTest() {}

  @override
  DiagnosticsApiException? healthFailureFor(String diagnosticsUrl) => null;

  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => false;

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) {
    throw const DiagnosticsApiException('offline');
  }

  @override
  Future<bool> requestShutdown(String diagnosticsUrl) async => false;

  @override
  Future<SpeedTestResult> runSpeedTest(
    String diagnosticsUrl, {
    required String peerVirtualIp,
    Duration duration = const Duration(seconds: 10),
  }) {
    throw const DiagnosticsApiException('offline');
  }

  @override
  Future<EventsResponse> fetchEvents(
    String diagnosticsUrl, {
    int since = 0,
    int? processId,
    Duration timeout = const Duration(seconds: 30),
  }) => throw const DiagnosticsApiException('offline');

  @override
  Future<PeersPageResponse> fetchPeers(
    String diagnosticsUrl, {
    String? cursor,
    int limit = 100,
  }) => throw const DiagnosticsApiException('offline');

  @override
  Future<String> fetchLogTail(
    String diagnosticsUrl, {
    int lines = 120,
    int maxBytes = 262144,
  }) => throw const DiagnosticsApiException('offline');

  @override
  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) =>
      throw const DiagnosticsApiException('offline');

  @override
  Future<RouteRepairResponse> repairRoutes(String diagnosticsUrl) =>
      throw const DiagnosticsApiException('offline');

  @override
  void close() {}
}
