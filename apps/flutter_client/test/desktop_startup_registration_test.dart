import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/platform/desktop_startup_registration.dart';

void main() {
  late Directory tempHome;

  setUp(() async {
    tempHome = await Directory.systemTemp.createTemp('p2wlan-startup-test-');
  });

  tearDown(() async {
    if (await tempHome.exists()) {
      await tempHome.delete(recursive: true);
    }
  });

  test('macOS writes and confirms a per-user LaunchAgent', () async {
    const executable = '/Applications/P2WLAN.app/Contents/MacOS/P2WLAN';
    final registration = DesktopStartupRegistration(
      executablePath: executable,
      homeDirectoryPath: tempHome.path,
      platformOverride: DesktopStartupPlatform.macos,
    );

    expect(await registration.isEnabled(), isFalse);
    await registration.setEnabled(true);
    expect(await registration.isEnabled(), isTrue);

    final file = File(
      '${tempHome.path}/Library/LaunchAgents/'
      'io.p2wlan.desktop.login-startup.plist',
    );
    final contents = await file.readAsString();
    expect(contents, contains('<string>$executable</string>'));
    expect(contents, contains('<string>$loginStartupArgument</string>'));
    expect(contents, contains('<key>RunAtLoad</key>'));

    await registration.setEnabled(false);
    expect(await file.exists(), isFalse);
  });

  test('macOS stale executable path is not reported enabled', () async {
    final file = File(
      '${tempHome.path}/Library/LaunchAgents/'
      'io.p2wlan.desktop.login-startup.plist',
    );
    await file.parent.create(recursive: true);
    await file.writeAsString('''<?xml version="1.0"?>
<plist><dict><key>ProgramArguments</key><array>
<string>/Applications/Old.app/Contents/MacOS/Old</string>
<string>$loginStartupArgument</string>
</array></dict></plist>
''');

    final registration = DesktopStartupRegistration(
      executablePath: '/Applications/P2WLAN.app/Contents/MacOS/P2WLAN',
      homeDirectoryPath: tempHome.path,
      platformOverride: DesktopStartupPlatform.macos,
    );

    expect(await registration.isEnabled(), isFalse);
  });

  test('Linux writes an XDG autostart desktop entry', () async {
    final xdg = Directory('${tempHome.path}/xdg');
    final registration = DesktopStartupRegistration(
      executablePath: '${tempHome.path}/P2WLAN Client/p2wlan',
      homeDirectoryPath: tempHome.path,
      environment: {'HOME': tempHome.path, 'XDG_CONFIG_HOME': xdg.path},
      platformOverride: DesktopStartupPlatform.linux,
    );

    expect(await registration.isEnabled(), isFalse);
    await registration.setEnabled(true);
    expect(await registration.isEnabled(), isTrue);

    final file = File('${xdg.path}/autostart/p2wlan.desktop');
    final contents = await file.readAsString();
    expect(contents, contains('[Desktop Entry]'));
    expect(
      contents,
      contains(
        'Exec="${tempHome.path}/P2WLAN Client/p2wlan" $loginStartupArgument',
      ),
    );
    expect(contents, contains('X-GNOME-Autostart-enabled=true'));

    await registration.setEnabled(false);
    expect(await file.exists(), isFalse);
  });

  test('Linux ignores a relative XDG_CONFIG_HOME', () async {
    final registration = DesktopStartupRegistration(
      executablePath: '/opt/p2wlan/p2wlan',
      homeDirectoryPath: tempHome.path,
      environment: {'HOME': tempHome.path, 'XDG_CONFIG_HOME': 'relative/path'},
      platformOverride: DesktopStartupPlatform.linux,
    );

    await registration.setEnabled(true);
    expect(
      await File('${tempHome.path}/.config/autostart/p2wlan.desktop').exists(),
      isTrue,
    );
  });

  test('unsupported platforms hide the login-startup preference', () {
    final registration = DesktopStartupRegistration(
      platformOverride: DesktopStartupPlatform.unsupported,
    );
    expect(registration.isSupported, isFalse);
  });

  test('desktop entry and plist escaping reject or escape unsafe input', () {
    expect(desktopEntryQuoteArgument('/tmp/a b'), '"/tmp/a b"');
    expect(desktopEntryQuoteArgument(r'/tmp/a$b'), r'"/tmp/a\$b"');
    expect(xmlEscape('A&B<"'), 'A&amp;B&lt;&quot;');
    expect(
      () => desktopEntryQuoteArgument('/tmp/a\nmalformed'.replaceAll(r'\n', '\n')),
      throwsArgumentError,
    );
  });
}
