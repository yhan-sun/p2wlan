import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/capabilities/platform_capabilities.dart';
import 'package:p2wlan_flutter_client/features/onboarding/onboarding_model.dart';

void main() {
  final desktop = OnboardingModel(capabilities: PlatformCapabilities.fromPlatform('macos'));
  final mobile = OnboardingModel(capabilities: PlatformCapabilities.fromPlatform('android'));
  final web = OnboardingModel(capabilities: PlatformCapabilities.fromPlatform('web'));

  OnboardingFacts none() => const OnboardingFacts();

  test('fresh managed desktop starts at auth', () {
    expect(desktop.step(none()), OnboardingStep.auth);
  });

  test('auth -> permission -> daemon -> virtualIp -> discover -> done ladder', () {
    expect(desktop.step(none().copy(hasCredential: true)), OnboardingStep.permission);
    expect(desktop.step(none().copy(hasCredential: true, permissionGranted: true)),
        OnboardingStep.daemon);
    expect(
        desktop.step(none().copy(hasCredential: true, permissionGranted: true, daemonReachable: true)),
        OnboardingStep.virtualIp);
    expect(
        desktop.step(none().copy(
            hasCredential: true,
            permissionGranted: true,
            daemonReachable: true,
            virtualIp: '10.20.0.7')),
        OnboardingStep.discover);
    expect(
        desktop.step(none().copy(
            hasCredential: true,
            permissionGranted: true,
            daemonReachable: true,
            virtualIp: '10.20.0.7',
            onlinePeerCount: 2)),
        OnboardingStep.done);
  });

  test('manual mode skips auth (no credential required)', () {
    expect(desktop.step(none().copy(manualMode: true)), OnboardingStep.permission);
    expect(desktop.step(none().copy(manualMode: true, permissionGranted: true)),
        OnboardingStep.daemon);
  });

  test('mobile and web are remote-management only: onboarding is immediately done', () {
    expect(mobile.step(none()), OnboardingStep.done);
    expect(web.step(none()), OnboardingStep.done);
    expect(mobile.isLocalNodeFlow, isFalse);
    expect(desktop.isLocalNodeFlow, isTrue);
  });

  test('resumability: a fully-progressed state recomputes done without a cursor', () {
    final complete = none().copy(
      hasCredential: true,
      permissionGranted: true,
      daemonReachable: true,
      virtualIp: '10.20.0.7',
      onlinePeerCount: 1,
    );
    expect(desktop.isComplete(complete), isTrue);
  });

  test('resumability: if the daemon died after auth, it resumes at daemon step', () {
    final wasProgressed = none().copy(
      hasCredential: true,
      permissionGranted: true,
      daemonReachable: false, // daemon not running now
      virtualIp: '',
      onlinePeerCount: 0,
    );
    expect(desktop.step(wasProgressed), OnboardingStep.daemon);
  });

  test('isComplete is false until every local step is satisfied', () {
    expect(desktop.isComplete(none()), isFalse);
    expect(
        desktop.isComplete(
            none().copy(hasCredential: true, permissionGranted: true)),
        isFalse);
    expect(
        desktop.isComplete(none().copy(
            hasCredential: true,
            permissionGranted: true,
            daemonReachable: true,
            virtualIp: '10.20.0.7',
            onlinePeerCount: 1)),
        isTrue);
  });

  test('discover is skippable; auth/daemon are not', () {
    expect(desktop.canSkip(OnboardingStep.discover), isTrue);
    expect(desktop.canSkip(OnboardingStep.auth), isFalse);
    expect(desktop.canSkip(OnboardingStep.daemon), isFalse);
    expect(desktop.canSkip(OnboardingStep.done), isFalse);
  });

  test('nextOf advances canonical order and clamps at done', () {
    expect(desktop.nextOf(OnboardingStep.auth), OnboardingStep.permission);
    expect(desktop.nextOf(OnboardingStep.permission), OnboardingStep.daemon);
    expect(desktop.nextOf(OnboardingStep.daemon), OnboardingStep.virtualIp);
    expect(desktop.nextOf(OnboardingStep.virtualIp), OnboardingStep.discover);
    expect(desktop.nextOf(OnboardingStep.discover), OnboardingStep.done);
    expect(desktop.nextOf(OnboardingStep.done), OnboardingStep.done);
  });
}
