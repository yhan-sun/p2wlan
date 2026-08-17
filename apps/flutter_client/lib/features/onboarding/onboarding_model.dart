// Resumable onboarding state machine for the local (desktop) P2WLAN node flow:
//
//   auth -> permission -> daemon -> virtualIp -> discover -> done
//
// Design goals (ADR 0004, TODO D-01):
//  - **Resumable**: the current step is *derived* from observable facts (is a
//    credential stored, is the daemon reachable, is a virtual IP assigned, how
//    many peers are online, has elevation been granted), never from an
//    imperative cursor. Restarting the app or interrupting mid-flow therefore
//    always recomputes the right step to resume from.
//  - **Capability-aware**: steps that require a local daemon / TUN are only
//    reachable on platforms that can act as a local VPN node (mobile/web are
//    remote-management only and skip straight to `done` / their own flow).
//  - **Pure & testable**: no Flutter, no I/O. The model is a function of an
//    input record and the platform capability, so transitions and recovery are
//    unit-testable without a device.
import '../../core/capabilities/platform_capabilities.dart';

/// The discrete steps of the local-node onboarding flow, in order.
enum OnboardingStep {
  auth,
  permission,
  daemon,
  virtualIp,
  discover,
  done,
}

/// Observable facts that drive the onboarding model. All fields are plain
/// values a caller (the app) can assemble from the existing stores; no
/// credential material (token text) is carried here — only booleans.
class OnboardingFacts {
  const OnboardingFacts({
    this.hasCredential = false,
    this.manualMode = false,
    this.permissionGranted = false,
    this.daemonReachable = false,
    this.virtualIp = '',
    this.onlinePeerCount = 0,
  });

  /// Whether a control credential is stored (managed mode). True also for a
  /// user who has already signed in.
  final bool hasCredential;

  /// Offline / self-hosted manual mode — no control credential is required.
  final bool manualMode;

  /// Whether the platform elevation/permission prompt has been satisfied
  /// (meaningful only on desktop).
  final bool permissionGranted;

  /// Whether the local daemon's diagnostics endpoint is reachable.
  final bool daemonReachable;

  /// The allocated virtual IP, if any (authoritative, from the daemon).
  final String virtualIp;

  /// Number of online peers observed (>= 1 means discovery has produced a
  /// usable network).
  final int onlinePeerCount;

  /// Return a copy with the given fields overridden.
  OnboardingFacts copy({
    bool? hasCredential,
    bool? manualMode,
    bool? permissionGranted,
    bool? daemonReachable,
    String? virtualIp,
    int? onlinePeerCount,
  }) {
    return OnboardingFacts(
      hasCredential: hasCredential ?? this.hasCredential,
      manualMode: manualMode ?? this.manualMode,
      permissionGranted: permissionGranted ?? this.permissionGranted,
      daemonReachable: daemonReachable ?? this.daemonReachable,
      virtualIp: virtualIp ?? this.virtualIp,
      onlinePeerCount: onlinePeerCount ?? this.onlinePeerCount,
    );
  }
}

/// Pure onboarding state machine.
class OnboardingModel {
  const OnboardingModel({required this.capabilities});

  /// The platform capability that gates local-node steps.
  final PlatformCapabilities capabilities;

  /// Whether this device participates in the local-node onboarding flow at
  /// all. Mobile/web are remote-management only, so they consider onboarding
  /// immediately complete (their "first run" is just signing in).
  bool get isLocalNodeFlow => capabilities.canActAsLocalVpnNode;

  /// Compute the current step from the facts. Idempotent and total: every
  /// input yields exactly one step, which is what makes the flow resumable.
  OnboardingStep step(OnboardingFacts facts) {
    if (!isLocalNodeFlow) return OnboardingStep.done;

    // 1. Authentication (managed) or explicit manual mode.
    final authed = facts.manualMode || facts.hasCredential;
    if (!authed) return OnboardingStep.auth;

    // 2. Platform permission / elevation for local node work.
    if (capabilities.canRequestElevation && !facts.permissionGranted) {
      return OnboardingStep.permission;
    }

    // 3. Daemon must be running and reachable.
    if (!facts.daemonReachable) return OnboardingStep.daemon;

    // 4. A virtual IP must be assigned.
    if (facts.virtualIp.trim().isEmpty) return OnboardingStep.virtualIp;

    // 5. Discovery: at least one online peer, OR the daemon is up with a VIP
    //    and the user has chosen to continue. We treat "VIP assigned" as the
    //    resumable completion point; discover is best-effort.
    if (facts.onlinePeerCount <= 0) return OnboardingStep.discover;

    return OnboardingStep.done;
  }

  /// True when the flow is fully complete (no further first-run steps).
  bool isComplete(OnboardingFacts facts) => step(facts) == OnboardingStep.done;

  /// Whether the user may skip the current step (discover is skippable — a
  /// fresh network may legitimately have no peers yet; auth/daemon are not).
  bool canSkip(OnboardingStep step) => step == OnboardingStep.discover;

  /// The next step after [step] in the canonical order (for progress UI).
  OnboardingStep nextOf(OnboardingStep step) {
    final values = OnboardingStep.values;
    final index = values.indexOf(step);
    if (index < 0 || index >= values.length - 1) return OnboardingStep.done;
    return values[index + 1];
  }

  /// Human-friendly short name for a step (used by the UI copy, localized at
  /// the call site — this is a stable machine token, not user copy).
  String stepId(OnboardingStep step) => step.name;
}
