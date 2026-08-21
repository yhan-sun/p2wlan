import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/capabilities/permission_preflight.dart';
import '../../core/capabilities/platform_capabilities.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/permission_copy.dart';
import 'onboarding_model.dart';

/// Resumable first-run / node-setup flow for a local P2WLAN node.
///
/// Rendered by [P2WlanApp] once the user is authenticated but the device has
/// not yet completed onboarding. Every step is *derived* from live facts
/// (permission acknowledged, daemon reachable, virtual IP assigned, peers
/// online), so an interrupted flow resumes at the correct step on the next
/// launch instead of restarting. Mobile/web never reach this page (their
/// capability marks onboarding complete / they use the remote flow).
class OnboardingPage extends StatefulWidget {
  const OnboardingPage({
    super.key,
    required this.settingsStore,
    required this.statusStore,
    this.capabilities,
    this.onCompleted,
    this.permissionCheck,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final PlatformCapabilities? capabilities;
  final VoidCallback? onCompleted;

  /// Test seam: replaces the live permission preflight. When null the real
  /// preflight runs.
  final Future<PermissionPreflight> Function()? permissionCheck;

  @override
  State<OnboardingPage> createState() => _OnboardingPageState();
}

class _OnboardingPageState extends State<OnboardingPage> {
  late final OnboardingModel _model = OnboardingModel(
    capabilities: widget.capabilities ?? PlatformCapabilities.current(),
  );
  PermissionPreflight? _preflight;
  bool _busy = false;
  bool _completing = false;
  bool _completionNotified = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _refreshPreflight();
  }

  /// Re-run the live permission preflight. The result (not an in-memory
  /// boolean) is what drives the permission step.
  Future<void> _refreshPreflight() async {
    final preflight =
        await (widget.permissionCheck ?? runPermissionPreflight)();
    if (!mounted) return;
    setState(() => _preflight = preflight);
  }

  OnboardingFacts _facts() {
    final settings = widget.settingsStore.settings;
    final snapshot = widget.statusStore.snapshot;
    final onlinePeers = snapshot?.peers.where((p) => p.online).length ?? 0;
    return OnboardingFacts(
      hasCredential: settings.authToken.trim().isNotEmpty,
      manualMode: settings.manualMode,
      // Runtime proof must include a healthy daemon snapshot and an actual
      // route verification. Health alone is not evidence that TUN/route setup
      // succeeded.
      permissionGranted:
          (_preflight?.satisfied ?? false) ||
          (widget.statusStore.daemonReachable &&
              widget.statusStore.routeHealthy &&
              snapshot?.virtualIp.trim().isNotEmpty == true &&
              snapshot?.health.status == 'healthy'),
      daemonReachable: widget.statusStore.daemonReachable,
      virtualIp: snapshot?.virtualIp ?? '',
      onlinePeerCount: onlinePeers,
    );
  }

  /// The visible node-setup steps (auth is handled by LoginPage before this
  /// page, so onboarding starts at the permission step).
  static const _visibleSteps = [
    OnboardingStep.permission,
    OnboardingStep.daemon,
    OnboardingStep.virtualIp,
    OnboardingStep.discover,
  ];

  Future<void> _completeOnce() async {
    if (_completing || _completionNotified) return;
    final strings = AppStringsScope.of(context);

    if (widget.settingsStore.settings.onboardingCompleted) {
      _completionNotified = true;
      widget.onCompleted?.call();
      return;
    }

    _completing = true;
    if (mounted) {
      setState(() {
        _busy = true;
        _error = null;
      });
    }
    try {
      await widget.settingsStore.markOnboardingCompleted();
      if (!mounted) return;
      _completionNotified = true;
      widget.onCompleted?.call();
    } catch (error) {
      if (mounted) {
        setState(() => _error = strings.onboardingCompleteFailed);
      }
    } finally {
      _completing = false;
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }

  /// Start the daemon. The permission step and the daemon step both land here:
  /// granting permission IS the real elevation that happens when the daemon
  /// is launched (osascript/UAC/pkexec), and once the daemon is reachable the
  /// permission fact is true by definition.
  Future<void> _startDaemon() async {
    setState(() => _busy = true);
    try {
      final strings = AppStringsScope.of(context);
      final result = await widget.statusStore.startDaemon();
      await widget.statusStore.refresh();
      await _refreshPreflight();
      if (!result.ok && mounted) {
        final detail = result.message.trim();
        setState(
          () => _error = _isSafeStartupDetail(detail)
              ? detail
              : strings.onboardingStartFailed,
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  bool _isSafeStartupDetail(String detail) {
    if (detail.isEmpty) return false;
    // Controller-generated Windows diagnostics are already redacted and give
    // the user a useful next action. Do not render arbitrary daemon/error
    // strings here: they can contain tokens, socket details, or stack traces.
    const safePrefixes = [
      'Windows UAC',
      'Windows 运行组件',
      'Windows 虚拟网卡',
      '已完成启动授权',
      '管理员认证失败',
      '已取消管理员授权',
    ];
    return safePrefixes.any(detail.startsWith);
  }

  Future<void> _onPrimaryAction(OnboardingStep step) async {
    _error = null;
    switch (step) {
      case OnboardingStep.permission:
      case OnboardingStep.daemon:
        await _startDaemon();
        break;
      case OnboardingStep.virtualIp:
      case OnboardingStep.discover:
      case OnboardingStep.done:
        await _completeOnce();
        break;
      case OnboardingStep.auth:
        break;
    }
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    return AnimatedBuilder(
      animation: Listenable.merge([widget.settingsStore, widget.statusStore]),
      builder: (context, _) {
        final facts = _facts();
        final step = _model.step(facts);
        return Scaffold(
          body: SafeArea(
            child: Center(
              child: SingleChildScrollView(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 560),
                  child: Padding(
                    padding: const EdgeInsets.all(32),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(
                          Icons.router_rounded,
                          size: 40,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                        const SizedBox(height: AppTokens.space16),
                        Text(
                          strings.onboardingTitle,
                          style: Theme.of(context).textTheme.headlineSmall,
                        ),
                        const SizedBox(height: AppTokens.space8),
                        Text(
                          strings.onboardingSubtitle,
                          style: Theme.of(context).textTheme.bodyMedium
                              ?.copyWith(
                                color: P2WlanColors.of(context).textMuted,
                              ),
                        ),
                        const SizedBox(height: 28),
                        _OnboardingStepper(
                          model: _model,
                          step: step,
                          visible: _visibleSteps,
                          facts: facts,
                          permissionGranted: facts.permissionGranted,
                        ),
                        const SizedBox(height: 28),
                        _StepBody(
                          step: step,
                          strings: strings,
                          busy: _busy,
                          preflight: _preflight,
                        ),
                        if (_error != null) ...[
                          const SizedBox(height: AppTokens.space16),
                          Text(
                            _error!,
                            style: TextStyle(
                              color: P2WlanColors.of(context).dangerText,
                            ),
                          ),
                        ],
                        const SizedBox(height: AppTokens.space24),
                        _PrimaryAction(
                          step: step,
                          strings: strings,
                          busy: _busy,
                          skippable: _model.canSkip(step),
                          onPrimary: () => _onPrimaryAction(step),
                          onSkip: () {
                            if (step == OnboardingStep.virtualIp) {
                              // A VIP may take a moment; virtual IP step is not
                              // skippable but we allow "keep waiting" (no-op).
                            } else if (_model.canSkip(step)) {
                              _completeOnce();
                            }
                          },
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ),
        );
      },
    );
  }
}

class _OnboardingStepper extends StatelessWidget {
  const _OnboardingStepper({
    required this.model,
    required this.step,
    required this.visible,
    required this.facts,
    required this.permissionGranted,
  });

  final OnboardingModel model;
  final OnboardingStep step;
  final List<OnboardingStep> visible;
  final OnboardingFacts facts;
  final bool permissionGranted;

  bool _done(OnboardingStep s) {
    switch (s) {
      case OnboardingStep.permission:
        return !model.capabilities.canRequestElevation ||
            facts.manualMode ||
            permissionGranted;
      case OnboardingStep.daemon:
        return facts.daemonReachable;
      case OnboardingStep.virtualIp:
        return facts.virtualIp.trim().isNotEmpty;
      case OnboardingStep.discover:
        return facts.onlinePeerCount > 0;
      case OnboardingStep.auth:
        return facts.hasCredential || facts.manualMode;
      case OnboardingStep.done:
        return true;
    }
  }

  @override
  Widget build(BuildContext context) {
    final current = step;
    final strings = AppStringsScope.of(context);
    return Row(
      children: [
        for (var i = 0; i < visible.length; i++) ...[
          if (i > 0)
            Expanded(
              child: Container(height: 2, color: AppTokens.colorBorderSubtle),
            ),
          Flexible(
            fit: FlexFit.loose,
            child: _StepDot(
              label: _label(visible[i], strings),
              state: _dotState(visible[i], current),
            ),
          ),
        ],
      ],
    );
  }

  String _label(OnboardingStep s, AppStrings strings) {
    switch (s) {
      case OnboardingStep.permission:
        return strings.onboardingStepPermission;
      case OnboardingStep.daemon:
        return strings.onboardingStepStart;
      case OnboardingStep.virtualIp:
        return strings.onboardingStepVirtualIp;
      case OnboardingStep.discover:
        return strings.onboardingStepDiscover;
      case OnboardingStep.auth:
        return strings.signIn;
      case OnboardingStep.done:
        return strings.onboardingStepDone;
    }
  }

  _DotState _dotState(OnboardingStep s, OnboardingStep current) {
    final done = _done(s);
    if (done && s != current) return _DotState.done;
    if (s == current) return _DotState.current;
    return _DotState.pending;
  }
}

enum _DotState { pending, current, done }

class _StepDot extends StatelessWidget {
  const _StepDot({required this.label, required this.state});

  final String label;
  final _DotState state;

  @override
  Widget build(BuildContext context) {
    final c = P2WlanColors.of(context);
    final color = switch (state) {
      _DotState.done => c.relay,
      _DotState.current => c.relay,
      _DotState.pending => c.textMuted,
    };
    return Column(
      children: [
        Icon(
          state == _DotState.done ? Icons.check_rounded : Icons.circle_outlined,
          size: 20,
          color: color,
        ),
        const SizedBox(height: AppTokens.space6),
        ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 72),
          child: Text(
            label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            textAlign: TextAlign.center,
            style: Theme.of(
              context,
            ).textTheme.labelSmall?.copyWith(color: color),
          ),
        ),
      ],
    );
  }
}

class _StepBody extends StatelessWidget {
  const _StepBody({
    required this.step,
    required this.strings,
    required this.busy,
    this.preflight,
  });

  final OnboardingStep step;
  final AppStrings strings;
  final bool busy;
  final PermissionPreflight? preflight;

  @override
  Widget build(BuildContext context) {
    final (title, subtitle) = switch (step) {
      OnboardingStep.auth => (
        strings.onboardingAuthTitle,
        strings.onboardingAuthSubtitle,
      ),
      OnboardingStep.permission => (
        strings.onboardingPermissionTitle,
        strings.onboardingPermissionSubtitle,
      ),
      OnboardingStep.daemon => (
        strings.onboardingDaemonTitle,
        strings.onboardingDaemonSubtitle,
      ),
      OnboardingStep.virtualIp => (
        strings.onboardingVirtualIpTitle,
        strings.onboardingVirtualIpSubtitle,
      ),
      OnboardingStep.discover => (
        strings.onboardingDiscoverTitle,
        strings.onboardingDiscoverSubtitle,
      ),
      OnboardingStep.done => (
        strings.onboardingReadyTitle,
        strings.onboardingReadySubtitle,
      ),
    };
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            if (busy) ...[
              const SizedBox.square(
                dimension: 16,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
              const SizedBox(width: AppTokens.space10),
            ],
            Expanded(
              child: Text(
                title,
                style: Theme.of(context).textTheme.titleMedium,
              ),
            ),
          ],
        ),
        const SizedBox(height: AppTokens.space6),
        Text(
          subtitle,
          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
            color: P2WlanColors.of(context).textMuted,
          ),
        ),
        if (step == OnboardingStep.permission && preflight != null) ...[
          const SizedBox(height: AppTokens.space12),
          _PermissionSummary(preflight: preflight!),
        ],
      ],
    );
  }
}

/// Real preflight summary for the permission step: shows what the live
/// platform check found, so the user grants permission from evidence rather
/// than a blind click.
class _PermissionSummary extends StatelessWidget {
  const _PermissionSummary({required this.preflight});

  final PermissionPreflight preflight;

  @override
  Widget build(BuildContext context) {
    final c = P2WlanColors.of(context);
    final tone = preflight.bad
        ? c.dangerText
        : preflight.warn
        ? c.probing
        : c.relay;
    final strings = AppStringsScope.of(context);
    final label = preflight.satisfied
        ? strings.onboardingPermissionSatisfied
        : strings.onboardingPermissionNeeded;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(AppTokens.space12),
      decoration: BoxDecoration(
        color: AppTokens.colorSurfaceSubtle,
        borderRadius: BorderRadius.circular(AppTokens.radiusSm),
        border: Border.all(color: AppTokens.colorBorderSubtle),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.security_rounded, size: 16, color: tone),
              const SizedBox(width: AppTokens.space6),
              Expanded(
                child: Text(label, style: TextStyle(fontSize: 12, color: tone)),
              ),
            ],
          ),
          const SizedBox(height: AppTokens.space6),
          Text(
            '${preflight.canCreateTun == true
                ? strings.onboardingTunAvailable
                : preflight.canCreateTun == null
                ? strings.onboardingTunRuntimeVerify
                : strings.onboardingTunUnavailable} · ${preflight.canModifyRoutes == true
                ? strings.onboardingRoutesAvailable
                : preflight.canModifyRoutes == null
                ? strings.onboardingRoutesRuntimeVerify
                : strings.onboardingRoutesUnavailable}',
            style: TextStyle(fontSize: 12, height: 1.35, color: tone),
          ),
          const SizedBox(height: AppTokens.space6),
          Text(
            permissionRecommendedAction(strings, preflight),
            style: TextStyle(
              fontSize: 12,
              height: 1.4,
              color: P2WlanColors.of(context).textSecondary,
            ),
          ),
        ],
      ),
    );
  }
}

class _PrimaryAction extends StatelessWidget {
  const _PrimaryAction({
    required this.step,
    required this.strings,
    required this.busy,
    required this.skippable,
    required this.onPrimary,
    required this.onSkip,
  });

  final OnboardingStep step;
  final AppStrings strings;
  final bool busy;
  final bool skippable;
  final VoidCallback onPrimary;
  final VoidCallback onSkip;

  String get _label => switch (step) {
    OnboardingStep.permission => strings.onboardingGrantContinue,
    OnboardingStep.daemon => strings.startP2wlan,
    OnboardingStep.virtualIp => strings.continueAction,
    OnboardingStep.discover => strings.onboardingFinish,
    OnboardingStep.done => strings.onboardingFinish,
    _ => strings.continueAction,
  };

  @override
  Widget build(BuildContext context) {
    final waiting = step == OnboardingStep.virtualIp;
    return Row(
      children: [
        if (waiting) ...[
          const SizedBox.square(
            dimension: 16,
            child: CircularProgressIndicator(strokeWidth: 2),
          ),
          const SizedBox(width: AppTokens.space10),
          Text(
            strings.onboardingConnecting,
            style: TextStyle(color: P2WlanColors.of(context).textMuted),
          ),
          const Spacer(),
        ] else ...[
          if (skippable)
            TextButton(
              onPressed: busy ? null : onSkip,
              child: Text(strings.onboardingSkip),
            ),
          const Spacer(),
          FilledButton(
            onPressed: busy ? null : onPrimary,
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
              child: Text(_label),
            ),
          ),
        ],
      ],
    );
  }
}
