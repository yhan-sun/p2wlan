import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/capabilities/permission_preflight.dart';
import '../../core/capabilities/platform_capabilities.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
import '../../shared/permission_copy.dart';
import '../../shared/widgets/windows_window_controls.dart';
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
    this.onOpenConnectionSettings,
    this.onReauthenticate,
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final PlatformCapabilities? capabilities;
  final VoidCallback? onCompleted;
  final VoidCallback? onOpenConnectionSettings;
  final VoidCallback? onReauthenticate;

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
  Timer? _waitTimer;
  bool _waitingForIp = false;
  int _waitSeconds = 0;
  static const _maxWaitSeconds = 300;

  @override
  void initState() {
    super.initState();
    widget.settingsStore.addListener(_syncWaitTimer);
    widget.statusStore.addListener(_syncWaitTimer);
    _refreshPreflight();
    _syncWaitTimer();
  }

  @override
  void didUpdateWidget(covariant OnboardingPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.settingsStore != widget.settingsStore) {
      oldWidget.settingsStore.removeListener(_syncWaitTimer);
      widget.settingsStore.addListener(_syncWaitTimer);
    }
    if (oldWidget.statusStore != widget.statusStore) {
      oldWidget.statusStore.removeListener(_syncWaitTimer);
      widget.statusStore.addListener(_syncWaitTimer);
    }
    _syncWaitTimer();
  }

  @override
  void dispose() {
    widget.settingsStore.removeListener(_syncWaitTimer);
    widget.statusStore.removeListener(_syncWaitTimer);
    _waitTimer?.cancel();
    super.dispose();
  }

  // This timer only updates presentation; the status store owns connection
  // facts. It stops at five minutes, on leaving this stage, or on disposal.
  void _syncWaitTimer() {
    final waiting = _model.step(_facts()) == OnboardingStep.virtualIp;
    if (waiting == _waitingForIp) return;
    _waitingForIp = waiting;
    _waitTimer?.cancel();
    _waitTimer = null;
    _waitSeconds = 0;
    if (!waiting) return;
    _waitTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (!mounted || !_waitingForIp) {
        timer.cancel();
        return;
      }
      setState(() => _waitSeconds += 1);
      if (_waitSeconds >= _maxWaitSeconds) {
        timer.cancel();
        _waitTimer = null;
      }
    });
  }

  Future<void> _recheckConnection() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.statusStore.refresh();
      if (mounted) await _refreshPreflight();
    } catch (_) {
      if (mounted) {
        final isZh = AppStringsScope.of(context).isZh;
        setState(
          () => _error = isZh ? '暂时无法刷新连接状态，请检查服务或修改服务器设置。' : 'Could not refresh the connection. Check the service or server settings.',
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// Re-run the live permission preflight. The result (not an in-memory
  /// boolean) is what drives the permission step.
  Future<void> _refreshPreflight() async {
    final preflight =
        await (widget.permissionCheck ?? runPermissionPreflight)();
    if (!mounted) return;
    setState(() => _preflight = preflight);
    _syncWaitTimer();
  }

  OnboardingFacts _facts() {
    final settings = widget.settingsStore.settings;
    final snapshot = widget.statusStore.snapshot;
    final onlinePeers = snapshot?.peers.where((p) => p.online).length ?? 0;
    return OnboardingFacts(
      hasCredential: settings.hasAuthenticatedConnection,
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
  /// is launched (local encrypted config + sudo/UAC/pkexec), and once the daemon is
  /// reachable the permission fact is true by definition.
  Future<void> _startDaemon() async {
    setState(() => _busy = true);
    try {
      final strings = AppStringsScope.of(context);
      final result = await widget.statusStore.startDaemon();
      await widget.statusStore.refresh();
      await _refreshPreflight();
      if (!result.ok && mounted) {
        setState(
          () => _error = daemonStartupFailurePresentation(
            strings,
            result,
            failureCode: widget.statusStore.lastDaemonFailureCode,
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _onPrimaryAction(OnboardingStep step) async {
    _error = null;
    switch (step) {
      case OnboardingStep.permission:
      case OnboardingStep.daemon:
        await _startDaemon();
        break;
      case OnboardingStep.virtualIp:
        await _recheckConnection();
        break;
      case OnboardingStep.discover:
      case OnboardingStep.done:
        await _completeOnce();
        break;
      case OnboardingStep.auth:
        widget.onReauthenticate?.call();
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
          body: Stack(
            children: [
              if (_usesWindowsOnboardingChrome)
                const Positioned(
                  top: 0,
                  left: 0,
                  right: WindowsWindowControls.width,
                  height: 56,
                  child: DragToMoveArea(child: SizedBox.expand()),
                ),
              SafeArea(
                child: Center(
                  child: SingleChildScrollView(
                    child: ConstrainedBox(
                      constraints: const BoxConstraints(maxWidth: 640),
                      child: Padding(
                        padding: EdgeInsets.symmetric(
                          horizontal: MediaQuery.sizeOf(context).width < 600
                              ? 20
                              : 28,
                          vertical: 28,
                        ),
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Container(
                                  width: 44,
                                  height: 44,
                                  decoration: BoxDecoration(
                                    color: Theme.of(context).colorScheme.primary
                                        .withValues(alpha: .08),
                                    borderRadius: BorderRadius.circular(12),
                                  ),
                                  child: Icon(
                                    Icons.router_outlined,
                                    size: 24,
                                    color: Theme.of(context)
                                        .colorScheme
                                        .primary,
                                  ),
                                ),
                                const SizedBox(width: 14),
                                Expanded(
                                  child: Column(
                                    crossAxisAlignment:
                                        CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        strings.onboardingTitle,
                                        style: TextStyle(
                                          fontSize: 22,
                                          height: 1.3,
                                          fontWeight: FontWeight.w700,
                                          color: Theme.of(context)
                                              .colorScheme
                                              .onSurface,
                                        ),
                                      ),
                                      const SizedBox(height: 6),
                                      Text(
                                        strings.onboardingSubtitle,
                                        style: TextStyle(
                                          fontSize: 13,
                                          height: 1.5,
                                          color: Theme.of(context)
                                              .colorScheme
                                              .onSurfaceVariant,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ],
                            ),
                            const SizedBox(height: 28),
                            Container(
                              width: double.infinity,
                              padding: EdgeInsets.all(
                                MediaQuery.sizeOf(context).width < 600
                                    ? 20
                                    : 24,
                              ),
                              decoration: BoxDecoration(
                                color: Theme.of(context).colorScheme.surface,
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(
                                  color: Theme.of(context)
                                      .colorScheme
                                      .outlineVariant,
                                ),
                              ),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
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
                                  if (step == OnboardingStep.virtualIp) ...[
                                    const SizedBox(height: AppTokens.space16),
                                    _WaitingForIpProgress(
                                      seconds: _waitSeconds,
                                    ),
                                  ],
                                  if (_error != null) ...[
                                    const SizedBox(height: AppTokens.space16),
                                    Text(
                                      _error!,
                                      style: TextStyle(
                                        color: P2WlanColors.of(context)
                                            .dangerText,
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
                                  if (step != OnboardingStep.done &&
                                      (widget.onOpenConnectionSettings !=
                                              null ||
                                          widget.onReauthenticate != null)) ...[
                                    const SizedBox(height: AppTokens.space12),
                                    Wrap(
                                      spacing: AppTokens.space8,
                                      runSpacing: AppTokens.space4,
                                      children: [
                                        if (widget.onOpenConnectionSettings !=
                                            null)
                                          TextButton.icon(
                                            key: const ValueKey(
                                              'onboarding-connection-settings',
                                            ),
                                            onPressed: _busy
                                                ? null
                                                : widget
                                                      .onOpenConnectionSettings,
                                            icon: const Icon(
                                              Icons.settings_outlined,
                                              size: 18,
                                            ),
                                            label: Text(
                                              strings.isZh
                                                  ? '修改服务器或账号'
                                                  : 'Server or account',
                                            ),
                                          ),
                                        if (step != OnboardingStep.auth &&
                                            widget.onReauthenticate != null)
                                          TextButton.icon(
                                            key: const ValueKey(
                                              'onboarding-reauthenticate',
                                            ),
                                            onPressed: _busy
                                                ? null
                                                : widget.onReauthenticate,
                                            icon: const Icon(
                                              Icons.login_rounded,
                                              size: 18,
                                            ),
                                            label: Text(
                                              strings.isZh
                                                  ? '重新登录'
                                                  : 'Sign in again',
                                            ),
                                          ),
                                      ],
                                    ),
                                  ],
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

bool get _usesWindowsOnboardingChrome => !kIsWeb && Platform.isWindows;

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
        return !model.capabilities.canRequestElevation || permissionGranted;
      case OnboardingStep.daemon:
        return facts.daemonReachable;
      case OnboardingStep.virtualIp:
        return facts.virtualIp.trim().isNotEmpty;
      case OnboardingStep.discover:
        return facts.onlinePeerCount > 0;
      case OnboardingStep.auth:
        return facts.hasCredential;
      case OnboardingStep.done:
        return true;
    }
  }

  @override
  Widget build(BuildContext context) {
    final current = step;
    final strings = AppStringsScope.of(context);
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (var index = 0; index < visible.length; index++)
          Expanded(
            child: _StepDot(
              number: index + 1,
              label: _label(visible[index], strings),
              state: _dotState(visible[index], current),
            ),
          ),
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
  const _StepDot({
    required this.number,
    required this.label,
    required this.state,
  });

  final int number;
  final String label;
  final _DotState state;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final active = state == _DotState.current;
    final done = state == _DotState.done;
    final color = active || done
        ? theme.colorScheme.primary
        : theme.colorScheme.onSurfaceVariant;
    return Column(
      children: [
        Container(
          width: 28,
          height: 28,
          alignment: Alignment.center,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: active
                ? theme.colorScheme.primary
                : done
                ? theme.colorScheme.primary.withValues(alpha: .08)
                : theme.colorScheme.surfaceContainerHighest,
          ),
          child: done
              ? Icon(Icons.check_rounded, size: 16, color: color)
              : Text(
                  '$number',
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: active ? theme.colorScheme.onPrimary : color,
                  ),
                ),
        ),
        const SizedBox(height: 8),
        Text(
          label,
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
          textAlign: TextAlign.center,
          style: TextStyle(
            fontSize: 12,
            height: 1.4,
            color: color,
            fontWeight: active ? FontWeight.w600 : FontWeight.w400,
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
          style: Theme.of(context).textTheme.bodyMedium
              ?.copyWith(color: P2WlanColors.of(context).textMuted),
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
        color: Theme.of(context).colorScheme.surfaceContainerLow,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
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
    OnboardingStep.auth => strings.signIn,
  };

  @override
  Widget build(BuildContext context) {
    final waiting = step == OnboardingStep.virtualIp;
    final primary = FilledButton(
      onPressed: busy ? null : onPrimary,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
        child: Text(_label, textAlign: TextAlign.center),
      ),
    );
    final skip = TextButton(
      onPressed: busy ? null : onSkip,
      child: Text(strings.onboardingSkip, textAlign: TextAlign.center),
    );
    if (waiting) {
      return SizedBox(
        width: double.infinity,
        child: FilledButton.icon(
          key: const ValueKey('onboarding-recheck'),
          onPressed: busy ? null : onPrimary,
          icon: busy
              ? const SizedBox.square(
                  dimension: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.refresh_rounded, size: 18),
          label: Text(strings.isZh ? '重新检测' : 'Check again'),
        ),
      );
    }
    return LayoutBuilder(
      builder: (context, constraints) {
        final stacked =
            constraints.maxWidth < 360 ||
            MediaQuery.textScalerOf(context).scale(14) > 18;
        if (stacked) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              primary,
              if (skippable) ...[const SizedBox(height: 8), skip],
            ],
          );
        }
        return Row(children: [if (skippable) skip, const Spacer(), primary]);
      },
    );
  }
}

class _WaitingForIpProgress extends StatelessWidget {
  const _WaitingForIpProgress({required this.seconds});

  final int seconds;

  @override
  Widget build(BuildContext context) {
    final isZh = AppStringsScope.of(context).isZh;
    final theme = Theme.of(context);
    final elapsed =
        '${seconds ~/ 60}:${(seconds % 60).toString().padLeft(2, '0')}${seconds >= 300 ? '+' : ''}';
    return Container(
      key: const ValueKey('onboarding-ip-progress'),
      width: double.infinity,
      padding: const EdgeInsets.all(AppTokens.space16),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                Icons.check_circle_outline_rounded,
                size: 18,
                color: theme.colorScheme.primary,
              ),
              const SizedBox(width: AppTokens.space8),
              Expanded(
                child: Text(isZh ? '本机服务已启动' : 'Local service is running'),
              ),
            ],
          ),
          const SizedBox(height: AppTokens.space12),
          Text(
            isZh
                ? '正在等待控制服务器分配虚拟 IP · 已等待 $elapsed'
                : 'Waiting for a virtual IP from the control server · $elapsed elapsed',
            style: theme.textTheme.bodyMedium,
          ),
          const SizedBox(height: AppTokens.space8),
          Text(
            seconds >= 30
                ? (isZh
                      ? '等待时间较长。可重新检测当前状态，或确认服务器和账号后重新登录。'
                      : 'This is taking longer than usual. Check the current status or confirm your server and sign in again.')
                : (isZh
                      ? '地址分配完成后会自动进入下一步。'
                      : 'Setup continues automatically when an address is assigned.'),
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }
}
