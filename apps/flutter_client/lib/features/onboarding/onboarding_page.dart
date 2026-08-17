import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/capabilities/permission_preflight.dart';
import '../../core/capabilities/platform_capabilities.dart';
import '../../core/state/settings_store.dart';
import '../../core/state/status_store.dart';
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
  });

  final SettingsStore settingsStore;
  final StatusStore statusStore;
  final PlatformCapabilities? capabilities;
  final VoidCallback? onCompleted;

  @override
  State<OnboardingPage> createState() => _OnboardingPageState();
}

class _OnboardingPageState extends State<OnboardingPage> {
  late final OnboardingModel _model = OnboardingModel(
    capabilities: widget.capabilities ?? PlatformCapabilities.current(),
  );
  PermissionPreflight? _preflight;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _refreshPreflight();
  }

  /// Re-run the live permission preflight. The result (not an in-memory
  /// boolean) is what drives the permission step.
  Future<void> _refreshPreflight() async {
    final preflight = await runPermissionPreflight();
    if (!mounted) return;
    setState(() => _preflight = preflight);
  }

  OnboardingFacts _facts() {
    final settings = widget.settingsStore.settings;
    final snapshot = widget.statusStore.snapshot;
    final onlinePeers =
        snapshot?.peers.where((p) => p.online).length ?? 0;
    return OnboardingFacts(
      hasCredential: settings.authToken.trim().isNotEmpty,
      manualMode: settings.manualMode,
      // Real permission: the static preflight says TUN/route work is possible
      // right now, OR the daemon is already running (the authoritative runtime
      // proof that elevation was granted).
      permissionGranted:
          (_preflight?.satisfied ?? false) || widget.statusStore.daemonReachable,
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

  Future<void> _complete() async {
    await widget.settingsStore.markOnboardingCompleted();
    widget.onCompleted?.call();
  }

  /// Start the daemon. The permission step and the daemon step both land here:
  /// granting permission IS the real elevation that happens when the daemon
  /// is launched (osascript/UAC/pkexec), and once the daemon is reachable the
  /// permission fact is true by definition.
  Future<void> _startDaemon() async {
    setState(() => _busy = true);
    try {
      final result = await widget.statusStore.startDaemon();
      await widget.statusStore.refresh();
      await _refreshPreflight();
      if (!result.ok && mounted) setState(() => _error = result.message);
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
      case OnboardingStep.discover:
        await _complete();
        break;
      case OnboardingStep.auth:
      case OnboardingStep.done:
        break;
    }
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: Listenable.merge(
        [widget.settingsStore, widget.statusStore],
      ),
      builder: (context, _) {
        final facts = _facts();
        final step = _model.step(facts);
        final strings = AppStringsScope.of(context);
        final isZh = strings.isZh;
        return Scaffold(
          body: SafeArea(
            child: Center(
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
                        color: AppTokens.colorAccent,
                      ),
                      const SizedBox(height: 16),
                      Text(
                        isZh ? '把这台设备接入 P2WLAN' : 'Connect this device to P2WLAN',
                        style: Theme.of(context).textTheme.headlineSmall,
                      ),
                      const SizedBox(height: 8),
                      Text(
                        isZh
                            ? '几步完成本地节点设置；中途退出可随时从这里继续。'
                            : 'A few steps to set up your local node; you can resume here anytime.',
                        style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                              color: AppTokens.colorTextMuted,
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
                      _StepBody(step: step, isZh: isZh, busy: _busy, preflight: _preflight),
                      if (_error != null) ...[
                        const SizedBox(height: 16),
                        Text(
                          _error!,
                          style: const TextStyle(color: Colors.redAccent),
                        ),
                      ],
                      const SizedBox(height: 24),
                      _PrimaryAction(
                        step: step,
                        isZh: isZh,
                        busy: _busy,
                        skippable: _model.canSkip(step),
                        onPrimary: () => _onPrimaryAction(step),
                        onSkip: () {
                          if (step == OnboardingStep.virtualIp) {
                            // A VIP may take a moment; virtual IP step is not
                            // skippable but we allow "keep waiting" (no-op).
                          } else if (_model.canSkip(step)) {
                            _complete();
                          }
                        },
                      ),
                    ],
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
    final isZh = AppStringsScope.of(context).isZh;
    return Row(
      children: [
        for (var i = 0; i < visible.length; i++)
          ...[
            if (i > 0)
              Expanded(
                child: Container(height: 2, color: AppTokens.colorBorderSubtle),
              ),
            _StepDot(
              label: _label(visible[i], isZh),
              state: _dotState(visible[i], current, isZh),
            ),
          ],
      ],
    );
  }

  String _label(OnboardingStep s, bool isZh) {
    switch (s) {
      case OnboardingStep.permission:
        return isZh ? '权限' : 'Permission';
      case OnboardingStep.daemon:
        return isZh ? '启动' : 'Start';
      case OnboardingStep.virtualIp:
        return isZh ? '虚拟 IP' : 'Virtual IP';
      case OnboardingStep.discover:
        return isZh ? '发现设备' : 'Discover';
      case OnboardingStep.auth:
        return isZh ? '登录' : 'Sign in';
      case OnboardingStep.done:
        return isZh ? '完成' : 'Done';
    }
  }

  _DotState _dotState(OnboardingStep s, OnboardingStep current, bool isZh) {
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
    final color = switch (state) {
      _DotState.done => AppTokens.colorAccent,
      _DotState.current => AppTokens.colorAccent,
      _DotState.pending => AppTokens.colorTextMuted,
    };
    return Column(
      children: [
        Icon(
          state == _DotState.done ? Icons.check_rounded : Icons.circle_outlined,
          size: 20,
          color: color,
        ),
        const SizedBox(height: 6),
        Text(
          label,
          style: Theme.of(context).textTheme.labelSmall?.copyWith(color: color),
        ),
      ],
    );
  }
}

class _StepBody extends StatelessWidget {
  const _StepBody({
    required this.step,
    required this.isZh,
    required this.busy,
    this.preflight,
  });

  final OnboardingStep step;
  final bool isZh;
  final bool busy;
  final PermissionPreflight? preflight;

  @override
  Widget build(BuildContext context) {
    final (title, subtitle) = switch (step) {
      OnboardingStep.auth => (
          isZh ? '登录控制面' : 'Sign in to the control plane',
          isZh
              ? '使用账号登录以加入你的网络。'
              : 'Use your account to join your network.',
        ),
      OnboardingStep.permission => (
          isZh ? '授予本机权限' : 'Grant local permissions',
          isZh
              ? 'P2WLAN 需要创建虚拟网卡并安装路由，可能需要管理员权限。'
              : 'P2WLAN creates a virtual adapter and installs routes; this may need admin rights.',
        ),
      OnboardingStep.daemon => (
          isZh ? '启动本地守护进程' : 'Start the local daemon',
          isZh
              ? '启动 p2wlan-daemon 以建立虚拟网卡与加密会话。'
              : 'Start p2wlan-daemon to create the virtual adapter and secure sessions.',
        ),
      OnboardingStep.virtualIp => (
          isZh ? '等待分配虚拟 IP' : 'Waiting for a virtual IP',
          isZh
              ? '正在加入网络并获取 10.20.x.x 地址…'
              : 'Joining the network and getting a 10.20.x.x address…',
        ),
      OnboardingStep.discover => (
          isZh ? '发现其他设备' : 'Discover other devices',
          isZh
              ? '正在同步节点目录。可以现在完成，之后在"设备"页继续查看。'
              : 'Syncing the node catalog. You can finish now and check "Devices" later.',
        ),
      OnboardingStep.done => (
          isZh ? '准备就绪' : 'Ready',
          isZh ? '本地节点已配置完成。' : 'Your local node is set up.',
        ),
    };
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            if (busy) ...[
              const SizedBox.square(dimension: 16, child: CircularProgressIndicator(strokeWidth: 2)),
              const SizedBox(width: 10),
            ],
            Text(title, style: Theme.of(context).textTheme.titleMedium),
          ],
        ),
        const SizedBox(height: 6),
        Text(
          subtitle,
          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: AppTokens.colorTextMuted,
              ),
        ),
        if (step == OnboardingStep.permission && preflight != null) ...[
          const SizedBox(height: 12),
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
    final tone = preflight.bad
        ? Colors.redAccent
        : preflight.warn
        ? Colors.orange
        : AppTokens.colorAccent;
    final label = preflight.satisfied
        ? '权限已满足'
        : '需要授权';
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
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
              const SizedBox(width: 6),
              Text(
                '$label · ${preflight.canCreateTun == 'true' ? '可创建 TUN' : 'TUN: ${preflight.canCreateTun}'} · ${preflight.canModifyRoutes == 'true' ? '可修改路由' : '路由: ${preflight.canModifyRoutes}'}',
                style: TextStyle(fontSize: 12, color: tone),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            preflight.recommendedAction,
            style: const TextStyle(
              fontSize: 12,
              height: 1.4,
              color: AppTokens.colorTextSecondary,
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
    required this.isZh,
    required this.busy,
    required this.skippable,
    required this.onPrimary,
    required this.onSkip,
  });

  final OnboardingStep step;
  final bool isZh;
  final bool busy;
  final bool skippable;
  final VoidCallback onPrimary;
  final VoidCallback onSkip;

  String get _label => switch (step) {
        OnboardingStep.permission => isZh ? '授予并继续' : 'Grant & continue',
        OnboardingStep.daemon => isZh ? '启动 P2WLAN' : 'Start P2WLAN',
        OnboardingStep.virtualIp => isZh ? '继续' : 'Continue',
        OnboardingStep.discover => isZh ? '完成' : 'Finish',
        _ => isZh ? '继续' : 'Continue',
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
          const SizedBox(width: 10),
          Text(
            isZh ? '正在连接…' : 'Connecting…',
            style: TextStyle(color: AppTokens.colorTextMuted),
          ),
          const Spacer(),
        ] else ...[
          if (skippable)
            TextButton(onPressed: busy ? null : onSkip, child: Text(isZh ? '跳过' : 'Skip')),
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
