import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../app/p2wlan_colors.dart';

/// Presentation only. The caller still owns the operation and reads current
/// service/configuration facts from StatusStore before rendering or retrying.
enum LocalConnectionRestartPhase {
  idle,
  stopping,
  starting,
  stopFailed,
  startFailed,
  complete,
}

class LocalConnectionRestartFeedback extends StatelessWidget {
  const LocalConnectionRestartFeedback({
    super.key,
    required this.phase,
    required this.serviceReachable,
    required this.configurationPending,
    required this.onRetry,
    this.busy = false,
    this.successMessage,
    this.onDismiss,
  });

  final LocalConnectionRestartPhase phase;
  final bool serviceReachable;
  final bool configurationPending;
  final VoidCallback? onRetry;
  final bool busy;
  final String? successMessage;
  final VoidCallback? onDismiss;

  @override
  Widget build(BuildContext context) {
    if (phase == LocalConnectionRestartPhase.idle) {
      return const SizedBox.shrink();
    }
    final isZh = AppStringsScope.of(context).isZh;
    final colors = P2WlanColors.of(context);
    final failed =
        phase == LocalConnectionRestartPhase.stopFailed ||
        phase == LocalConnectionRestartPhase.startFailed;
    final waiting =
        phase == LocalConnectionRestartPhase.stopping ||
        phase == LocalConnectionRestartPhase.starting;
    final tone = failed
        ? (colors.dangerSurface, colors.dangerBorder, colors.dangerText)
        : !waiting &&
              (configurationPending ||
                  (phase == LocalConnectionRestartPhase.complete &&
                      !serviceReachable))
        ? (colors.warningSurface, colors.warningBorder, colors.warningText)
        : phase == LocalConnectionRestartPhase.complete
        ? (colors.successSurface, colors.successBorder, colors.successText)
        : (colors.neutralSurface, colors.neutralBorder, colors.neutralText);
    final message = switch (phase) {
      LocalConnectionRestartPhase.stopping =>
        isZh ? '正在停止本机默认连接…' : 'Stopping the default local connection…',
      LocalConnectionRestartPhase.starting =>
        isZh
            ? '停止步骤已完成，正在启动本机默认连接…'
            : 'The stop step completed. Starting the default local connection…',
      LocalConnectionRestartPhase.stopFailed =>
        isZh ? '未能完成停止操作，尚未尝试重新启动本机默认连接。' : 'The default local connection could not be stopped. Starting it again has not been attempted.',
      LocalConnectionRestartPhase.startFailed =>
        isZh ? '停止步骤已完成，但未能确认本机默认连接已重新启动。' : 'The stop step completed, but the default local connection could not be confirmed as restarted.',
      LocalConnectionRestartPhase.complete =>
        successMessage ??
            (isZh
                ? '本机默认连接已重新启动。'
                : 'The default local connection has restarted.'),
      LocalConnectionRestartPhase.idle => '',
    };
    if (phase == LocalConnectionRestartPhase.complete) {
      final summary = configurationPending
          ? (isZh
                ? '已重启，配置仍待确认应用。'
                : 'Restarted; configuration is still pending confirmation.')
          : !serviceReachable
          ? (isZh
                ? '重启步骤已完成，服务状态待确认。'
                : 'Restart finished; service status is unconfirmed.')
          : message;
      return Container(
        key: const ValueKey('local-connection-restart-feedback'),
        padding: const EdgeInsets.symmetric(horizontal: 12),
        decoration: BoxDecoration(
          color: tone.$1,
          borderRadius: BorderRadius.circular(AppTokens.radiusSm),
        ),
        child: Row(
          children: [
            Icon(
              configurationPending || !serviceReachable
                  ? Icons.info_outline_rounded
                  : Icons.check_circle_outline_rounded,
              size: 17,
              color: tone.$3,
            ),
            const SizedBox(width: 8),
            Expanded(
              child: Semantics(
                liveRegion: true,
                child: Tooltip(
                  message: summary,
                  child: Text(
                    summary,
                    maxLines: MediaQuery.textScalerOf(context).scale(14) > 18
                        ? 2
                        : 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(color: tone.$3, fontSize: 13, height: 1.4),
                  ),
                ),
              ),
            ),
            if (onDismiss != null && !configurationPending)
              IconButton(
                key: const ValueKey('restart-dismiss-success'),
                onPressed: onDismiss,
                tooltip: MaterialLocalizations.of(context).closeButtonTooltip,
                icon: const Icon(Icons.close_rounded, size: 16),
              )
            else
              const SizedBox(height: AppTokens.minTouchTarget),
          ],
        ),
      );
    }
    return Container(
      key: const ValueKey('local-connection-restart-feedback'),
      decoration: BoxDecoration(
        color: tone.$1,
        border: Border.all(color: tone.$2),
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
      ),
      padding: const EdgeInsets.all(AppTokens.space12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Semantics(
            liveRegion: true,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(message, style: TextStyle(color: tone.$3, height: 1.4)),
                if (!waiting) ...[
                  const SizedBox(height: AppTokens.space6),
                  Text(
                    serviceReachable
                        ? (isZh
                              ? '最近一次检查显示本机服务可访问；业务连通性仍需验证。'
                              : 'The last check found the local service reachable. Application connectivity still needs verification.')
                        : (isZh
                              ? '当前无法确认本机服务可访问。'
                              : 'The local service is not currently confirmed as reachable.'),
                    style: TextStyle(color: tone.$3, fontSize: 12, height: 1.4),
                  ),
                  if (configurationPending)
                    Text(
                      isZh ? '已保存的配置仍待确认应用。' : 'The saved configuration is still pending confirmation.',
                      style: TextStyle(
                        color: tone.$3,
                        fontSize: 12,
                        height: 1.4,
                      ),
                    ),
                ],
              ],
            ),
          ),
          if (failed && onRetry != null) ...[
            const SizedBox(height: AppTokens.space8),
            OutlinedButton.icon(
              onPressed: busy ? null : onRetry,
              icon: const Icon(Icons.refresh_rounded, size: 16),
              label: Text(
                phase == LocalConnectionRestartPhase.startFailed
                    ? (isZh ? '重试启动' : 'Retry starting')
                    : (isZh ? '重试停止并重启' : 'Retry stopping and restarting'),
              ),
            ),
          ],
        ],
      ),
    );
  }
}
