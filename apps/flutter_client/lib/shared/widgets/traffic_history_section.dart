import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/p2wlan_colors.dart';
import '../../core/presentation/traffic_statistics.dart';
import 'traffic_history_scope.dart';
import 'traffic_totals.dart';

class TrafficHistorySection extends StatelessWidget {
  const TrafficHistorySection({super.key, this.networkId, this.peerId});

  final String? networkId;
  final String? peerId;

  @override
  Widget build(BuildContext context) {
    final scope = TrafficHistoryScope.maybeOf(context);
    if (scope == null) return const SizedBox.shrink();
    final strings = AppStringsScope.of(context);
    final store = scope.store;
    final summary = store.summary(
      settings: scope.settings,
      networkId: networkId,
      peerId: peerId,
    );
    final muted = Theme.of(context).colorScheme.onSurfaceVariant;
    final start = summary?.startedAt.toLocal();
    final since = start == null
        ? null
        : '${start.year}-${start.month.toString().padLeft(2, '0')}-${start.day.toString().padLeft(2, '0')}';
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(
          strings.isZh ? '历史累计' : 'Saved traffic history',
          style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600),
        ),
        const SizedBox(height: 12),
        TrafficTotals(
          counters: summary?.counters ?? const TrafficCounters(),
          keyPrefix: 'traffic-history',
        ),
        const SizedBox(height: 8),
        Text(
          since == null
              ? (strings.isZh
                    ? '获得有效流量数据后开始记录。'
                    : 'Recording starts when traffic data is available.')
              : (strings.isZh
                    ? '自 $since 起在本机记录，重启后保留。'
                    : 'Recorded on this device since $since; retained after restart.'),
          style: TextStyle(fontSize: 12, height: 1.45, color: muted),
        ),
        if (store.error != null) ...[
          const SizedBox(height: 8),
          Text(
            store.error == 'traffic_history_capacity'
                ? (strings.isZh
                      ? '历史记录已达到本机存储上限，新增统计暂未记录。已有历史保留。'
                      : 'Local history storage is full. New observations are not recorded; existing history is retained.')
                : store.loaded
                ? (strings.isZh
                      ? '最新统计尚未保存，历史文件保持原样。'
                      : 'Latest totals are not saved yet. The existing history is preserved.')
                : (strings.isZh
                      ? '历史记录暂不可用，原文件已保留。'
                      : 'History is unavailable. The existing file is preserved.'),
            style: TextStyle(
              color: P2WlanColors.of(context).warningText,
              fontSize: 12,
              height: 1.4,
            ),
          ),
          if (store.error != 'traffic_history_capacity')
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                onPressed: store.loading || store.saving
                    ? null
                    : () async {
                        if (store.loaded) {
                          await store.flush();
                        } else {
                          await store.load();
                        }
                        scope.onRefresh();
                      },
                icon: const Icon(Icons.refresh_rounded, size: 16),
                label: Text(
                  store.loaded
                      ? (strings.isZh ? '重试保存' : 'Retry saving')
                      : (strings.isZh ? '重新读取' : 'Retry loading'),
                ),
              ),
            ),
        ],
      ],
    );
  }
}
