import 'package:flutter/material.dart';

import '../../app/app_strings.dart';
import '../../app/app_tokens.dart';
import '../../core/presentation/traffic_statistics.dart';
import '../formatters.dart';

/// Comparable byte totals with enough width for large text and long units.
class TrafficTotals extends StatelessWidget {
  const TrafficTotals({
    super.key,
    required this.counters,
    this.keyPrefix = 'traffic',
  });

  final TrafficCounters counters;
  final String keyPrefix;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final items = [
      ('upload', strings.isZh ? '上传' : 'Uploaded', counters.uploadBytes),
      ('download', strings.isZh ? '下载' : 'Downloaded', counters.downloadBytes),
      ('total', strings.isZh ? '合计' : 'Total', counters.totalBytes),
    ];
    return LayoutBuilder(
      builder: (context, constraints) {
        final scale = MediaQuery.textScalerOf(context).scale(14) / 14;
        final columns = constraints.maxWidth >= 300 * scale ? 3 : 1;
        final width = (constraints.maxWidth - 16 * (columns - 1)) / columns;
        return Wrap(
          spacing: 16,
          runSpacing: 14,
          children: [
            for (final item in items)
              SizedBox(
                width: width,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      item.$2,
                      style: TextStyle(
                        fontSize: 12,
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      formatOptionalBytes(item.$3),
                      key: ValueKey('$keyPrefix-${item.$1}'),
                      style: const TextStyle(
                        fontSize: 20,
                        height: 1.3,
                        fontWeight: FontWeight.w600,
                        fontFeatures: AppTokens.tabularFontFeatures,
                      ),
                    ),
                  ],
                ),
              ),
          ],
        );
      },
    );
  }
}
