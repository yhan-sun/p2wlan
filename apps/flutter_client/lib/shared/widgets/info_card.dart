import 'package:flutter/material.dart';

import '../../app/app_tokens.dart';

/// Clean native surface panel (replaces generic bloated Cards).
class AppPanel extends StatelessWidget {
  const AppPanel({
    super.key,
    required this.title,
    required this.child,
    this.trailing,
    this.headerPadding = const EdgeInsets.fromLTRB(16, 16, 16, 0),
    this.contentPadding = const EdgeInsets.all(16),
    this.flushContent = false,
  });

  final String title;
  final Widget child;
  final Widget? trailing;
  final EdgeInsetsGeometry headerPadding;
  final EdgeInsetsGeometry contentPadding;
  final bool flushContent;

  @override
  Widget build(BuildContext context) {
    final effectiveContentPadding = flushContent
        ? EdgeInsets.zero
        : contentPadding;

    return Container(
      decoration: BoxDecoration(
        color: AppTokens.colorSurface,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: AppTokens.colorBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: headerPadding,
            child: _PanelHeader(title: title, trailing: trailing),
          ),
          const SizedBox(height: 12),
          Padding(padding: effectiveContentPadding, child: child),
        ],
      ),
    );
  }
}

class _PanelHeader extends StatelessWidget {
  const _PanelHeader({required this.title, required this.trailing});

  final String title;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final titleWidget = Text(
      title,
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
      style: const TextStyle(
        fontSize: 14,
        fontWeight: FontWeight.w700,
        color: AppTokens.colorTextPrimary,
        letterSpacing: -0.1,
      ),
    );

    final trailingWidget = trailing;
    if (trailingWidget == null) return titleWidget;

    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 360) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              titleWidget,
              const SizedBox(height: 8),
              Align(alignment: Alignment.centerLeft, child: trailingWidget),
            ],
          );
        }
        return Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Expanded(child: titleWidget),
            const SizedBox(width: 12),
            trailingWidget,
          ],
        );
      },
    );
  }
}

/// Backwards compatible alias for InfoCard using AppPanel.
class InfoCard extends StatelessWidget {
  const InfoCard({
    super.key,
    required this.title,
    required this.child,
    this.trailing,
  });

  final String title;
  final Widget child;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    return AppPanel(title: title, trailing: trailing, child: child);
  }
}

/// Compact metric row/tile with tabular numbers to prevent jumpiness on refresh.
class MetricTile extends StatelessWidget {
  const MetricTile({
    super.key,
    required this.label,
    required this.value,
    this.detail,
    this.minWidth = 140,
    this.maxWidth = 300,
  });

  final String label;
  final String value;
  final String? detail;
  final double minWidth;
  final double maxWidth;

  @override
  Widget build(BuildContext context) {
    return ConstrainedBox(
      constraints: BoxConstraints(minWidth: minWidth, maxWidth: maxWidth),
      child: Padding(
        padding: const EdgeInsets.only(right: 16, bottom: 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              label,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w500,
                color: AppTokens.colorTextMuted,
              ),
            ),
            const SizedBox(height: 3),
            SelectableText(
              value,
              maxLines: 2,
              style: const TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w600,
                color: AppTokens.colorTextPrimary,
                fontFeatures: AppTokens.tabularFontFeatures,
              ),
            ),
            if (detail != null) ...[
              const SizedBox(height: 2),
              Text(
                detail!,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w400,
                  color: AppTokens.colorTextMuted,
                  fontFeatures: AppTokens.tabularFontFeatures,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
