import 'package:flutter/material.dart';

import '../../app/app_tokens.dart';

/// A page heading shared by the overview and settings surfaces.
/// Text remains free to wrap and follows the user's accessibility text scale.
class PageHeading extends StatelessWidget {
  const PageHeading({
    super.key,
    required this.title,
    required this.subtitle,
    this.compact = false,
    this.actions = const [],
    this.toolbar,
  });

  final String title;
  final String subtitle;
  final bool compact;
  final List<Widget> actions;
  final Widget? toolbar;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    final description = subtitle.trim();
    final heading = Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Semantics(
          header: true,
          child: Text(
            title,
            style: TextStyle(
              fontSize: compact ? 22 : 24,
              height: 1.3,
              fontWeight: FontWeight.w600,
              color: colors.onSurface,
              letterSpacing: 0,
            ),
          ),
        ),
        if (description.isNotEmpty) ...[
          const SizedBox(height: AppTokens.space6),
          Text(
            description,
            style: TextStyle(
              fontSize: 13,
              height: 1.4,
              fontWeight: FontWeight.w400,
              color: colors.onSurfaceVariant,
            ),
          ),
        ],
      ],
    );
    if (actions.isEmpty && toolbar == null) return heading;
    final commands = Wrap(
      spacing: AppTokens.space8,
      runSpacing: AppTokens.space8,
      children: [?toolbar, ...actions],
    );
    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth >= 480 &&
            MediaQuery.textScalerOf(context).scale(14) <= 18) {
          return Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              Expanded(child: heading),
              const SizedBox(width: AppTokens.space16),
              Flexible(child: commands),
            ],
          );
        }
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            heading,
            const SizedBox(height: AppTokens.space8),
            commands,
          ],
        );
      },
    );
  }
}
