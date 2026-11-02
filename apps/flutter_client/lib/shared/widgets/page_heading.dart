import 'package:flutter/material.dart';

import '../../app/app_tokens.dart';

/// A compact page heading shared by the overview and settings surfaces.
/// Text remains free to wrap and follows the user's accessibility text scale.
class PageHeading extends StatelessWidget {
  const PageHeading({
    super.key,
    required this.title,
    required this.subtitle,
    this.compact = false,
  });

  final String title;
  final String subtitle;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    final description = subtitle.trim();
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Semantics(
          header: true,
          child: Text(
            title,
            style: TextStyle(
              fontSize: compact ? 18 : 20,
              height: 1.3,
              fontWeight: FontWeight.w600,
              color: colors.onSurface,
              letterSpacing: 0,
            ),
          ),
        ),
        if (description.isNotEmpty) ...[
          const SizedBox(height: AppTokens.space4),
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
  }
}
