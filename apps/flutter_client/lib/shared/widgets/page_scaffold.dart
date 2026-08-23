import 'package:flutter/material.dart';

import '../../app/app_tokens.dart';
import '../layout/app_breakpoints.dart';

class PageScaffold extends StatelessWidget {
  const PageScaffold({
    super.key,
    required this.title,
    required this.subtitle,
    required this.children,
    this.showHeader = true,
    this.maxWidth = defaultPageMaxWidth,
  });

  static const defaultPageMaxWidth = 980.0;

  final String title;
  final String subtitle;
  final List<Widget> children;
  final bool showHeader;
  final double maxWidth;

  @override
  Widget build(BuildContext context) {
    final trimmedSubtitle = subtitle.trim();
    return SafeArea(
      child: LayoutBuilder(
        builder: (context, constraints) {
          // Content density follows the shell's compact breakpoint: below it
          // (phones / very narrow windows) the page uses tighter padding.
          final isNarrow =
              constraints.maxWidth < AppBreakpoints.compactMaxWidth;
          final horizontalPadding = isNarrow
              ? AppTokens.space14
              : AppTokens.space24;
          final verticalPadding = isNarrow
              ? AppTokens.space14
              : AppTokens.space20;

          return ListView(
            padding: EdgeInsets.fromLTRB(
              horizontalPadding,
              verticalPadding,
              horizontalPadding,
              verticalPadding + AppTokens.space8,
            ),
            children: [
              Center(
                child: ConstrainedBox(
                  constraints: BoxConstraints(maxWidth: maxWidth),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      if (showHeader) ...[
                        Align(
                          alignment: isNarrow
                              ? Alignment.center
                              : Alignment.centerLeft,
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            crossAxisAlignment: isNarrow
                                ? CrossAxisAlignment.center
                                : CrossAxisAlignment.start,
                            children: [
                              Text(
                                title,
                                textAlign: isNarrow
                                    ? TextAlign.center
                                    : TextAlign.left,
                                style: TextStyle(
                                  fontSize: isNarrow ? 20 : 22,
                                  fontWeight: FontWeight.w600,
                                  color: Theme.of(
                                    context,
                                  ).colorScheme.onSurface,
                                  letterSpacing: 0,
                                ),
                              ),
                              if (trimmedSubtitle.isNotEmpty) ...[
                                const SizedBox(height: 3),
                                Text(
                                  trimmedSubtitle,
                                  textAlign: isNarrow
                                      ? TextAlign.center
                                      : TextAlign.left,
                                  style: TextStyle(
                                    fontSize: 13,
                                    fontWeight: FontWeight.w400,
                                    color: Theme.of(
                                      context,
                                    ).colorScheme.onSurfaceVariant,
                                  ),
                                ),
                              ],
                            ],
                          ),
                        ),
                        const SizedBox(height: AppTokens.space16),
                      ],
                      ...children,
                    ],
                  ),
                ),
              ),
            ],
          );
        },
      ),
    );
  }
}
