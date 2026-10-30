import 'package:flutter/material.dart';

import '../../app/app_tokens.dart';

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
          final isNarrow = constraints.maxWidth < 480;
          final horizontalPadding = isNarrow
              ? AppTokens.space16
              : AppTokens.space28;
          final verticalPadding = isNarrow
              ? AppTokens.space20
              : AppTokens.space24;

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
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      if (showHeader) ...[
                        Align(
                          alignment: Alignment.centerLeft,
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                title,
                                textAlign: TextAlign.left,
                                style: TextStyle(
                                  fontSize: isNarrow ? 22 : 24,
                                  height: 1.25,
                                  fontWeight: FontWeight.w700,
                                  color: Theme.of(context)
                                      .colorScheme
                                      .onSurface,
                                  letterSpacing: 0,
                                ),
                              ),
                              if (trimmedSubtitle.isNotEmpty) ...[
                                const SizedBox(height: 6),
                                Text(
                                  trimmedSubtitle,
                                  textAlign: TextAlign.left,
                                  style: TextStyle(
                                    fontSize: 14,
                                    height: 1.45,
                                    fontWeight: FontWeight.w400,
                                    color: Theme.of(context)
                                        .colorScheme
                                        .onSurfaceVariant,
                                  ),
                                ),
                              ],
                            ],
                          ),
                        ),
                        const SizedBox(height: AppTokens.space20),
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
