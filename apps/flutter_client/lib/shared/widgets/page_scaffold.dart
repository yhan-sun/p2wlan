import 'package:flutter/material.dart';

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
          final isNarrow = constraints.maxWidth < 640;
          final horizontalPadding = isNarrow ? 14.0 : 22.0;
          final verticalPadding = isNarrow ? 14.0 : 20.0;

          return ListView(
            padding: EdgeInsets.fromLTRB(
              horizontalPadding,
              verticalPadding,
              horizontalPadding,
              verticalPadding + 8,
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
                          alignment: Alignment.center,
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            crossAxisAlignment: CrossAxisAlignment.center,
                            children: [
                              Text(
                                title,
                                textAlign: TextAlign.center,
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
                                  textAlign: TextAlign.center,
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
                        const SizedBox(height: 16),
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
