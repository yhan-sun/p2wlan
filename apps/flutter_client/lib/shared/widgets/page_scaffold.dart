import 'package:flutter/material.dart';

import '../../app/app_tokens.dart';
import 'page_heading.dart';

class PageScaffold extends StatelessWidget {
  const PageScaffold({
    super.key,
    required this.title,
    required this.subtitle,
    required this.children,
    this.showHeader = true,
    this.maxWidth = defaultPageMaxWidth,
    this.actions = const [],
    this.scrollController,
    this.toolbar,
  });

  static const defaultPageMaxWidth = 980.0;

  final String title;
  final String subtitle;
  final List<Widget> children;
  final bool showHeader;
  final double maxWidth;
  final List<Widget> actions;
  final ScrollController? scrollController;
  final Widget? toolbar;

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: LayoutBuilder(
        builder: (context, constraints) {
          final isNarrow = constraints.maxWidth < 480;
          final horizontalPadding = isNarrow
              ? AppTokens.space16
              : AppTokens.space24;
          final verticalPadding = isNarrow
              ? AppTokens.space16
              : AppTokens.space20;

          return ListView(
            controller: scrollController,
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
                        PageHeading(
                          title: title,
                          subtitle: subtitle,
                          compact: isNarrow,
                          actions: actions,
                          toolbar: toolbar,
                        ),
                        const SizedBox(height: AppTokens.space16),
                      ] else if (toolbar != null || actions.isNotEmpty) ...[
                        Wrap(
                          spacing: AppTokens.space8,
                          runSpacing: AppTokens.space8,
                          children: [?toolbar, ...actions],
                        ),
                        const SizedBox(height: AppTokens.space12),
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
