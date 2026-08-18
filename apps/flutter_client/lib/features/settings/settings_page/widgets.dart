part of '../settings_page.dart';

/// Two-column responsive field pair. Collapses to a single column on narrow
/// screens so two text fields never sit side-by-side on a phone.
class _ResponsiveFieldRow extends StatelessWidget {
  const _ResponsiveFieldRow({required this.first, required this.second});

  final Widget first;
  final Widget second;

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 560) {
          return Column(
            children: [
              first,
              const SizedBox(height: AppTokens.space12),
              second,
            ],
          );
        }
        return Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(child: first),
            const SizedBox(width: AppTokens.space12),
            Expanded(child: second),
          ],
        );
      },
    );
  }
}

class _SettingsTextField extends StatelessWidget {
  const _SettingsTextField({
    required this.controller,
    required this.label,
    required this.helper,
    this.hintText,
    this.keyboardType,
    this.obscureText = false,
    this.errorText,
    this.onSubmitted,
  });

  final TextEditingController controller;
  final String label;
  final String helper;
  final String? hintText;
  final TextInputType? keyboardType;
  final bool obscureText;
  final String? errorText;
  final ValueChanged<String>? onSubmitted;

  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: controller,
      keyboardType: keyboardType,
      obscureText: obscureText,
      onSubmitted: onSubmitted,
      decoration: InputDecoration(
        labelText: label,
        hintText: hintText,
        helperText: helper,
        errorText: errorText,
      ),
    );
  }
}

/// A titled settings group. Lighter than a full panel: a muted section heading
/// with a hairline, then the rows, so the page reads as a real preference app
/// rather than a stack of cards.
class _SettingsSection extends StatelessWidget {
  const _SettingsSection({
    required this.title,
    required this.children,
    this.helper,
  });

  final String title;
  final String? helper;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title.toUpperCase(),
          style: TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w700,
            letterSpacing: 0.6,
            color: theme.colorScheme.primary,
          ),
        ),
        if (helper != null && helper!.isNotEmpty) ...[
          const SizedBox(height: 2),
          Text(
            helper!,
            style: TextStyle(
              fontSize: 12,
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
        const SizedBox(height: AppTokens.space10),
        Container(
          decoration: BoxDecoration(
            color: theme.colorScheme.surface,
            borderRadius: BorderRadius.circular(AppTokens.radiusLg),
            border: Border.all(color: theme.colorScheme.outlineVariant),
          ),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
            child: Column(children: children),
          ),
        ),
      ],
    );
  }
}

/// A horizontal, dense preference row (label + subtitle on the left, control on
/// the right). Collapses to a stacked column on narrow screens. Used for
/// dropdown-style settings and short value tiles so we do not spend 100px per
/// item on full-width text fields.
class _SettingsRow extends StatelessWidget {
  const _SettingsRow({
    required this.label,
    required this.control,
    this.subtitle,
  });

  final String label;
  final String? subtitle;
  final Widget control;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final labelColumn = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(
          label,
          style: TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w500,
            color: theme.colorScheme.onSurface,
          ),
        ),
        if (subtitle != null && subtitle!.isNotEmpty) ...[
          const SizedBox(height: 3),
          Text(
            subtitle!,
            style: TextStyle(
              fontSize: 12,
              height: 1.35,
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ],
    );

    return LayoutBuilder(
      builder: (context, constraints) {
        final endPadding = const EdgeInsets.only(bottom: 16);
        if (constraints.maxWidth < 520) {
          return Padding(
            padding: endPadding,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                labelColumn,
                const SizedBox(height: AppTokens.space8),
                SizedBox(width: double.infinity, child: control),
              ],
            ),
          );
        }
        return Padding(
          padding: endPadding,
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              Expanded(child: labelColumn),
              const SizedBox(width: AppTokens.space16),
              SizedBox(width: 260, child: control),
            ],
          ),
        );
      },
    );
  }
}

/// Progressively disclosed settings group. Defaults to collapsed; the header
/// carries a real label plus an "Expand / Collapse" text (never just a chevron)
/// for accessibility. The open state is owned by the page so it survives within
/// the current page lifecycle but is not persisted.
class _SettingsDisclosure extends StatelessWidget {
  const _SettingsDisclosure({
    required this.title,
    required this.subtitle,
    required this.open,
    required this.onToggle,
    required this.children,
  });

  final String title;
  final String subtitle;
  final bool open;
  final VoidCallback onToggle;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    final trailingLabel = open
        ? strings.disclosureCollapse
        : strings.disclosureExpand;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Material(
          type: MaterialType.transparency,
          child: InkWell(
            key: Key('settings-disclosure-$title'),
            borderRadius: BorderRadius.circular(AppTokens.radiusLg),
            onTap: onToggle,
            child: Container(
              padding: const EdgeInsets.symmetric(
                horizontal: AppTokens.space16,
                vertical: AppTokens.space14,
              ),
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(AppTokens.radiusLg),
                border: Border.all(color: theme.colorScheme.outlineVariant),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          title,
                          style: TextStyle(
                            fontSize: 15,
                            fontWeight: FontWeight.w600,
                            color: theme.colorScheme.onSurface,
                          ),
                        ),
                        if (subtitle.isNotEmpty) ...[
                          const SizedBox(height: 3),
                          Text(
                            subtitle,
                            style: TextStyle(
                              fontSize: 12,
                              height: 1.35,
                              color: theme.colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                  const SizedBox(width: AppTokens.space12),
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        trailingLabel,
                        style: TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                          color: theme.colorScheme.primary,
                        ),
                      ),
                      const SizedBox(width: AppTokens.space4),
                      Icon(
                        open ? Icons.expand_less : Icons.expand_more,
                        size: 20,
                        color: theme.colorScheme.primary,
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
        AnimatedSize(
          duration: AppTokens.durationMedium,
          curve: AppTokens.curveEase,
          alignment: Alignment.topCenter,
          child: open
              ? Padding(
                  padding: const EdgeInsets.fromLTRB(2, 10, 2, 2),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: children,
                  ),
                )
              : const SizedBox(width: double.infinity),
        ),
      ],
    );
  }
}

class _ErrorBanner extends StatelessWidget {
  const _ErrorBanner({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return DecoratedBox(
      decoration: BoxDecoration(
        color: theme.colorScheme.errorContainer,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: theme.colorScheme.error),
      ),
      child: Padding(
        padding: const EdgeInsets.all(AppTokens.space12),
        child: Text(
          message,
          style: TextStyle(
            color: theme.colorScheme.onErrorContainer,
            fontSize: 13,
            height: 1.35,
          ),
        ),
      ),
    );
  }
}

class _PendingRestartNotice extends StatelessWidget {
  const _PendingRestartNotice({
    required this.busy,
    required this.onRestart,
    required this.canRestart,
  });

  final bool busy;
  final bool canRestart;
  final Future<void> Function() onRestart;

  @override
  Widget build(BuildContext context) {
    final strings = AppStringsScope.of(context);
    final theme = Theme.of(context);
    return DecoratedBox(
      decoration: BoxDecoration(
        color: theme.colorScheme.secondaryContainer,
        border: Border.all(color: theme.colorScheme.outlineVariant),
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
      ),
      child: Padding(
        padding: const EdgeInsets.all(AppTokens.space12),
        child: LayoutBuilder(
          builder: (context, constraints) {
            final message = Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  strings.restartRequired,
                  style: TextStyle(
                    color: theme.colorScheme.onSecondaryContainer,
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 3),
                Text(
                  canRestart
                      ? strings.restartRequiredDetail
                      : strings.restartWillApplyLater,
                  style: TextStyle(
                    color: theme.colorScheme.onSecondaryContainer,
                    fontSize: 12,
                    height: 1.35,
                  ),
                ),
              ],
            );
            if (!canRestart) {
              return message;
            }
            final action = FilledButton.icon(
              onPressed: busy ? null : onRestart,
              icon: busy
                  ? const SizedBox.square(
                      dimension: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.restart_alt_rounded, size: 17),
              label: Text(strings.restartNow),
            );
            if (constraints.maxWidth < 540) {
              return Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  message,
                  const SizedBox(height: AppTokens.space10),
                  action,
                ],
              );
            }
            return Row(
              children: [
                Expanded(child: message),
                const SizedBox(width: AppTokens.space14),
                action,
              ],
            );
          },
        ),
      ),
    );
  }
}
