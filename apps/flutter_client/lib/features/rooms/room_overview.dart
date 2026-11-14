part of 'rooms_page.dart';

class _DesktopRoomRow extends StatelessWidget {
  const _DesktopRoomRow({
    required this.name,
    required this.code,
    required this.owner,
    required this.status,
    required this.members,
    required this.notes,
    this.latency,
    this.lockedLabel,
    this.action,
  });

  final String name;
  final String code;
  final String owner;
  final Widget status;
  final Widget members;
  final Widget? latency;
  final List<String> notes;
  final String? lockedLabel;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    final metadataStyle = theme.textTheme.bodySmall!.copyWith(
      color: colors.textSecondary,
    );
    final identity = Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          width: AppTokens.space32,
          height: AppTokens.space32,
          decoration: BoxDecoration(
            color: colors.surfaceMuted,
            borderRadius: BorderRadius.circular(AppTokens.radiusSm),
          ),
          child: Icon(
            Icons.meeting_room_outlined,
            color: colors.textSecondary,
            size: AppTokens.iconMd,
          ),
        ),
        const SizedBox(width: AppTokens.space12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Wrap(
                spacing: AppTokens.space8,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  Text(name, style: theme.textTheme.titleMedium),
                  if (lockedLabel != null)
                    Tooltip(
                      message: lockedLabel!,
                      child: Icon(
                        Icons.lock_outline_rounded,
                        color: colors.textMuted,
                        size: AppTokens.iconSm,
                      ),
                    ),
                ],
              ),
              const SizedBox(height: AppTokens.space4),
              Wrap(
                spacing: AppTokens.space12,
                runSpacing: AppTokens.space4,
                children: [
                  Text(
                    code,
                    style: metadataStyle.copyWith(
                      fontFeatures: AppTokens.tabularFontFeatures,
                    ),
                  ),
                  Text(owner, style: metadataStyle),
                ],
              ),
            ],
          ),
        ),
      ],
    );
    final disclosure = Icon(
      Icons.chevron_right_rounded,
      size: AppTokens.iconMd,
      color: colors.textMuted,
    );
    return Padding(
      padding: const EdgeInsets.all(AppTokens.space12),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final wide =
              constraints.maxWidth >= 760 &&
              MediaQuery.textScalerOf(context).scale(14) <= 18;
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (wide)
                Row(
                  children: [
                    Expanded(flex: 4, child: identity),
                    const SizedBox(width: AppTokens.space16),
                    Expanded(flex: 2, child: status),
                    const SizedBox(width: AppTokens.space12),
                    Expanded(flex: 2, child: members),
                    const SizedBox(width: AppTokens.space12),
                    Expanded(
                      flex: 2,
                      child: latency ?? const SizedBox.shrink(),
                    ),
                    if (action != null) ...[
                      const SizedBox(width: AppTokens.space12),
                      SizedBox(
                        width: 184,
                        child: Align(
                          alignment: Alignment.centerRight,
                          child: action,
                        ),
                      ),
                    ],
                    const SizedBox(width: AppTokens.space8),
                    disclosure,
                  ],
                )
              else ...[
                Row(
                  children: [
                    Expanded(child: identity),
                    disclosure,
                  ],
                ),
                const SizedBox(height: AppTokens.space12),
                Padding(
                  padding: const EdgeInsetsDirectional.only(
                    start: AppTokens.space32 + AppTokens.space12,
                  ),
                  child: Wrap(
                    spacing: AppTokens.space16,
                    runSpacing: AppTokens.space8,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [status, members, ?latency, ?action],
                  ),
                ),
              ],
              if (notes.isNotEmpty) ...[
                const SizedBox(height: AppTokens.space8),
                Padding(
                  padding: const EdgeInsetsDirectional.only(
                    start: AppTokens.space32 + AppTokens.space12,
                  ),
                  child: Wrap(
                    spacing: AppTokens.space12,
                    runSpacing: AppTokens.space4,
                    children: [
                      for (final note in notes)
                        Text(
                          note,
                          style: metadataStyle.copyWith(
                            color: colors.warningText,
                          ),
                        ),
                    ],
                  ),
                ),
              ],
            ],
          );
        },
      ),
    );
  }
}

class _DesktopRoomsEmpty extends StatelessWidget {
  const _DesktopRoomsEmpty({required this.title, required this.message});

  final String title;
  final String message;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = P2WlanColors.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Divider(height: 1),
        Padding(
          padding: const EdgeInsets.symmetric(vertical: AppTokens.space24),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                width: AppTokens.space40,
                height: AppTokens.space40,
                decoration: BoxDecoration(
                  color: colors.selectedSurface,
                  borderRadius: BorderRadius.circular(AppTokens.radiusSm),
                ),
                child: Icon(
                  Icons.meeting_room_outlined,
                  color: theme.colorScheme.primary,
                  size: AppTokens.iconMd,
                ),
              ),
              const SizedBox(width: AppTokens.space12),
              Flexible(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(title, style: theme.textTheme.titleMedium),
                    const SizedBox(height: AppTokens.space4),
                    Text(
                      message,
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: colors.textSecondary,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
      ],
    );
  }
}

class _RoomRowMetric extends StatelessWidget {
  const _RoomRowMetric({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context).textTheme;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: theme.labelSmall?.copyWith(
            color: P2WlanColors.of(context).textSecondary,
          ),
        ),
        const SizedBox(height: AppTokens.space4),
        Text(
          value,
          style: theme.bodyMedium?.copyWith(
            fontFeatures: AppTokens.tabularFontFeatures,
          ),
        ),
      ],
    );
  }
}
