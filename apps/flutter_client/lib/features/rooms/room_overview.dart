part of 'rooms_page.dart';

class _DesktopRoomListTitle extends StatelessWidget {
  const _DesktopRoomListTitle({required this.title, this.count});

  final String title;
  final int? count;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context).textTheme;
    final colors = P2WlanColors.of(context);
    return Semantics(
      header: true,
      child: Wrap(
        spacing: AppTokens.space10,
        runSpacing: AppTokens.space4,
        crossAxisAlignment: WrapCrossAlignment.center,
        children: [
          Text(title, style: theme.titleMedium),
          if (count != null)
            DecoratedBox(
              decoration: BoxDecoration(
                color: colors.neutralSurface,
                borderRadius: BorderRadius.circular(100),
              ),
              child: Padding(
                padding: const EdgeInsets.symmetric(
                  horizontal: AppTokens.space8,
                  vertical: AppTokens.space2,
                ),
                child: Text(
                  '$count',
                  style: theme.labelSmall?.copyWith(
                    color: colors.textSecondary,
                    fontFeatures: AppTokens.tabularFontFeatures,
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class _DesktopRoomRow extends StatelessWidget {
  const _DesktopRoomRow({
    required this.name,
    required this.code,
    required this.owner,
    required this.connected,
    required this.hasOnlineMembers,
    required this.members,
    required this.latencyOrStatus,
    required this.notes,
    this.lockedLabel,
    this.action,
  });

  static const _identityInset = 56.0;
  static const _buttonWidth = 114.0;

  final String name;
  final String code;
  final String owner;
  final bool connected;
  final bool hasOnlineMembers;
  final Widget members;
  final Widget latencyOrStatus;
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
    final onlineTile = Color.alphaBlend(
      colors.probing.withValues(alpha: 0.10),
      colors.surfaceElevated,
    );
    final (icon, iconColor, tile) = switch ((connected, hasOnlineMembers)) {
      (true, _) => (
        'gamepad',
        theme.colorScheme.primary,
        colors.selectedSurface,
      ),
      (_, true) => ('server', colors.probing, onlineTile),
      _ => ('globe', colors.textMuted, colors.hoverSurface),
    };
    final identity = Row(
      children: [
        Container(
          width: 44,
          height: 44,
          decoration: BoxDecoration(
            color: tile,
            borderRadius: BorderRadius.circular(AppTokens.radiusMd),
          ),
          alignment: Alignment.center,
          child: DesktopIcon(icon, size: 20, color: iconColor),
        ),
        const SizedBox(width: AppTokens.space12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Wrap(
                spacing: AppTokens.space8,
                runSpacing: AppTokens.space4,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  Tooltip(
                    message: name,
                    excludeFromSemantics: true,
                    child: Text(
                      name,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.titleMedium,
                    ),
                  ),
                  Tooltip(
                    message: owner,
                    excludeFromSemantics: true,
                    child: DecoratedBox(
                      decoration: BoxDecoration(
                        color: colors.neutralSurface,
                        borderRadius: BorderRadius.circular(100),
                      ),
                      child: Padding(
                        padding: const EdgeInsets.symmetric(
                          horizontal: AppTokens.space8,
                          vertical: AppTokens.space2,
                        ),
                        child: Text(
                          owner,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: metadataStyle.copyWith(fontSize: 12),
                        ),
                      ),
                    ),
                  ),
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
              const SizedBox(height: AppTokens.space6),
              Text(
                code,
                style: metadataStyle.copyWith(
                  fontFeatures: AppTokens.tabularFontFeatures,
                ),
              ),
            ],
          ),
        ),
      ],
    );
    final disclosure = SizedBox(
      width: 32,
      height: AppTokens.desktopControlHeight,
      child: Center(
        child: DesktopIcon('chevron-right', size: 17, color: colors.textMuted),
      ),
    );
    final connection = action == null
        ? null
        : SizedBox(width: _buttonWidth, child: action);
    return ConstrainedBox(
      constraints: const BoxConstraints(minHeight: 88),
      child: Padding(
        padding: const EdgeInsets.symmetric(
          horizontal: AppTokens.space20,
          vertical: AppTokens.space16,
        ),
        child: LayoutBuilder(
          builder: (context, constraints) {
            final wide =
                constraints.maxWidth >= 720 &&
                MediaQuery.textScalerOf(context).scale(14) <= 18;
            return Column(
              mainAxisAlignment: MainAxisAlignment.center,
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                if (wide)
                  Row(
                    children: [
                      Expanded(child: identity),
                      const SizedBox(width: AppTokens.space20),
                      SizedBox(width: 108, child: members),
                      const SizedBox(width: AppTokens.space16),
                      SizedBox(width: 138, child: latencyOrStatus),
                      const SizedBox(width: AppTokens.space20),
                      if (connection != null) ...[
                        connection,
                        const SizedBox(width: AppTokens.space8),
                      ],
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
                    padding: EdgeInsetsDirectional.only(
                      start: constraints.maxWidth >= 280 ? _identityInset : 0,
                    ),
                    child: Wrap(
                      spacing: AppTokens.space24,
                      runSpacing: AppTokens.space10,
                      crossAxisAlignment: WrapCrossAlignment.center,
                      children: [members, latencyOrStatus, ?connection],
                    ),
                  ),
                ],
                if (notes.isNotEmpty) ...[
                  const SizedBox(height: AppTokens.space8),
                  Padding(
                    padding: const EdgeInsetsDirectional.only(
                      start: _identityInset,
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
    return DesktopCard(
      padding: const EdgeInsets.all(AppTokens.space24),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: AppTokens.space40,
            height: AppTokens.space40,
            decoration: BoxDecoration(
              color: colors.selectedSurface,
              borderRadius: BorderRadius.circular(AppTokens.radiusMd),
            ),
            alignment: Alignment.center,
            child: DesktopIcon('gamepad', color: theme.colorScheme.primary),
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
    );
  }
}

class _RoomRowMetric extends StatelessWidget {
  const _RoomRowMetric({required this.label, required this.value});

  final String label;
  final Widget value;

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: Theme.of(context).textTheme.labelSmall
              ?.copyWith(color: P2WlanColors.of(context).textSecondary),
        ),
        const SizedBox(height: AppTokens.space4),
        value,
      ],
    );
  }
}
