import 'package:flutter/material.dart';

enum StatusTone { good, warn, bad, neutral }

class StatusBadge extends StatelessWidget {
  const StatusBadge({
    super.key,
    required this.label,
    this.tone = StatusTone.neutral,
  });

  final String label;
  final StatusTone tone;

  @override
  Widget build(BuildContext context) {
    final colors = _colors(context);
    return Container(
      constraints: const BoxConstraints(minHeight: 28, maxWidth: 180),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: colors.$1,
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: colors.$2),
      ),
      child: Text(
        label,
        overflow: TextOverflow.ellipsis,
        style: Theme.of(context).textTheme.labelMedium?.copyWith(
          color: colors.$3,
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }

  (Color, Color, Color) _colors(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return switch (tone) {
      StatusTone.good => (
        const Color(0xFFE8F5E9),
        const Color(0xFFA5D6A7),
        const Color(0xFF1B5E20),
      ),
      StatusTone.warn => (
        const Color(0xFFFFF8E1),
        const Color(0xFFFFD54F),
        const Color(0xFF7A4D00),
      ),
      StatusTone.bad => (
        const Color(0xFFFFEBEE),
        const Color(0xFFEF9A9A),
        const Color(0xFFB71C1C),
      ),
      StatusTone.neutral => (
        scheme.surfaceContainerHighest,
        scheme.outlineVariant,
        scheme.onSurfaceVariant,
      ),
    };
  }
}
