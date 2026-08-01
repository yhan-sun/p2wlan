part of '../settings_page.dart';

class _ResponsiveFieldRow extends StatelessWidget {
  const _ResponsiveFieldRow({required this.first, required this.second});

  final Widget first;
  final Widget second;

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 560) {
          return Column(children: [first, const SizedBox(height: 12), second]);
        }
        return Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(child: first),
            const SizedBox(width: 12),
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
    this.keyboardType,
    this.obscureText = false,
  });

  final TextEditingController controller;
  final String label;
  final String helper;
  final TextInputType? keyboardType;
  final bool obscureText;

  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: controller,
      keyboardType: keyboardType,
      obscureText: obscureText,
      decoration: InputDecoration(labelText: label, helperText: helper),
    );
  }
}

class _ErrorBanner extends StatelessWidget {
  const _ErrorBanner({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: AppTokens.colorBadBg,
        borderRadius: BorderRadius.circular(AppTokens.radiusMd),
        border: Border.all(color: AppTokens.colorBadBorder),
      ),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Text(
          message,
          style: const TextStyle(
            color: AppTokens.colorBadText,
            fontSize: 13,
            height: 1.35,
          ),
        ),
      ),
    );
  }
}
