// Shared terminal-style primitives used across Vault X's screens, so no
// screen falls back to default Material chrome (buttons, cards, dialogs).
import 'dart:async';

import 'package:flutter/material.dart';

import '../theme/cypher_theme.dart';

/// A bordered box with a small `[ TITLE ]` label cut into the top border,
/// evoking a boxed terminal panel (`dialog(1)`-style).
class TerminalPanel extends StatelessWidget {
  const TerminalPanel({
    super.key,
    required this.child,
    this.title,
    this.borderColor = VaultXColors.border,
    this.padding = const EdgeInsets.all(16),
  });

  final Widget child;
  final String? title;
  final Color borderColor;
  final EdgeInsets padding;

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: VaultXColors.backgroundPanel,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: borderColor),
        boxShadow: [
          BoxShadow(
            color: VaultXColors.phosphor.withValues(alpha: 0.06),
            blurRadius: 24,
            spreadRadius: -4,
          ),
        ],
      ),
      clipBehavior: Clip.antiAlias,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (title != null)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                color: VaultXColors.phosphorDim.withValues(alpha: 0.06),
                border: Border(bottom: BorderSide(color: borderColor)),
              ),
              child: Text(
                '[ ${title!.toUpperCase()} ]',
                style: const TextStyle(
                  color: VaultXColors.phosphor,
                  fontFamily: VaultXFonts.mono,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.5,
                ),
              ),
            ),
          Padding(padding: padding, child: child),
        ],
      ),
    );
  }
}

/// A flat, rectangular, ASCII-bracketed button: `[ LABEL ]`. Deliberately
/// not `ElevatedButton`/`TextButton` — no Material ripple, elevation, or
/// rounded corners.
class AsciiButton extends StatefulWidget {
  const AsciiButton({
    super.key,
    required this.label,
    required this.onPressed,
    this.danger = false,
  });

  final String label;
  final VoidCallback? onPressed;
  final bool danger;

  @override
  State<AsciiButton> createState() => _AsciiButtonState();
}

class _AsciiButtonState extends State<AsciiButton> {
  bool _hovering = false;

  @override
  Widget build(BuildContext context) {
    final color = widget.danger ? VaultXColors.alertRed : VaultXColors.phosphor;
    final disabled = widget.onPressed == null;
    final active = _hovering && !disabled;
    return MouseRegion(
      cursor: disabled ? MouseCursor.defer : SystemMouseCursors.click,
      onEnter: (_) => setState(() => _hovering = true),
      onExit: (_) => setState(() => _hovering = false),
      child: GestureDetector(
        onTap: widget.onPressed,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 120),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          decoration: BoxDecoration(
            color: active ? color.withValues(alpha: 0.15) : Colors.transparent,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
              color: disabled ? color.withValues(alpha: 0.35) : color,
            ),
            boxShadow: active
                ? [
                    BoxShadow(
                      color: color.withValues(alpha: 0.35),
                      blurRadius: 12,
                      spreadRadius: -2,
                    ),
                  ]
                : null,
          ),
          child: Text(
            '[ ${widget.label.toUpperCase()} ]',
            textAlign: TextAlign.center,
            style: TextStyle(
              color: disabled ? color.withValues(alpha: 0.35) : color,
              fontFamily: VaultXFonts.mono,
              fontWeight: FontWeight.bold,
              letterSpacing: 1.2,
            ),
          ),
        ),
      ),
    );
  }
}

/// A single `>>` prompt line with a blinking block cursor at the end,
/// optionally revealed with a terminal typing animation.
class TerminalPrompt extends StatefulWidget {
  const TerminalPrompt({
    super.key,
    required this.text,
    this.typewriter = false,
    this.style,
  });

  final String text;
  final bool typewriter;
  final TextStyle? style;

  @override
  State<TerminalPrompt> createState() => _TerminalPromptState();
}

class _TerminalPromptState extends State<TerminalPrompt>
    with SingleTickerProviderStateMixin {
  late Timer _blinkTimer;
  bool _cursorVisible = true;
  int _visibleChars = 0;
  Timer? _typeTimer;

  @override
  void initState() {
    super.initState();
    _blinkTimer = Timer.periodic(const Duration(milliseconds: 530), (_) {
      if (!mounted) return;
      setState(() => _cursorVisible = !_cursorVisible);
    });
    if (widget.typewriter) {
      _typeTimer = Timer.periodic(const Duration(milliseconds: 18), (timer) {
        if (!mounted) return;
        setState(() => _visibleChars++);
        if (_visibleChars >= widget.text.length) {
          timer.cancel();
        }
      });
    } else {
      _visibleChars = widget.text.length;
    }
  }

  @override
  void dispose() {
    _blinkTimer.cancel();
    _typeTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final shown = widget.text.substring(
      0,
      _visibleChars.clamp(0, widget.text.length),
    );
    final style =
        widget.style ??
        const TextStyle(color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono);
    return RichText(
      text: TextSpan(
        style: style,
        children: [
          const TextSpan(text: '>> '),
          TextSpan(text: shown),
          TextSpan(text: _cursorVisible ? '█' : ' '),
        ],
      ),
    );
  }
}

/// A minimal, terminal-styled single-line text field: no fill, no rounded
/// corners, an underline in phosphor green, `>>` prompt prefix.
class TerminalTextField extends StatelessWidget {
  const TerminalTextField({
    super.key,
    required this.controller,
    this.hintText,
    this.obscureText = false,
    this.autofocus = false,
    this.onSubmitted,
  });

  final TextEditingController controller;
  final String? hintText;
  final bool obscureText;
  final bool autofocus;
  final ValueChanged<String>? onSubmitted;

  @override
  Widget build(BuildContext context) {
    const style = TextStyle(color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono);
    return Row(
      children: [
        const Text('>> ', style: style),
        Expanded(
          child: TextField(
            controller: controller,
            obscureText: obscureText,
            autofocus: autofocus,
            onSubmitted: onSubmitted,
            style: style,
            cursorColor: VaultXColors.phosphor,
            decoration: InputDecoration(
              isDense: true,
              border: const UnderlineInputBorder(
                borderSide: BorderSide(color: VaultXColors.border),
              ),
              focusedBorder: const UnderlineInputBorder(
                borderSide: BorderSide(color: VaultXColors.phosphor),
              ),
              enabledBorder: const UnderlineInputBorder(
                borderSide: BorderSide(color: VaultXColors.border),
              ),
              hintText: hintText,
              hintStyle: style.copyWith(color: VaultXColors.phosphorDim),
            ),
          ),
        ),
      ],
    );
  }
}

/// A small pill showing the active cipher state, e.g.
/// `ENC: AES-256-GCM | PQXDH ACTIVE`.
class CipherBadge extends StatelessWidget {
  const CipherBadge({super.key, required this.label});

  final String label;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: VaultXColors.phosphorDim),
      ),
      child: Text(
        label,
        style: const TextStyle(
          color: VaultXColors.phosphorDim,
          fontFamily: VaultXFonts.mono,
          fontSize: 11,
          letterSpacing: 0.5,
        ),
      ),
    );
  }
}

/// A small pulsing dot indicating a live/online connection, in the spirit
/// of a link-status LED.
class StatusDot extends StatefulWidget {
  const StatusDot({super.key, this.color = VaultXColors.phosphor, this.size = 8});

  final Color color;
  final double size;

  @override
  State<StatusDot> createState() => _StatusDotState();
}

class _StatusDotState extends State<StatusDot>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1400),
    )..repeat(reverse: true);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _controller,
      builder: (context, _) {
        final glow = 0.4 + 0.6 * _controller.value;
        return Container(
          width: widget.size,
          height: widget.size,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: widget.color,
            boxShadow: [
              BoxShadow(
                color: widget.color.withValues(alpha: glow * 0.8),
                blurRadius: 6,
                spreadRadius: 1,
              ),
            ],
          ),
        );
      },
    );
  }
}
