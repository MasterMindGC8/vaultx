// Vault X's Matrix terminal design system: green phosphor on near-black, a CRT
// scanline/curvature/bloom shader over the whole app, and monospaced type
// throughout. Per CLAUDE.md, screens built on this theme must not fall back
// to Material/Cupertino default chrome — every control here is drawn from
// terminal primitives (borders, `>>` prompts, blocky ASCII-style buttons).
import 'package:flutter/material.dart';
import 'package:flutter/scheduler.dart';
import 'package:flutter_shaders/flutter_shaders.dart';

/// Vault X's fixed color palette. Not a `ThemeExtension` with light/dark
/// variants — the whole point of this app's aesthetic is that it never
/// looks like anything else, so it does not adapt to system theme.
abstract final class VaultXColors {
  static const phosphor = Color(0xFF00FF66);
  static const phosphorDim = Color(0xFF0A8F3D);
  static const background = Color(0xFF050505);
  static const backgroundPanel = Color(0xFF0A0F0A);
  static const alertRed = Color(0xFFFF0033);
  static const border = Color(0xFF104022);
}

/// Font family names registered via `pubspec.yaml`'s `fonts:` section.
abstract final class VaultXFonts {
  static const mono = 'Fira Code';
  static const terminal = 'VT323';
}

/// The single `ThemeData` Vault X's `MaterialApp` is built with. Widgets
/// should still prefer the explicit terminal-style widgets in
/// `lib/widgets/` over raw Material components, but this keeps any
/// Material internals Flutter itself renders (text selection handles,
/// scrollbars) from clashing with the aesthetic.
ThemeData buildVaultXThemeData() {
  return ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    scaffoldBackgroundColor: VaultXColors.background,
    fontFamily: VaultXFonts.mono,
    colorScheme: const ColorScheme.dark(
      surface: VaultXColors.background,
      primary: VaultXColors.phosphor,
      onPrimary: VaultXColors.background,
      secondary: VaultXColors.phosphorDim,
      error: VaultXColors.alertRed,
    ),
    textSelectionTheme: const TextSelectionThemeData(
      cursorColor: VaultXColors.phosphor,
      selectionColor: VaultXColors.phosphorDim,
      selectionHandleColor: VaultXColors.phosphor,
    ),
    textTheme: const TextTheme(
      bodyMedium: TextStyle(
        color: VaultXColors.phosphor,
        fontFamily: VaultXFonts.mono,
        fontSize: 14,
        height: 1.4,
      ),
    ),
  );
}

/// Wraps [child] with Vault X's CRT scanline/curvature/phosphor-bloom shader.
/// Mount once, near the root of the app (see `main.dart`), so every screen
/// underneath renders through the same tube.
class CrtOverlay extends StatefulWidget {
  const CrtOverlay({super.key, required this.child});

  final Widget child;

  @override
  State<CrtOverlay> createState() => _CrtOverlayState();
}

class _CrtOverlayState extends State<CrtOverlay>
    with SingleTickerProviderStateMixin {
  late final Ticker _ticker;
  double _elapsedSeconds = 0;

  @override
  void initState() {
    super.initState();
    _ticker = createTicker((elapsed) {
      setState(() => _elapsedSeconds = elapsed.inMicroseconds / 1e6);
    })..start();
  }

  @override
  void dispose() {
    _ticker.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ShaderBuilder(
      (context, shader, child) {
        return AnimatedSampler(
          (image, size, canvas) {
            shader
              ..setFloat(0, size.width)
              ..setFloat(1, size.height)
              ..setFloat(2, _elapsedSeconds)
              ..setImageSampler(0, image);
            canvas.drawRect(
              Rect.fromLTWH(0, 0, size.width, size.height),
              Paint()..shader = shader,
            );
          },
          child: child!,
        );
      },
      assetKey: 'assets/shaders/crt.frag',
      child: widget.child,
    );
  }
}
