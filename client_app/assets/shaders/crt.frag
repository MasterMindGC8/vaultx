// Vault X Matrix-terminal CRT shader.
//
// Applies to the whole app surface via a Flutter `FragmentShader` +
// `BackdropFilter`/`ShaderMask`-style paint (see
// `lib/theme/cypher_theme.dart`'s `CrtOverlay` widget). Composites onto
// whatever was already rendered underneath (`uTexture`): scanlines, a
// faint vignette, and a green phosphor tint/bloom so straight white UI
// text reads as glowing phosphor green even without recoloring every
// widget individually. No screen curvature/bend — flat, so the UI stays
// crisp and undistorted at every edge.
#version 460 core
#include <flutter/runtime_effect.glsl>

uniform vec2 uSize;   // logical size of the surface being shaded, in pixels
uniform float uTime;  // seconds since app start, for the slow scanline drift
uniform sampler2D uTexture;

out vec4 fragColor;

// Phosphor tint applied on top of the source color. Vault X's accent green.
const vec3 kPhosphor = vec3(0.0, 1.0, 0.4);

void main() {
    vec2 uv = FlutterFragCoord().xy / uSize;
    vec4 srcColor = texture(uTexture, uv);

    // Horizontal scanlines, drifting slowly downward over time so the
    // terminal never looks perfectly static.
    float scanlineY = uv.y * uSize.y + uTime * 12.0;
    float scanline = 0.5 + 0.5 * sin(scanlineY * 3.14159265);
    float scanlineDarken = mix(0.9, 1.0, scanline);

    // Faint per-pixel phosphor mask (every third column dimmed slightly),
    // approximating an aperture grille without needing a texture asset.
    float column = mod(uv.x * uSize.x, 3.0);
    float grille = column < 1.0 ? 0.97 : 1.0;

    // Very faint vignette — just enough to feel like a screen, not a bend.
    vec2 centered = uv * 2.0 - 1.0;
    float vignette = 1.0 - 0.12 * dot(centered, centered);

    vec3 shaped = srcColor.rgb * scanlineDarken * grille * vignette;

    // Phosphor bloom: push bright pixels further toward the accent green so
    // highlights read as glowing rather than merely light-colored.
    float luma = dot(shaped, vec3(0.299, 0.587, 0.114));
    float bloom = smoothstep(0.6, 1.0, luma);
    vec3 bloomed = mix(shaped, kPhosphor, bloom * 0.2);

    fragColor = vec4(bloomed, srcColor.a);
}
