// Boot screen: a simulated terminal diagnostic sequence, ending in an
// authentication prompt. Deliberately does not touch crypto_core at all —
// the real device identity only makes sense once the vault is unlocked
// (see DuressVaultScreen), since it's stored *in* the vault so it stays
// stable across restarts instead of being regenerated (and the Device ID
// changing) every launch.
import 'dart:async';

import 'package:flutter/material.dart';

import '../theme/cypher_theme.dart';
import '../widgets/terminal_widgets.dart';
import 'duress_vault_screen.dart';

class TerminalScreen extends StatefulWidget {
  const TerminalScreen({
    super.key,
    this.bootLineDelay = const Duration(milliseconds: 220),
  });

  /// Delay between each revealed boot line. Overridable so widget tests can
  /// run the boot sequence instantly instead of racing real timers.
  final Duration bootLineDelay;

  @override
  State<TerminalScreen> createState() => _TerminalScreenState();
}

const _bootSequence = [
  'VAULT X SECURE TERMINAL v1.0.0',
  'INITIALIZING POST-QUANTUM RATCHET...',
  'LOADING X25519 + ML-KEM-768 HYBRID KEX...',
  'LOADING RFC 9420 MLS GROUP RATCHET ENGINE...',
  'MOUNTING ENCRYPTED VAULT SUBSYSTEM (ARGON2ID)...',
  'ESTABLISHING ZERO-KNOWLEDGE RELAY LINK...',
  'ALL SYSTEMS NOMINAL.',
];

class _TerminalScreenState extends State<TerminalScreen> {
  final List<String> _visibleLines = [];
  bool _bootComplete = false;

  @override
  void initState() {
    super.initState();
    _runBootSequence();
  }

  Future<void> _runBootSequence() async {
    for (final line in _bootSequence) {
      await Future.delayed(widget.bootLineDelay);
      if (!mounted) return;
      setState(() => _visibleLines.add(line));
    }
    if (!mounted) return;
    setState(() => _bootComplete = true);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: VaultXColors.background,
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: SingleChildScrollView(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      for (final line in _visibleLines)
                        Padding(
                          padding: const EdgeInsets.symmetric(vertical: 2),
                          child: RichText(
                            text: TextSpan(
                              style: const TextStyle(
                                fontFamily: VaultXFonts.mono,
                                fontSize: 13,
                              ),
                              children: [
                                const TextSpan(
                                  text: '[OK] ',
                                  style: TextStyle(
                                    color: VaultXColors.phosphor,
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                                TextSpan(
                                  text: line,
                                  style: const TextStyle(
                                    color: VaultXColors.phosphorDim,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
              ),
              if (_bootComplete)
                Padding(
                  padding: const EdgeInsets.only(top: 16),
                  child: Row(
                    children: [
                      const Expanded(
                        child: TerminalPrompt(
                          text: 'PRESS CONTINUE TO AUTHENTICATE',
                          typewriter: true,
                        ),
                      ),
                      AsciiButton(
                        label: 'Continue',
                        onPressed: () {
                          Navigator.of(context).pushReplacement(
                            MaterialPageRoute(
                              builder: (_) => const DuressVaultScreen(),
                            ),
                          );
                        },
                      ),
                    ],
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}
