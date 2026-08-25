// Duress vault screen: PIN entry that opens either the real vault or the
// decoy vault, calling straight into crypto_core::storage::VaultManager via
// the FFI bridge. Per CLAUDE.md, a decoy unlock must be visually
// indistinguishable from a real one — this screen never renders a
// "you entered the decoy PIN" state; it just moves on to the same
// ConversationScreen either way, and the screen itself has no branch in
// its own UI on which PIN kind was entered.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

import '../bridge/native_crypto.dart';
import '../theme/cypher_theme.dart';
import '../widgets/terminal_widgets.dart';
import 'conversation_screen.dart';

/// Resolves where the two vault files live. Kept dependency-free (no
/// `path_provider`) by hand-picking a per-OS user-data directory; a real
/// packaged build should route this through platform-appropriate storage
/// APIs instead of `Directory.current`.
class VaultPaths {
  static Directory _baseDir() {
    // Lets two instances run side-by-side on one machine with independent
    // identities/vaults, e.g. for local testing of the relay/contact flow
    // without needing two physical devices.
    final override = Platform.environment['VAULTX_DATA_DIR'];
    if (override != null) return Directory(override);
    if (Platform.isWindows) {
      final appData = Platform.environment['APPDATA'];
      if (appData != null) return Directory('$appData/VaultX');
    }
    if (Platform.isLinux || Platform.isMacOS) {
      final home = Platform.environment['HOME'];
      if (home != null) return Directory('$home/.vaultx');
    }
    return Directory('${Directory.current.path}/.vaultx');
  }

  static String get realVaultPath => '${_baseDir().path}/real.vaultxvault';
  static String get decoyVaultPath => '${_baseDir().path}/decoy.vaultxvault';

  static Future<void> ensureDirectoryExists() async {
    await _baseDir().create(recursive: true);
  }

  static bool get bothVaultsProvisioned =>
      File(realVaultPath).existsSync() && File(decoyVaultPath).existsSync();
}

class DuressVaultScreen extends StatefulWidget {
  const DuressVaultScreen({super.key});

  @override
  State<DuressVaultScreen> createState() => _DuressVaultScreenState();
}

class _DuressVaultScreenState extends State<DuressVaultScreen> {
  final _pinController = TextEditingController();
  final _decoyPinController = TextEditingController();
  bool _isFirstRun = false;
  bool _checkedFirstRun = false;
  String? _statusMessage;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _checkFirstRun();
  }

  Future<void> _checkFirstRun() async {
    await VaultPaths.ensureDirectoryExists();
    setState(() {
      _isFirstRun = !VaultPaths.bothVaultsProvisioned;
      _checkedFirstRun = true;
    });
  }

  @override
  void dispose() {
    _pinController.dispose();
    _decoyPinController.dispose();
    super.dispose();
  }

  Future<void> _provision() async {
    final realPin = _pinController.text;
    final decoyPin = _decoyPinController.text;
    if (realPin.isEmpty || decoyPin.isEmpty) {
      setState(() => _statusMessage = 'BOTH PINS ARE REQUIRED');
      return;
    }
    if (realPin == decoyPin) {
      setState(() => _statusMessage = 'REAL AND DECOY PINS MUST DIFFER');
      return;
    }
    setState(() {
      _busy = true;
      _statusMessage = null;
    });
    try {
      final realVault = NativeCrypto.instance.createVault(
        VaultPaths.realVaultPath,
        utf8.encode(realPin),
      );
      final decoyVault = NativeCrypto.instance.createVault(
        VaultPaths.decoyVaultPath,
        utf8.encode(decoyPin),
      );
      if (realVault == null || decoyVault == null) {
        setState(() => _statusMessage = 'VAULT PROVISIONING FAILED');
        return;
      }
      // Provisioning only needs to confirm the decoy vault was created
      // successfully — it isn't entered now, so its handle must be freed
      // here. Leaving it open (as this used to) holds the decoy vault
      // file locked for the rest of the process, causing any decoy PIN
      // unlock attempt later in the same session to fail with "ACCESS
      // DENIED" until the app actually restarts and the OS reclaims the
      // handle.
      decoyVault.dispose();
      if (!mounted) return;
      _enterConsole(realVault, isDecoy: false);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _unlock() async {
    final pin = _pinController.text;
    if (pin.isEmpty) return;
    setState(() {
      _busy = true;
      _statusMessage = null;
    });
    try {
      final outcome = NativeCrypto.instance.unlockVault(
        VaultPaths.realVaultPath,
        VaultPaths.decoyVaultPath,
        utf8.encode(pin),
      );
      if (outcome == null) {
        setState(() => _statusMessage = 'ACCESS DENIED');
        return;
      }
      if (!mounted) return;
      _enterConsole(outcome.vault, isDecoy: outcome.isDecoy);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  static const _identityVaultKey = 'device_identity_v1';

  /// Loads this vault's stored device identity, or creates and saves a new
  /// one if this is the first time this particular vault has been opened.
  /// Keeping the identity *in* the vault (rather than generating a fresh one
  /// every launch) is what keeps a device's ID — and thus its ability to be
  /// reached by contacts — stable across restarts.
  NativeIdentity _loadOrCreateIdentity(NativeVault vault) {
    final stored = vault.get(utf8.encode(_identityVaultKey));
    if (stored != null) {
      final loaded = NativeCrypto.instance.loadIdentity(stored);
      if (loaded != null) return loaded;
      // Falls through to regenerate only if the stored bytes were somehow
      // corrupt; a real deployment would surface this rather than silently
      // rotating identity.
    }
    final identity = NativeCrypto.instance.generateIdentity();
    vault.put(utf8.encode(_identityVaultKey), identity.toWireBytes());
    return identity;
  }

  void _enterConsole(NativeVault vault, {required bool isDecoy}) {
    final identity = _loadOrCreateIdentity(vault);
    Navigator.of(context).pushReplacement(
      MaterialPageRoute(
        builder: (_) =>
            ConversationScreen(vault: vault, identity: identity, isDecoy: isDecoy),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: VaultXColors.background,
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 480),
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: TerminalPanel(
              title: 'access control',
              child: !_checkedFirstRun
                  ? const Text(
                      '>> CHECKING VAULT STATE...',
                      style: TextStyle(
                        color: VaultXColors.phosphor,
                        fontFamily: VaultXFonts.mono,
                      ),
                    )
                  : _isFirstRun
                  ? _buildProvisionForm()
                  : _buildUnlockForm(),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildProvisionForm() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        const Text(
          'FIRST RUN: SET YOUR REAL AND DECOY PINS.\n'
          'THE DECOY PIN OPENS A SEPARATE, HARMLESS VAULT\n'
          'UNDER DURESS — CHOOSE ONE YOU CAN ENTER CONVINCINGLY.',
          style: TextStyle(
            color: VaultXColors.phosphorDim,
            fontFamily: VaultXFonts.mono,
            fontSize: 12,
          ),
        ),
        const SizedBox(height: 16),
        const Text(
          'REAL PIN',
          style: TextStyle(color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono),
        ),
        const SizedBox(height: 4),
        TerminalTextField(controller: _pinController, obscureText: true),
        const SizedBox(height: 16),
        const Text(
          'DECOY PIN',
          style: TextStyle(color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono),
        ),
        const SizedBox(height: 4),
        TerminalTextField(controller: _decoyPinController, obscureText: true),
        if (_statusMessage != null) ...[
          const SizedBox(height: 12),
          Text(
            _statusMessage!,
            style: const TextStyle(
              color: VaultXColors.alertRed,
              fontFamily: VaultXFonts.mono,
            ),
          ),
        ],
        const SizedBox(height: 20),
        Align(
          alignment: Alignment.centerRight,
          child: AsciiButton(
            label: _busy ? 'Working...' : 'Provision',
            onPressed: _busy ? null : _provision,
          ),
        ),
      ],
    );
  }

  Widget _buildUnlockForm() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        const Text(
          'ENTER PIN TO UNLOCK',
          style: TextStyle(color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono),
        ),
        const SizedBox(height: 8),
        TerminalTextField(
          controller: _pinController,
          obscureText: true,
          autofocus: true,
          onSubmitted: (_) => _unlock(),
        ),
        if (_statusMessage != null) ...[
          const SizedBox(height: 12),
          Text(
            _statusMessage!,
            style: const TextStyle(
              color: VaultXColors.alertRed,
              fontFamily: VaultXFonts.mono,
            ),
          ),
        ],
        const SizedBox(height: 20),
        Align(
          alignment: Alignment.centerRight,
          child: AsciiButton(
            label: _busy ? 'Working...' : 'Unlock',
            onPressed: _busy ? null : _unlock,
          ),
        ),
      ],
    );
  }
}
