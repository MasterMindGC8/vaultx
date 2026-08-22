// Add Contact: shows this device's own ID to share, and lets the user
// paste a friend's Device ID to start a real PQXDH handshake with them over
// the relay. This is the screen that answers "how do I actually start a
// conversation" — CYAN/Vault X has no accounts or phone-number directory by
// design (zero-knowledge posture), so devices find each other purely by
// this opaque ID, exchanged however the two people already talk to each
// other (in person, a messaging app, a phone call).
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../bridge/native_crypto.dart';
import '../models/contact.dart';
import '../services/relay_client.dart';
import '../theme/cypher_theme.dart';
import '../widgets/terminal_widgets.dart';

/// Result of a successful add: the new contact plus the live session
/// established with them, and the handshake packet the caller must still
/// relay to the peer.
class AddContactResult {
  AddContactResult({
    required this.contact,
    required this.session,
    required this.handshakePacketId,
    required this.handshakePayload,
  });

  final Contact contact;
  final NativeSession session;
  final String handshakePacketId;
  final List<int> handshakePayload;
}

class AddContactScreen extends StatefulWidget {
  const AddContactScreen({
    super.key,
    required this.identity,
    required this.relayHttp,
    required this.myDeviceId,
  });

  final NativeIdentity identity;
  final RelayHttp relayHttp;
  final String myDeviceId;

  @override
  State<AddContactScreen> createState() => _AddContactScreenState();
}

class _AddContactScreenState extends State<AddContactScreen> {
  final _labelController = TextEditingController();
  final _deviceIdController = TextEditingController();
  String? _statusMessage;
  bool _busy = false;

  @override
  void dispose() {
    _labelController.dispose();
    _deviceIdController.dispose();
    super.dispose();
  }

  Future<void> _copyMyId() async {
    await Clipboard.setData(ClipboardData(text: widget.myDeviceId));
    if (!mounted) return;
    setState(() => _statusMessage = 'COPIED YOUR DEVICE ID TO CLIPBOARD');
  }

  Future<void> _addContact() async {
    final friendId = _deviceIdController.text.trim().toLowerCase();
    final label = _labelController.text.trim();
    if (friendId.length != 64 || !RegExp(r'^[0-9a-f]+$').hasMatch(friendId)) {
      setState(() => _statusMessage = 'DEVICE ID MUST BE 64 HEX CHARACTERS');
      return;
    }
    if (friendId == widget.myDeviceId) {
      setState(() => _statusMessage = "THAT'S YOUR OWN DEVICE ID");
      return;
    }
    setState(() {
      _busy = true;
      _statusMessage = 'LOOKING UP DEVICE...';
    });
    try {
      final bundle = await widget.relayHttp.fetchPreKeyBundle(friendId);
      if (bundle == null) {
        setState(
          () => _statusMessage =
              'NO BUNDLE PUBLISHED FOR THIS ID YET — ASK THEM TO OPEN THE APP',
        );
        return;
      }
      final outcome = NativeCrypto.instance.initiateSession(widget.identity, bundle);
      if (outcome == null) {
        setState(() => _statusMessage = 'HANDSHAKE FAILED — MALFORMED BUNDLE');
        return;
      }
      if (!mounted) return;
      Navigator.of(context).pop(
        AddContactResult(
          contact: Contact(
            deviceId: friendId,
            label: label.isEmpty ? '0x${friendId.substring(0, 8).toUpperCase()}' : label,
          ),
          session: outcome.session,
          handshakePacketId: DateTime.now().microsecondsSinceEpoch.toString(),
          handshakePayload: outcome.initialMessageBytes,
        ),
      );
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: VaultXColors.background,
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 560),
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                TerminalPanel(
                  title: 'your device id — share this with a friend',
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      SelectableText(
                        widget.myDeviceId,
                        style: const TextStyle(
                          color: VaultXColors.phosphor,
                          fontFamily: VaultXFonts.mono,
                          fontSize: 13,
                        ),
                      ),
                      const SizedBox(height: 12),
                      Align(
                        alignment: Alignment.centerRight,
                        child: AsciiButton(label: 'Copy', onPressed: _copyMyId),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 16),
                TerminalPanel(
                  title: 'add a contact',
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Text(
                        "ASK YOUR FRIEND FOR THEIR DEVICE ID (SHOWN ON THIS SAME\n"
                        "SCREEN ON THEIR END) AND PASTE IT BELOW. THEY MUST HAVE\n"
                        "OPENED THE APP AT LEAST ONCE SO THEIR DEVICE HAS\n"
                        "PUBLISHED ITSELF TO THE RELAY.",
                        style: TextStyle(
                          color: VaultXColors.phosphorDim,
                          fontFamily: VaultXFonts.mono,
                          fontSize: 12,
                        ),
                      ),
                      const SizedBox(height: 16),
                      const Text(
                        'LABEL (OPTIONAL)',
                        style: TextStyle(color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono),
                      ),
                      const SizedBox(height: 4),
                      TerminalTextField(
                        controller: _labelController,
                        hintText: 'e.g. Alex',
                      ),
                      const SizedBox(height: 16),
                      const Text(
                        "FRIEND'S DEVICE ID",
                        style: TextStyle(color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono),
                      ),
                      const SizedBox(height: 4),
                      TerminalTextField(
                        controller: _deviceIdController,
                        hintText: '64 hex characters',
                        onSubmitted: (_) => _addContact(),
                      ),
                      if (_statusMessage != null) ...[
                        const SizedBox(height: 12),
                        Text(
                          _statusMessage!,
                          style: const TextStyle(
                            color: VaultXColors.phosphor,
                            fontFamily: VaultXFonts.mono,
                            fontSize: 12,
                          ),
                        ),
                      ],
                      const SizedBox(height: 20),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.end,
                        children: [
                          AsciiButton(
                            label: 'Cancel',
                            onPressed: () => Navigator.of(context).pop(),
                          ),
                          const SizedBox(width: 8),
                          AsciiButton(
                            label: _busy ? 'Working...' : 'Add',
                            onPressed: _busy ? null : _addContact,
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
