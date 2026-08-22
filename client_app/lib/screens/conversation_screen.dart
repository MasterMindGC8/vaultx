// Main console: split-view hacker terminal, now wired to a real relay
// connection. Left pane lists saved contacts, right pane shows the active
// conversation stream with cipher badges and terminal-style typing.
//
// This is the screen that makes Vault X an actual messenger rather than a
// local notepad: it publishes this device's prekey bundle to the relay,
// listens for incoming handshakes/messages on the WebSocket stream, and
// drives real PQXDH + Double Ratchet sessions per contact (see
// NativeSession in bridge/native_crypto.dart).
//
// Renders identically whether reached via a real or decoy vault unlock
// (see DuressVaultScreen) — there is no branch anywhere in this file on
// `isDecoy`. A decoy vault has its own independent identity and contact
// list, stored the same way; it just starts out empty like any fresh
// install would.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../bridge/native_crypto.dart';
import '../models/contact.dart';
import '../services/relay_client.dart';
import '../services/update_checker.dart';
import '../theme/cypher_theme.dart';
import '../widgets/terminal_widgets.dart';
import 'add_contact_screen.dart';

const _defaultRelayUrl = 'http://127.0.0.1:8443';
const _relayUrlVaultKey = 'relay_url_v1';
const _updateManifestUrlVaultKey = 'update_manifest_url_v1';
const _defaultUpdateManifestUrl =
    'https://raw.githubusercontent.com/MasterMindGC8/vaultx/master/update-manifest.json';

class ChatMessage {
  const ChatMessage({required this.fromSelf, required this.text, required this.sentAt});
  final bool fromSelf;
  final String text;
  final DateTime sentAt;
}

class ConversationScreen extends StatefulWidget {
  const ConversationScreen({
    super.key,
    required this.vault,
    required this.identity,
    required this.isDecoy,
  });

  final NativeVault vault;
  final NativeIdentity identity;
  final bool isDecoy;

  @override
  State<ConversationScreen> createState() => _ConversationScreenState();
}

class _ConversationScreenState extends State<ConversationScreen> {
  late final String _myDeviceId;
  late String _relayUrl;
  late RelayHttp _relayHttp;
  RelayStream? _relayStream;

  List<Contact> _contacts = [];
  Contact? _selectedContact;
  final Map<String, NativeSession> _sessions = {};
  final Map<String, List<ChatMessage>> _messagesByContact = {};
  final _composerController = TextEditingController();
  String _connectionStatus = 'CONNECTING...';
  late String _updateManifestUrl;

  @override
  void initState() {
    super.initState();
    _myDeviceId = widget.identity.deviceIdHex();
    _relayUrl = _loadRelayUrl();
    _relayHttp = RelayHttp(baseUrl: _relayUrl);
    _updateManifestUrl = _loadUpdateManifestUrl();
    _contacts = _loadContacts();
    for (final contact in _contacts) {
      _messagesByContact[contact.deviceId] = _loadHistory(contact);
    }
    _selectedContact = _contacts.isNotEmpty ? _contacts.first : null;
    _connectToRelay();
  }

  String _loadUpdateManifestUrl() {
    final stored = widget.vault.get(utf8.encode(_updateManifestUrlVaultKey));
    return stored == null ? _defaultUpdateManifestUrl : utf8.decode(stored);
  }

  void _saveUpdateManifestUrl(String url) {
    widget.vault.put(utf8.encode(_updateManifestUrlVaultKey), utf8.encode(url));
  }

  String _loadRelayUrl() {
    final stored = widget.vault.get(utf8.encode(_relayUrlVaultKey));
    return stored == null ? _defaultRelayUrl : utf8.decode(stored);
  }

  void _saveRelayUrl(String url) {
    widget.vault.put(utf8.encode(_relayUrlVaultKey), utf8.encode(url));
  }

  List<Contact> _loadContacts() {
    final stored = widget.vault.get(utf8.encode(Contact.vaultKey));
    if (stored == null) return [];
    try {
      return Contact.decodeList(stored);
    } catch (_) {
      return [];
    }
  }

  void _saveContacts() {
    widget.vault.put(utf8.encode(Contact.vaultKey), Contact.encodeList(_contacts));
  }

  List<ChatMessage> _loadHistory(Contact contact) {
    final stored = widget.vault.get(utf8.encode('history:${contact.deviceId}'));
    if (stored == null) return [];
    return utf8
        .decode(stored)
        .split('\n')
        .where((line) => line.isNotEmpty)
        .map(
          (line) => ChatMessage(
            fromSelf: line.startsWith('me: '),
            text: line.replaceFirst(RegExp(r'^(me|peer): '), ''),
            sentAt: DateTime.now(),
          ),
        )
        .toList();
  }

  void _persistHistory(Contact contact) {
    final lines = (_messagesByContact[contact.deviceId] ?? [])
        .map((m) => '${m.fromSelf ? 'me' : 'peer'}: ${m.text}')
        .join('\n');
    widget.vault.put(utf8.encode('history:${contact.deviceId}'), utf8.encode(lines));
  }

  Future<void> _connectToRelay() async {
    setState(() => _connectionStatus = 'CONNECTING...');
    try {
      final bundle = widget.identity.publicBundleBytes();
      await _relayHttp.publishPreKeyBundle(_myDeviceId, bundle);
      final stream = RelayStream(baseUrl: _relayUrl, deviceId: _myDeviceId);
      await stream.connect();
      stream.deliveries.listen(_handleDelivery);
      _relayStream = stream;
      if (!mounted) return;
      setState(() => _connectionStatus = 'ONLINE');
    } catch (e) {
      if (!mounted) return;
      setState(() => _connectionStatus = 'OFFLINE — RELAY UNREACHABLE');
    }
  }

  void _handleDelivery(RelayDelivery delivery) {
    if (delivery.payload.isEmpty) return;
    final tag = delivery.payload[0];
    final body = delivery.payload.sublist(1);

    if (tag == relayTagHandshake) {
      final session = NativeCrypto.instance.respondSession(widget.identity, body);
      if (session == null) return;
      _sessions[delivery.sender] = session;
      if (!_contacts.any((c) => c.deviceId == delivery.sender)) {
        final newContact = Contact(
          deviceId: delivery.sender,
          label: '0x${delivery.sender.substring(0, 8).toUpperCase()}',
        );
        setState(() {
          _contacts = [..._contacts, newContact];
          _messagesByContact[newContact.deviceId] = [];
          _selectedContact ??= newContact;
        });
        _saveContacts();
      }
    } else if (tag == relayTagMessage) {
      final session = _sessions[delivery.sender];
      if (session == null) return; // no session yet — can't decrypt, drop.
      final plaintext = session.decrypt(Uint8List.fromList(body));
      if (plaintext == null) return;
      final contact = _contacts.firstWhere(
        (c) => c.deviceId == delivery.sender,
        orElse: () => Contact(deviceId: delivery.sender, label: delivery.sender),
      );
      setState(() {
        _messagesByContact
            .putIfAbsent(contact.deviceId, () => [])
            .add(ChatMessage(fromSelf: false, text: utf8.decode(plaintext), sentAt: DateTime.now()));
      });
      _persistHistory(contact);
    }
    _relayStream?.ack(delivery.packetId);
  }

  Future<void> _openAddContact() async {
    final result = await Navigator.of(context).push<AddContactResult>(
      MaterialPageRoute(
        builder: (_) => AddContactScreen(
          identity: widget.identity,
          relayHttp: _relayHttp,
          myDeviceId: _myDeviceId,
        ),
      ),
    );
    if (result == null) return;
    _sessions[result.contact.deviceId] = result.session;
    setState(() {
      _contacts = [..._contacts, result.contact];
      _messagesByContact[result.contact.deviceId] = [];
      _selectedContact = result.contact;
    });
    _saveContacts();
    _relayStream?.send(
      result.contact.deviceId,
      result.handshakePacketId,
      Uint8List.fromList([relayTagHandshake, ...result.handshakePayload]),
    );
  }

  void _sendMessage() {
    final text = _composerController.text.trim();
    final contact = _selectedContact;
    if (text.isEmpty || contact == null) return;
    final session = _sessions[contact.deviceId];
    if (session == null) {
      setState(() => _connectionStatus = 'NO ACTIVE SESSION WITH THIS CONTACT');
      return;
    }
    final ciphertext = session.encrypt(Uint8List.fromList(utf8.encode(text)));
    final packetId = DateTime.now().microsecondsSinceEpoch.toString();
    _relayStream?.send(
      contact.deviceId,
      packetId,
      Uint8List.fromList([relayTagMessage, ...ciphertext]),
    );
    setState(() {
      _messagesByContact
          .putIfAbsent(contact.deviceId, () => [])
          .add(ChatMessage(fromSelf: true, text: text, sentAt: DateTime.now()));
      _composerController.clear();
    });
    _persistHistory(contact);
  }

  Future<void> _copyMyId() async {
    await Clipboard.setData(ClipboardData(text: _myDeviceId));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Device ID copied to clipboard')),
    );
  }

  Future<void> _editRelayUrl() async {
    final controller = TextEditingController(text: _relayUrl);
    final newUrl = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: VaultXColors.backgroundPanel,
        title: const Text(
          'RELAY ADDRESS',
          style: TextStyle(color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono),
        ),
        content: TerminalTextField(controller: controller),
        actions: [
          AsciiButton(label: 'Cancel', onPressed: () => Navigator.of(context).pop()),
          AsciiButton(
            label: 'Save',
            onPressed: () => Navigator.of(context).pop(controller.text.trim()),
          ),
        ],
      ),
    );
    if (newUrl == null || newUrl.isEmpty || newUrl == _relayUrl) return;
    setState(() => _relayUrl = newUrl);
    _saveRelayUrl(newUrl);
    _relayHttp = RelayHttp(baseUrl: newUrl);
    await _relayStream?.close();
    _relayStream = null;
    _sessions.clear();
    await _connectToRelay();
  }

  Future<void> _checkForUpdates() async {
    var manifestUrl = _updateManifestUrl;
    if (manifestUrl.isEmpty) {
      final controller = TextEditingController();
      final entered = await showDialog<String>(
        context: context,
        builder: (context) => AlertDialog(
          backgroundColor: VaultXColors.backgroundPanel,
          title: const Text(
            'UPDATE MANIFEST URL NOT SET',
            style: TextStyle(color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono),
          ),
          content: TerminalTextField(
            controller: controller,
            hintText: 'https://.../update-manifest.json',
          ),
          actions: [
            AsciiButton(label: 'Cancel', onPressed: () => Navigator.of(context).pop()),
            AsciiButton(
              label: 'Save',
              onPressed: () => Navigator.of(context).pop(controller.text.trim()),
            ),
          ],
        ),
      );
      if (entered == null || entered.isEmpty) return;
      manifestUrl = entered;
      setState(() => _updateManifestUrl = manifestUrl);
      _saveUpdateManifestUrl(manifestUrl);
    }

    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Checking for updates...')),
    );
    final update = await UpdateChecker.checkForUpdate(manifestUrl);
    if (!mounted) return;
    if (update == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text("You're on the latest version.")),
      );
      return;
    }

    final shouldUpdate = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: VaultXColors.backgroundPanel,
        title: Text(
          'UPDATE AVAILABLE: v${update.version}',
          style: const TextStyle(color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono),
        ),
        content: Text(
          update.notes ?? 'A newer version of Vault X is available.',
          style: const TextStyle(color: VaultXColors.phosphorDim, fontFamily: VaultXFonts.mono),
        ),
        actions: [
          AsciiButton(label: 'Later', onPressed: () => Navigator.of(context).pop(false)),
          AsciiButton(label: 'Update Now', onPressed: () => Navigator.of(context).pop(true)),
        ],
      ),
    );
    if (shouldUpdate != true) return;

    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Downloading update...')),
    );
    try {
      await UpdateChecker.downloadAndLaunchInstaller(update.installerUrl);
      // The installer needs this process's files unlocked to overwrite
      // them; closing now (rather than leaving the user to close it
      // manually) is what makes this a true one-click update.
      await Future.delayed(const Duration(milliseconds: 500));
      exit(0);
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Update failed: $e')),
      );
    }
  }

  @override
  void dispose() {
    _relayStream?.close();
    for (final session in _sessions.values) {
      session.dispose();
    }
    widget.identity.dispose();
    widget.vault.dispose();
    _composerController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: VaultXColors.background,
      body: Padding(
        padding: const EdgeInsets.all(12),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(
              width: 260,
              child: TerminalPanel(
                title: 'contacts',
                padding: EdgeInsets.zero,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Padding(
                      padding: const EdgeInsets.all(10),
                      child: Row(
                        children: [
                          Expanded(
                            child: Text(
                              _connectionStatus,
                              style: TextStyle(
                                color: _connectionStatus == 'ONLINE'
                                    ? VaultXColors.phosphor
                                    : VaultXColors.alertRed,
                                fontFamily: VaultXFonts.mono,
                                fontSize: 11,
                              ),
                            ),
                          ),
                          GestureDetector(
                            onTap: _editRelayUrl,
                            child: const Text(
                              '[relay]',
                              style: TextStyle(
                                color: VaultXColors.phosphorDim,
                                fontFamily: VaultXFonts.mono,
                                fontSize: 11,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const Divider(height: 1, color: VaultXColors.border),
                    if (_contacts.isEmpty)
                      Padding(
                        padding: const EdgeInsets.all(14),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Text(
                              'NO CONTACTS YET.\n\n'
                              'TAP "+ ADD CONTACT" BELOW, SHARE YOUR\n'
                              'DEVICE ID WITH A FRIEND, AND ENTER\n'
                              'THEIRS TO START A SECURE SESSION.',
                              style: TextStyle(
                                color: VaultXColors.phosphorDim,
                                fontFamily: VaultXFonts.mono,
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                      )
                    else
                      Expanded(
                        child: ListView(
                          shrinkWrap: true,
                          children: [
                            for (final contact in _contacts)
                              _ContactListTile(
                                contact: contact,
                                selected: contact.deviceId == _selectedContact?.deviceId,
                                online: _sessions.containsKey(contact.deviceId),
                                onTap: () => setState(() => _selectedContact = contact),
                              ),
                          ],
                        ),
                      ),
                    Padding(
                      padding: const EdgeInsets.all(10),
                      child: AsciiButton(label: '+ Add Contact', onPressed: _openAddContact),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: TerminalPanel(
                title: _selectedContact == null
                    ? 'terminal // no contact selected'
                    : 'terminal // ${_selectedContact!.label}',
                padding: EdgeInsets.zero,
                child: Column(
                  children: [
                    Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                      child: Row(
                        children: [
                          const CipherBadge(label: 'ENC: CHACHA20-POLY1305'),
                          const SizedBox(width: 8),
                          const CipherBadge(label: 'POST-QUANTUM: ENABLED'),
                          const Spacer(),
                          AsciiButton(label: 'My ID', onPressed: _copyMyId),
                          const SizedBox(width: 8),
                          AsciiButton(label: 'Updates', onPressed: _checkForUpdates),
                        ],
                      ),
                    ),
                    const Divider(height: 1, color: VaultXColors.border),
                    Expanded(
                      child: _selectedContact == null
                          ? const _NoContactSelectedHint()
                          : ListView(
                              padding: const EdgeInsets.all(14),
                              children: [
                                for (final message
                                    in _messagesByContact[_selectedContact!.deviceId] ?? [])
                                  _MessageLine(message: message),
                              ],
                            ),
                    ),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: const BoxDecoration(
                        border: Border(top: BorderSide(color: VaultXColors.border)),
                      ),
                      child: Row(
                        children: [
                          Expanded(
                            child: TerminalTextField(
                              controller: _composerController,
                              hintText: _selectedContact == null
                                  ? 'select a contact first...'
                                  : 'type a message...',
                              onSubmitted: (_) => _sendMessage(),
                            ),
                          ),
                          const SizedBox(width: 8),
                          AsciiButton(
                            label: 'Send',
                            onPressed: _selectedContact == null ? null : _sendMessage,
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _NoContactSelectedHint extends StatelessWidget {
  const _NoContactSelectedHint();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Padding(
        padding: EdgeInsets.all(24),
        child: Text(
          '>> ADD A CONTACT TO START YOUR FIRST SECURE\n'
          '   CONVERSATION. SHARE YOUR DEVICE ID (TAP\n'
          '   "MY ID" ABOVE) WITH A FRIEND, THEN USE\n'
          '   "+ ADD CONTACT" WITH THEIRS.',
          textAlign: TextAlign.center,
          style: TextStyle(
            color: VaultXColors.phosphorDim,
            fontFamily: VaultXFonts.mono,
            fontSize: 13,
          ),
        ),
      ),
    );
  }
}

class _ContactListTile extends StatelessWidget {
  const _ContactListTile({
    required this.contact,
    required this.selected,
    required this.online,
    required this.onTap,
  });

  final Contact contact;
  final bool selected;
  final bool online;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        color: selected ? VaultXColors.phosphorDim.withValues(alpha: 0.15) : null,
        child: Row(
          children: [
            Expanded(
              child: Text(
                contact.label,
                style: TextStyle(
                  color: selected ? VaultXColors.phosphor : VaultXColors.phosphorDim,
                  fontFamily: VaultXFonts.mono,
                  fontSize: 13,
                ),
              ),
            ),
            if (online) const StatusDot(),
          ],
        ),
      ),
    );
  }
}

class _MessageLine extends StatelessWidget {
  const _MessageLine({required this.message});

  final ChatMessage message;

  @override
  Widget build(BuildContext context) {
    final prefix = message.fromSelf ? 'you' : 'peer';
    final color = message.fromSelf ? VaultXColors.phosphor : VaultXColors.phosphorDim;
    final time = message.sentAt.toIso8601String().substring(11, 19);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: RichText(
        text: TextSpan(
          style: const TextStyle(fontFamily: VaultXFonts.mono, fontSize: 13),
          children: [
            TextSpan(text: '[$time] ', style: const TextStyle(color: VaultXColors.phosphorDim)),
            TextSpan(
              text: '<$prefix>: ',
              style: TextStyle(color: color, fontWeight: FontWeight.bold),
            ),
            TextSpan(text: message.text, style: const TextStyle(color: VaultXColors.phosphor)),
          ],
        ),
      ),
    );
  }
}
