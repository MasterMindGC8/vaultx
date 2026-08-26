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
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:ui' show AppExitResponse;

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';

import '../bridge/native_crypto.dart';
import '../models/contact.dart';
import '../services/app_logger.dart';
import '../services/file_transfer.dart';
import '../services/relay_client.dart';
import '../services/update_checker.dart';
import '../theme/cypher_theme.dart';
import '../widgets/terminal_widgets.dart';
import 'add_contact_screen.dart';

// Isolated relay deployment on a dedicated OVH VM (its own systemd unit,
// its own directory, its own firewall rule — see
// transport_relay/vaultx-relay.service) — reachable by any device running
// this app, not just localhost. Transport is currently plain (not
// TLS-wrapped); message content stays protected regardless since it's
// end-to-end encrypted before it ever reaches the relay, but that does mean
// connection metadata (who's connecting, when) isn't hidden from a network
// observer between a client and this server. See CLAUDE.md for what's and
// isn't covered at this milestone.
const _defaultRelayUrl = 'http://51.81.84.85:8443';
const _relayUrlVaultKey = 'relay_url_v1';
const _updateManifestUrlVaultKey = 'update_manifest_url_v1';
const _defaultUpdateManifestUrl =
    'https://raw.githubusercontent.com/MasterMindGC8/vaultx/master/update-manifest.json';

class ChatMessage {
  const ChatMessage({
    required this.id,
    required this.fromSelf,
    required this.sentAt,
    this.text,
    this.cipherHex,
    this.fileName,
    this.fileSize,
    this.filePath,
  });

  final String id;
  final bool fromSelf;
  final DateTime sentAt;
  final String? text;

  /// Hex of the actual Double Ratchet ciphertext this text message was
  /// carried as — shown by default instead of [text] (see
  /// `_MessageLine`'s reveal-on-tap behavior). Only set for text messages;
  /// files already require an explicit tap-to-open.
  final String? cipherHex;
  final String? fileName;
  final int? fileSize;
  final String? filePath;

  bool get isFile => fileName != null;

  Map<String, dynamic> toJson() => {
    'id': id,
    'fromSelf': fromSelf,
    'sentAt': sentAt.toIso8601String(),
    if (text != null) 'text': text,
    if (cipherHex != null) 'cipherHex': cipherHex,
    if (fileName != null) 'fileName': fileName,
    if (fileSize != null) 'fileSize': fileSize,
    if (filePath != null) 'filePath': filePath,
  };

  factory ChatMessage.fromJson(Map<String, dynamic> json) => ChatMessage(
    id: json['id'] as String? ?? '${json['sentAt']}-${json['fromSelf']}',
    fromSelf: json['fromSelf'] as bool,
    sentAt: DateTime.parse(json['sentAt'] as String),
    text: json['text'] as String?,
    cipherHex: json['cipherHex'] as String?,
    fileName: json['fileName'] as String?,
    fileSize: json['fileSize'] as int?,
    filePath: json['filePath'] as String?,
  );
}

String _bytesToHex(Uint8List bytes) {
  final buffer = StringBuffer();
  for (final b in bytes) {
    buffer.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
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

  // Device IDs we sent our own handshake to via "Add Contact". Needed to
  // resolve "glare": if both sides click Add Contact for each other around
  // the same time, each independently starts its own PQXDH handshake, and
  // without this, each side's incoming handshake would silently overwrite
  // its own outgoing one — leaving both sides with different, unrelated
  // session keys that can never decrypt each other's messages. Both clients
  // apply the same deterministic tie-break (lower device ID's handshake
  // always wins) so they converge on exactly one shared session either way.
  final Set<String> _selfInitiated = {};

  final Map<String, IncomingFileTransfer> _incomingTransfers = {};
  int _packetSeq = 0;
  final Map<String, List<ChatMessage>> _messagesByContact = {};
  final _composerController = TextEditingController();
  String _connectionStatus = 'CONNECTING...';
  late String _updateManifestUrl;

  // Which message ids are currently shown decrypted (see _MessageLine):
  // every text message renders as its raw ciphertext hex by default, and
  // tapping it reveals the plaintext for 60 seconds before auto-hiding
  // again. Either side can re-reveal as many times as they want — this is
  // a local display gate, not an extra layer of encryption.
  final Set<String> _revealedMessageIds = {};
  final Map<String, Timer> _revealTimers = {};

  // Fires on an actual window-close/exit request, *before* the window and
  // engine are torn down — unlike State.dispose(), Flutter lets this one
  // delay the real exit until the returned future completes, which is
  // what makes the "burn history on close" send below actually reliable
  // instead of a fire-and-forget race against process teardown. Only
  // covers a normal close (Alt+F4, the X button, taskbar close); a forced
  // kill (Task Manager, power loss) skips this like everything else.
  AppLifecycleListener? _lifecycleListener;
  bool _exitWipeDone = false;

  // State.mounted stays true for the entire body of dispose() — it only
  // flips after dispose() returns — but the framework still forbids
  // calling setState() during that window regardless. `mounted` alone
  // isn't enough to guard _wipeContactHistory's setState call from the
  // dispose() fallback path below; this flag is.
  bool _isDisposing = false;

  String _newMessageId() => '${DateTime.now().microsecondsSinceEpoch}-${_packetSeq++}';

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
    _lifecycleListener = AppLifecycleListener(onExitRequested: _wipeAllOnExit);
  }

  /// Burns local chat history with every contact we still hold a session
  /// with, and tells each peer (over that same encrypted session) to burn
  /// theirs too — then holds real app exit open just long enough for
  /// those sends to actually leave the socket before the window and
  /// engine are destroyed. Idempotent: only runs once per screen
  /// instance, since dispose() calls this too as a fallback for exit
  /// paths that don't go through the lifecycle listener.
  Future<AppExitResponse> _wipeAllOnExit() async {
    if (_exitWipeDone) return AppExitResponse.exit;
    _exitWipeDone = true;
    // Logged but never awaited here: an `await` before the wipe loop below
    // would yield control back to the event loop, letting dispose()'s
    // later, synchronous vault.dispose() run *before* this resumes —
    // exactly the bug this comment is here to stop someone reintroducing.
    // Everything that touches the vault or a session must stay in this
    // function's synchronous prefix, not after any await.
    unawaited(AppLogger.info('exit-wipe triggered (${_contacts.length} contact(s))'));
    final hadAnySession = _contacts.any((c) => _sessions.containsKey(c.deviceId));
    for (final contact in _contacts) {
      _wipeContactHistory(contact, notifyPeer: true);
    }
    if (hadAnySession) {
      await Future.delayed(const Duration(milliseconds: 400));
    }
    return AppExitResponse.exit;
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
    try {
      final decoded = jsonDecode(utf8.decode(stored)) as List<dynamic>;
      return decoded
          .map((e) => ChatMessage.fromJson(e as Map<String, dynamic>))
          .toList();
    } catch (_) {
      return [];
    }
  }

  void _persistHistory(Contact contact) {
    final messages = _messagesByContact[contact.deviceId] ?? [];
    final encoded = jsonEncode(messages.map((m) => m.toJson()).toList());
    widget.vault.put(utf8.encode('history:${contact.deviceId}'), utf8.encode(encoded));
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
      await AppLogger.error('relay connection failed ($_relayUrl)', e);
      if (!mounted) return;
      setState(() => _connectionStatus = 'OFFLINE — RELAY UNREACHABLE');
    }
  }

  void _handleDelivery(RelayDelivery delivery) {
    if (delivery.payload.isEmpty) return;
    final tag = delivery.payload[0];
    final body = delivery.payload.sublist(1);

    if (tag == relayTagHandshake) {
      final peer = delivery.sender;
      // Glare resolution: if we already sent our own handshake to this
      // peer AND our device ID sorts lower (we're the canonical
      // initiator), keep our own session and ignore their incoming
      // handshake — they will independently reach the same conclusion in
      // reverse (their ID sorts higher, so they defer to ours) and
      // overwrite their side to match. If we didn't self-initiate, or our
      // ID sorts higher, always accept the incoming handshake as normal.
      final weSelfInitiated = _selfInitiated.contains(peer);
      final weAreCanonicalInitiator = _myDeviceId.compareTo(peer) < 0;
      if (weSelfInitiated && weAreCanonicalInitiator) {
        _relayStream?.ack(delivery.packetId);
        return;
      }
      final session = NativeCrypto.instance.respondSession(widget.identity, body);
      if (session == null) return;
      _selfInitiated.remove(peer);
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
      if (session == null) {
        AppLogger.warn('dropped message from ${delivery.sender}: no active session');
        return;
      }
      final plaintext = session.decrypt(Uint8List.fromList(body));
      if (plaintext == null) {
        AppLogger.warn('failed to decrypt message from ${delivery.sender}');
        return;
      }
      final contact = _contacts.firstWhere(
        (c) => c.deviceId == delivery.sender,
        orElse: () => Contact(deviceId: delivery.sender, label: delivery.sender),
      );
      _handleEnvelope(contact, MessageEnvelope.decode(plaintext), Uint8List.fromList(body));
    }
    _relayStream?.ack(delivery.packetId);
  }

  void _handleEnvelope(Contact contact, MessageEnvelope envelope, Uint8List ciphertext) {
    switch (envelope) {
      case TextEnvelope(:final body):
        setState(() {
          _messagesByContact
              .putIfAbsent(contact.deviceId, () => [])
              .add(
                ChatMessage(
                  id: _newMessageId(),
                  fromSelf: false,
                  text: body,
                  cipherHex: _bytesToHex(ciphertext),
                  sentAt: DateTime.now(),
                ),
              );
        });
        _persistHistory(contact);

      case FileOfferEnvelope(:final id, :final name, :final size, :final chunkCount):
        _incomingTransfers[id] = IncomingFileTransfer(
          name: name,
          size: size,
          chunkCount: chunkCount,
        );

      case FileChunkEnvelope(:final id, :final index, :final data):
        _incomingTransfers[id]?.addChunk(index, data);

      case FileDoneEnvelope(:final id):
        _finishIncomingFile(contact, id);

      case WipeEnvelope():
        _wipeContactHistory(contact, notifyPeer: false);
    }
  }

  /// Permanently clears local message history with [contact]. If
  /// [notifyPeer] is true and a session is active, also tells the peer to
  /// burn their copy (see `WipeEnvelope`) — used when this device is the
  /// one explicitly closing (see `dispose`). Contacts and sessions
  /// themselves are left intact; only the message log is destroyed.
  void _wipeContactHistory(Contact contact, {required bool notifyPeer}) {
    final session = _sessions[contact.deviceId];
    if (notifyPeer && session != null) {
      _sendEnvelope(contact, session, WipeEnvelope());
    }
    for (final message in _messagesByContact[contact.deviceId] ?? const <ChatMessage>[]) {
      _revealTimers.remove(message.id)?.cancel();
      _revealedMessageIds.remove(message.id);
      // Clearing the message list alone leaves any received file sitting
      // untouched on disk under received_files/ — not actually "no
      // traces" if a file was ever part of this conversation.
      final path = message.filePath;
      if (path != null) {
        unawaited(File(path).delete().catchError((_) => File(path)));
      }
    }
    if (mounted && !_isDisposing) {
      setState(() => _messagesByContact[contact.deviceId] = []);
    } else {
      _messagesByContact[contact.deviceId] = [];
    }
    widget.vault.put(utf8.encode('history:${contact.deviceId}'), utf8.encode('[]'));
  }

  Future<void> _finishIncomingFile(Contact contact, String transferId) async {
    final transfer = _incomingTransfers.remove(transferId);
    if (transfer == null || !transfer.isComplete) return;
    final bytes = transfer.assemble();
    final downloadsDir = await getApplicationSupportDirectory();
    final receivedDir = Directory('${downloadsDir.path}/received_files');
    await receivedDir.create(recursive: true);
    final savedPath = '${receivedDir.path}/${transfer.name}';
    await File(savedPath).writeAsBytes(bytes);
    if (!mounted) return;
    setState(() {
      _messagesByContact.putIfAbsent(contact.deviceId, () => []).add(
        ChatMessage(
          id: _newMessageId(),
          fromSelf: false,
          sentAt: DateTime.now(),
          fileName: transfer.name,
          fileSize: transfer.size,
          filePath: savedPath,
        ),
      );
    });
    _persistHistory(contact);
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
    _selfInitiated.add(result.contact.deviceId);
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

  /// Wipes a contact's session, history, and glare-tracking state and
  /// removes them from the list. Use this to recover from a stuck/broken
  /// session (e.g. both sides clicked "Add Contact" on an older build
  /// before glare resolution existed) — after removing, either side can
  /// hit "+ Add Contact" again to redo the handshake cleanly.
  Future<void> _removeContact(Contact contact) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: VaultXColors.backgroundPanel,
        title: const Text(
          'REMOVE CONTACT?',
          style: TextStyle(color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono),
        ),
        content: Text(
          'This deletes your local session and message history with '
          '"${contact.label}". They will need to be re-added to chat again.',
          style: const TextStyle(color: VaultXColors.phosphorDim, fontFamily: VaultXFonts.mono),
        ),
        actions: [
          AsciiButton(label: 'Cancel', onPressed: () => Navigator.of(context).pop(false)),
          AsciiButton(label: 'Remove', onPressed: () => Navigator.of(context).pop(true)),
        ],
      ),
    );
    if (confirmed != true) return;
    _sessions.remove(contact.deviceId)?.dispose();
    _selfInitiated.remove(contact.deviceId);
    // No delete op is exposed over the FFI bridge (put/get only) — an
    // empty history blob reads back the same as "no history" via
    // _loadHistory's empty-list decode.
    widget.vault.put(utf8.encode('history:${contact.deviceId}'), utf8.encode('[]'));
    setState(() {
      _contacts = _contacts.where((c) => c.deviceId != contact.deviceId).toList();
      _messagesByContact.remove(contact.deviceId);
      if (_selectedContact?.deviceId == contact.deviceId) {
        _selectedContact = _contacts.isNotEmpty ? _contacts.first : null;
      }
    });
    _saveContacts();
  }

  /// True only when the WebSocket to the relay is actually open. Both
  /// message and file sends must check this *before* queuing anything —
  /// `RelayStream.send` silently no-ops on a closed channel (see its own
  /// doc), so without this check a send while offline (or one that drops
  /// mid-transfer) looks identical, in the UI, to a successful one: no
  /// error, message marked sent, but the peer never receives it.
  bool get _isRelayConnected => _relayStream?.isConnected ?? false;

  Uint8List _sendEnvelope(Contact contact, NativeSession session, MessageEnvelope envelope) {
    final ciphertext = session.encrypt(envelope.encode());
    final packetId = _newMessageId();
    _relayStream?.send(
      contact.deviceId,
      packetId,
      Uint8List.fromList([relayTagMessage, ...ciphertext]),
    );
    return ciphertext;
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
    if (!_isRelayConnected) {
      setState(() => _connectionStatus = 'OFFLINE — MESSAGE NOT SENT, RECONNECTING...');
      AppLogger.warn('dropped outgoing text: relay not connected');
      return;
    }
    final ciphertext = _sendEnvelope(contact, session, TextEnvelope(text));
    setState(() {
      _messagesByContact
          .putIfAbsent(contact.deviceId, () => [])
          .add(
            ChatMessage(
              id: _newMessageId(),
              fromSelf: true,
              text: text,
              cipherHex: _bytesToHex(ciphertext),
              sentAt: DateTime.now(),
            ),
          );
      _composerController.clear();
    });
    _persistHistory(contact);
  }

  /// Sends a file of any size to the selected contact: an offer envelope
  /// (name/size/chunk count) followed by as many chunk envelopes as needed
  /// (see file_transfer.dart), each individually ratchet-encrypted and
  /// relayed as its own packet — there's no per-file size ceiling, only a
  /// per-chunk one, since the relay never sees more than one chunk at a
  /// time and never reassembles anything itself.
  Future<void> _sendFile() async {
    final contact = _selectedContact;
    if (contact == null) return;
    final session = _sessions[contact.deviceId];
    if (session == null) {
      setState(() => _connectionStatus = 'NO ACTIVE SESSION WITH THIS CONTACT');
      return;
    }
    if (!_isRelayConnected) {
      setState(() => _connectionStatus = 'OFFLINE — CANNOT SEND FILE, RECONNECTING...');
      await AppLogger.warn('dropped outgoing file: relay not connected');
      return;
    }

    FilePickerResult? result;
    try {
      result = await FilePicker.pickFiles(withData: true);
    } catch (e) {
      await AppLogger.error('file picker failed', e);
      if (!mounted) return;
      setState(() => _connectionStatus = 'FILE PICKER FAILED — SEE LOG');
      return;
    }
    if (result == null || result.files.isEmpty) return;
    final picked = result.files.first;
    if (picked.bytes == null) {
      await AppLogger.warn('picked file "${picked.name}" had no data (withData read failed)');
      if (!mounted) return;
      setState(() => _connectionStatus = 'COULD NOT READ THAT FILE — TRY AGAIN');
      return;
    }

    final bytes = picked.bytes!;
    final chunks = splitIntoChunks(bytes);
    final transferId = '${DateTime.now().microsecondsSinceEpoch}-${_packetSeq++}';

    setState(() => _connectionStatus = 'SENDING ${picked.name}...');
    _sendEnvelope(
      contact,
      session,
      FileOfferEnvelope(
        id: transferId,
        name: picked.name,
        size: bytes.length,
        chunkCount: chunks.length,
      ),
    );
    for (var i = 0; i < chunks.length; i++) {
      // Checked every chunk, not just once up front: a large file takes
      // real time to send across many packets, and the connection can
      // drop partway through — abort and say so clearly rather than
      // silently "finishing" a transfer the peer only received part of.
      if (!_isRelayConnected) {
        await AppLogger.warn(
          'relay disconnected mid-file-send: ${picked.name} (chunk $i/${chunks.length})',
        );
        if (!mounted) return;
        setState(() => _connectionStatus = 'OFFLINE — FILE SEND INTERRUPTED');
        return;
      }
      _sendEnvelope(
        contact,
        session,
        FileChunkEnvelope(id: transferId, index: i, data: chunks[i]),
      );
    }
    _sendEnvelope(contact, session, FileDoneEnvelope(transferId));
    if (!mounted) return;
    setState(() {
      _connectionStatus = 'ONLINE';
      _messagesByContact.putIfAbsent(contact.deviceId, () => []).add(
        ChatMessage(
          id: _newMessageId(),
          fromSelf: true,
          sentAt: DateTime.now(),
          fileName: picked.name,
          fileSize: bytes.length,
        ),
      );
    });
    _persistHistory(contact);
  }

  /// Toggles a message between its default ciphertext-hex view and
  /// plaintext. A reveal auto-expires after 60 seconds back to ciphertext;
  /// either side can re-reveal as many times as they like — see the
  /// `_revealedMessageIds` field doc for what this is (and isn't).
  void _toggleReveal(String messageId) {
    _revealTimers.remove(messageId)?.cancel();
    if (_revealedMessageIds.contains(messageId)) {
      setState(() => _revealedMessageIds.remove(messageId));
      return;
    }
    setState(() => _revealedMessageIds.add(messageId));
    _revealTimers[messageId] = Timer(const Duration(seconds: 60), () {
      _revealTimers.remove(messageId);
      if (mounted) setState(() => _revealedMessageIds.remove(messageId));
    });
  }

  Future<void> _copyMyId() async {
    await Clipboard.setData(ClipboardData(text: _myDeviceId));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Device ID copied to clipboard')),
    );
  }

  /// Reveals the local log file (see services/app_logger.dart) in the
  /// system file manager, so a user hitting a problem can find and send it
  /// along for troubleshooting without needing to know where app data
  /// lives on their platform.
  Future<void> _openLog() async {
    final path = AppLogger.path;
    if (path == null) return;
    if (Platform.isWindows) {
      await Process.run('explorer', ['/select,', path]);
    } else if (Platform.isMacOS) {
      await Process.run('open', ['-R', path]);
    } else {
      await Process.run('xdg-open', [File(path).parent.path]);
    }
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
    await AppLogger.info('update check started ($manifestUrl)');
    UpdateInfo? update;
    try {
      // UpdateChecker.checkForUpdate already times out its own HTTP fetch
      // and swallows network/parse errors, but the PackageInfo lookup after
      // it isn't covered by that inner timeout — this outer one is a hard
      // backstop so the "Checking for updates..." snackbar can never hang
      // indefinitely no matter what fails underneath.
      update = await UpdateChecker.checkForUpdate(manifestUrl).timeout(const Duration(seconds: 15));
    } on TimeoutException {
      await AppLogger.warn('update check timed out ($manifestUrl)');
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Update check timed out — try again later.')),
      );
      return;
    }
    if (update == null) {
      await AppLogger.info('update check: already on the latest version');
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text("You're on the latest version.")),
      );
      return;
    }
    final resolvedUpdate = update;
    await AppLogger.info('update check: v${resolvedUpdate.version} available');
    if (!mounted) return;

    final canAutoInstall = UpdateChecker.canAutoInstall;
    final shouldUpdate = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: VaultXColors.backgroundPanel,
        title: Text(
          'UPDATE AVAILABLE: v${resolvedUpdate.version}',
          style: const TextStyle(color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono),
        ),
        content: Text(
          resolvedUpdate.notes ?? 'A newer version of Vault X is available.',
          style: const TextStyle(color: VaultXColors.phosphorDim, fontFamily: VaultXFonts.mono),
        ),
        actions: [
          AsciiButton(label: 'Later', onPressed: () => Navigator.of(context).pop(false)),
          AsciiButton(
            label: canAutoInstall ? 'Update Now' : 'Open Download Page',
            onPressed: () => Navigator.of(context).pop(true),
          ),
        ],
      ),
    );
    if (shouldUpdate != true) return;

    if (!canAutoInstall) {
      // macOS/Linux: no safe way to self-replace a running .app bundle or
      // extracted tarball without a real updater framework — hand the user
      // the download instead of pretending to install it for them.
      await UpdateChecker.openInBrowser(resolvedUpdate.installerUrl);
      return;
    }

    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Downloading update...')),
    );
    try {
      await UpdateChecker.downloadAndLaunchInstaller(resolvedUpdate.installerUrl);
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
    _isDisposing = true;
    // Fallback only — _wipeAllOnExit is guarded by _exitWipeDone, so this
    // is a no-op on the normal path (already ran, and got to actually
    // delay exit for the sends to flush, via the lifecycle listener
    // above). Still calling it here covers screen teardown that isn't a
    // real app exit at all (e.g. hot reload/navigation in dev), where
    // skipping it would leave history sitting un-burned.
    unawaited(_wipeAllOnExit());
    _lifecycleListener?.dispose();
    for (final timer in _revealTimers.values) {
      timer.cancel();
    }
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
                expandContent: true,
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
                                onRemove: () => _removeContact(contact),
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
                expandContent: true,
                child: Column(
                  children: [
                    Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                      // Wrap rather than Row: two badges plus three buttons
                      // need ~1150px to fit on one line, wider than this
                      // panel gets once the window is resized down or the
                      // sidebar is open — Row would silently overflow off
                      // the right edge (only visible as a debug-mode
                      // warning stripe, never a crash, so easy to miss).
                      // Wrap instead lets buttons flow onto a second line.
                      child: Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        crossAxisAlignment: WrapCrossAlignment.center,
                        children: [
                          const CipherBadge(label: 'ENC: CHACHA20-POLY1305'),
                          const CipherBadge(label: 'POST-QUANTUM: ENABLED'),
                          AsciiButton(label: 'My ID', onPressed: _copyMyId),
                          AsciiButton(label: 'Updates', onPressed: _checkForUpdates),
                          AsciiButton(label: 'View Log', onPressed: _openLog),
                        ],
                      ),
                    ),
                    const Divider(height: 1, color: VaultXColors.border),
                    Expanded(
                      child: _selectedContact == null
                          ? _NoContactSelectedHint(onStartChat: _openAddContact)
                          : ListView(
                              padding: const EdgeInsets.all(14),
                              children: [
                                for (final message
                                    in _messagesByContact[_selectedContact!.deviceId] ?? [])
                                  _MessageLine(
                                    message: message,
                                    revealed: _revealedMessageIds.contains(message.id),
                                    onToggleReveal: () => _toggleReveal(message.id),
                                  ),
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
                            label: 'Attach',
                            onPressed: _selectedContact == null ? null : _sendFile,
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
  const _NoContactSelectedHint({required this.onStartChat});

  final VoidCallback onStartChat;

  @override
  Widget build(BuildContext context) {
    // Scrollable rather than a bare Center: on a short window this
    // multi-line hint plus the button can be taller than the available
    // space (only visible in debug mode as an overflow warning stripe,
    // since Flutter strips this specific layout assertion from release
    // builds — silently invisible there rather than actually fixed).
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text(
              '>> ADD A CONTACT TO START YOUR FIRST SECURE\n'
              '   CONVERSATION. SHARE YOUR DEVICE ID (TAP\n'
              '   "MY ID" ABOVE) WITH A FRIEND, THEN USE\n'
              '   "START CHAT" BELOW WITH THEIRS.\n\n'
              '   ONLY ONE OF YOU SHOULD ADD THE OTHER —\n'
              '   IF YOU BOTH DO IT AT THE SAME TIME, REMOVE\n'
              '   THE CONTACT ([x] IN THE LIST) AND RETRY.',
              textAlign: TextAlign.center,
              style: TextStyle(
                color: VaultXColors.phosphorDim,
                fontFamily: VaultXFonts.mono,
                fontSize: 13,
              ),
            ),
            const SizedBox(height: 20),
            AsciiButton(label: 'Start Chat', onPressed: onStartChat),
          ],
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
    required this.onRemove,
  });

  final Contact contact;
  final bool selected;
  final bool online;
  final VoidCallback onTap;
  final VoidCallback onRemove;

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
            const SizedBox(width: 8),
            GestureDetector(
              onTap: onRemove,
              child: const Text(
                '[x]',
                style: TextStyle(
                  color: VaultXColors.alertRed,
                  fontFamily: VaultXFonts.mono,
                  fontSize: 12,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _MessageLine extends StatelessWidget {
  const _MessageLine({
    required this.message,
    required this.revealed,
    required this.onToggleReveal,
  });

  final ChatMessage message;
  final bool revealed;
  final VoidCallback onToggleReveal;

  static String _formatSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }

  Future<void> _openFile() async {
    final path = message.filePath;
    if (path == null) return;
    if (Platform.isWindows) {
      await Process.run('explorer', ['/select,', path]);
    } else if (Platform.isMacOS) {
      await Process.run('open', ['-R', path]);
    } else {
      await Process.run('xdg-open', [File(path).parent.path]);
    }
  }

  @override
  Widget build(BuildContext context) {
    final prefix = message.fromSelf ? 'you' : 'peer';
    final color = message.fromSelf ? VaultXColors.phosphor : VaultXColors.phosphorDim;
    final time = message.sentAt.toIso8601String().substring(11, 19);

    final bodySpan = message.isFile
        ? TextSpan(
            text:
                '📎 ${message.fileName} (${_formatSize(message.fileSize ?? 0)})'
                '${message.filePath != null ? ' — click to reveal' : ''}',
            style: TextStyle(
              color: VaultXColors.phosphor,
              decoration: message.filePath != null ? TextDecoration.underline : null,
            ),
            recognizer: message.filePath != null
                ? (TapGestureRecognizer()..onTap = _openFile)
                : null,
          )
        : (revealed || message.cipherHex == null)
              ? TextSpan(
                  text: '${message.text}${message.cipherHex != null ? '  [tap to hide]' : ''}',
                  style: const TextStyle(color: VaultXColors.phosphor),
                  recognizer: message.cipherHex != null
                      ? (TapGestureRecognizer()..onTap = onToggleReveal)
                      : null,
                )
              : TextSpan(
                  text: '🔒 ${message.cipherHex}',
                  style: const TextStyle(
                    color: VaultXColors.phosphorDim,
                    fontStyle: FontStyle.italic,
                  ),
                  recognizer: TapGestureRecognizer()..onTap = onToggleReveal,
                );

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
            bodySpan,
          ],
        ),
      ),
    );
  }
}
