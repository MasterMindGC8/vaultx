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

import 'package:cross_file/cross_file.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';

import '../bridge/native_crypto.dart';
import '../models/contact.dart';
import '../services/app_logger.dart';
import '../services/file_transfer.dart';
import '../services/file_sender.dart';
import '../services/transfer_progress.dart';
import '../widgets/transfer_status.dart';
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
    this.delivery = 'unconfirmed',
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
  final String delivery;

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
        'delivery': delivery,
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
        delivery: json['delivery'] as String? ?? 'unconfirmed',
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
  Timer? _reconnectTimer;
  Timer? _healthTimer;
  bool _connecting = false;
  bool _measuring = false;
  int _retryCount = 0;
  int? _relayLatencyMs;
  bool _keepHistory = false;
  bool _sendingText = false;
  final Map<String, DateTime> _peerSeen = {};
  final Set<String> _presenceCapable = {};
  final Map<String, Contact> _pendingTexts = {};
  final Map<String, String> _packetMessageIds = {};

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
  final Map<String, FileSender> _outgoingTransfers = {};
  bool _startingUpload = false;
  final Map<String, TransferProgress> _transferProgress = {};
  final Map<String, Timer> _transferExpiry = {};
  final Set<String> _processedPackets = {};
  final Set<String> _seenHandshakes = {};
  Future<void> _deliveryChain = Future<void>.value();
  String _transferKey(Contact contact, String id) => '${contact.deviceId}:$id';

  void _queueDelivery(RelayDelivery delivery) {
    _deliveryChain = _deliveryChain.then((_) async {
      if (!mounted || _isDisposing || _exitWipeDone) return;
      try {
        await _handleDelivery(delivery);
      } catch (error) {
        unawaited(AppLogger.warn(
            'Incoming packet could not be processed (${error.runtimeType})'));
        if (mounted && !_isDisposing) {
          setState(() =>
              _connectionStatus = 'INCOMING DATA REJECTED — RETRY TRANSFER');
        }
      }
    });
  }

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

  // True while a drag-and-drop file is hovering over the conversation
  // panel — purely a visual cue (see the overlay in build()); the actual
  // drop is handled by _sendDroppedFiles.
  bool _isDragHovering = false;

  String _newMessageId() =>
      '${DateTime.now().microsecondsSinceEpoch}-${_packetSeq++}';

  @override
  void initState() {
    super.initState();
    _myDeviceId = widget.identity.deviceIdHex();
    _relayUrl = _loadRelayUrl();
    _relayHttp = RelayHttp(baseUrl: _relayUrl);
    _updateManifestUrl = _loadUpdateManifestUrl();
    _contacts = _loadContacts();
    final seen = widget.vault.get(utf8.encode('seen_handshakes_v1'));
    if (seen != null) {
      try {
        _seenHandshakes
            .addAll((jsonDecode(utf8.decode(seen)) as List).cast<String>());
      } catch (_) {
        /* A missing cache cannot prevent opening a vault. */
      } finally {
        seen.fillRange(0, seen.length, 0);
      }
    }
    _keepHistory =
        widget.vault.get(utf8.encode('keep_history_v1'))?.firstOrNull == 1;
    for (final contact in _contacts) {
      _messagesByContact[contact.deviceId] = _loadHistory(contact);
    }
    _selectedContact = _contacts.isNotEmpty ? _contacts.first : null;
    _connectToRelay();
    _lifecycleListener = AppLifecycleListener(onExitRequested: _wipeAllOnExit);
  }

  /// History OFF clears this device's chat on exit. Each person controls
  /// their own history setting; closing this window does not erase theirs.
  /// dispose() also calls this for exits without a lifecycle notification.
  Future<AppExitResponse> _wipeAllOnExit() async {
    if (_exitWipeDone || _keepHistory) return AppExitResponse.exit;
    _exitWipeDone = true;
    // Logged but never awaited here: an `await` before the wipe loop below
    // would yield control back to the event loop, letting dispose()'s
    // later, synchronous vault.dispose() run *before* this resumes —
    // exactly the bug this comment is here to stop someone reintroducing.
    // Everything that touches the vault or a session must stay in this
    // function's synchronous prefix, not after any await.
    unawaited(
        AppLogger.info('exit-wipe triggered (${_contacts.length} contact(s))'));
    for (final contact in _contacts) {
      _wipeContactHistory(contact, notifyPeer: false);
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
    widget.vault
        .put(utf8.encode(Contact.vaultKey), Contact.encodeList(_contacts));
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
    } finally {
      stored.fillRange(0, stored.length, 0);
    }
  }

  void _persistHistory(Contact contact) {
    final messages = _keepHistory
        ? (_messagesByContact[contact.deviceId] ?? [])
        : <ChatMessage>[];
    final encoded = jsonEncode(messages.map((m) => m.toJson()).toList());
    final bytes = utf8.encode(encoded);
    try {
      if (!widget.vault
          .put(utf8.encode('history:${contact.deviceId}'), bytes)) {
        throw StateError('Could not save history');
      }
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }
  }

  Future<void> _connectToRelay() async {
    if (_connecting || _isDisposing || !mounted) return;
    _connecting = true;
    _reconnectTimer?.cancel();
    _healthTimer?.cancel();
    final old = _relayStream;
    _relayStream = null;
    await old?.close();
    if (!mounted || _isDisposing) {
      _connecting = false;
      return;
    }
    setState(() => _connectionStatus = 'CONNECTING...');
    try {
      final bundle = widget.identity.publicBundleBytes();
      final published =
          await _relayHttp.publishPreKeyBundle(_myDeviceId, bundle);
      if (!mounted || _isDisposing) return;
      if (!published) throw StateError('Relay rejected the public key bundle');
      final stream = RelayStream(baseUrl: _relayUrl, deviceId: _myDeviceId);
      stream.deliveries.listen(_queueDelivery);
      stream.acceptedPackets
          .listen((id) => _updateDelivery(_packetMessageIds[id] ?? id, 'sent'));
      stream.rejectedPackets.listen(
          (id) => _updateDelivery(_packetMessageIds[id] ?? id, 'failed'));
      stream.connectionChanges.listen((connected) {
        if (mounted && !_isDisposing && _relayStream == stream && !connected) {
          setState(() => _connectionStatus = 'OFFLINE — CONNECTION LOST');
          _scheduleReconnect();
        }
      });
      _relayStream = stream;
      await stream.connect();
      if (!mounted || _isDisposing) {
        await stream.close();
        return;
      }
      _relayStream = stream;
      if (!mounted) return;
      setState(() => _connectionStatus = 'ONLINE');
      _retryCount = 0;
      unawaited(_restoreChatSessions());
      unawaited(_checkRelayHealth());
      _healthTimer = Timer.periodic(const Duration(seconds: 15), (_) {
        unawaited(_checkRelayHealth());
        _checkPresence();
      });
    } catch (e) {
      await AppLogger.error('relay connection failed ($_relayUrl)', e);
      if (!mounted) return;
      setState(() => _connectionStatus = 'OFFLINE — RELAY UNREACHABLE');
      _scheduleReconnect();
    } finally {
      _connecting = false;
    }
  }

  void _scheduleReconnect() {
    if (_isDisposing || !mounted || _reconnectTimer?.isActive == true) return;
    final seconds = [2, 5, 10, 30][_retryCount.clamp(0, 3)];
    _retryCount++;
    _reconnectTimer = Timer(Duration(seconds: seconds), _connectToRelay);
  }

  Future<void> _restoreChatSessions() async {
    // Ratchet keys live in memory. Announce fresh sessions after this app
    // reopens, even when the other person has kept their window open.
    for (final contact in List<Contact>.of(_contacts)) {
      if (!mounted || _isDisposing || !_isRelayConnected) return;
      try {
        await _ensureSession(contact);
      } catch (_) {
        // Sending can retry the lookup; a missing peer must not stop others.
        unawaited(AppLogger.warn('A saved chat could not reconnect yet'));
      }
    }
  }

  Future<void> _checkRelayHealth() async {
    if (_measuring || _isDisposing) return;
    _measuring = true;
    final http = _relayHttp;
    try {
      final elapsed = await http.measureLatency();
      if (mounted && !_isDisposing && http == _relayHttp) {
        setState(() => _relayLatencyMs = elapsed.inMilliseconds);
      }
    } catch (_) {
      if (mounted && !_isDisposing) setState(() => _relayLatencyMs = null);
    } finally {
      _measuring = false;
    }
  }

  void _checkPresence() {
    if (!_isRelayConnected || _isDisposing) return;
    for (final contact in _contacts) {
      final session = _sessions[contact.deviceId];
      if (session != null && _presenceCapable.contains(contact.deviceId)) {
        try {
          _sendEnvelope(contact, session, PresenceEnvelope(reply: false),
              messageId: 'vx2-presence-${_newMessageId()}');
        } catch (_) {/* next heartbeat retries */}
      }
    }
    if (mounted) setState(() {});
  }

  bool? _peerOnline(String id) {
    if (!_isRelayConnected) return false;
    final seen = _peerSeen[id];
    if (seen == null) return null;
    if (DateTime.now().difference(seen) < const Duration(seconds: 45)) {
      return true;
    }
    return _presenceCapable.contains(id) ? false : null;
  }

  void _rememberHandshake(String packetKey) {
    _seenHandshakes.add(packetKey);
    if (_seenHandshakes.length > 512) {
      _seenHandshakes.remove(_seenHandshakes.first);
    }
    final bytes = utf8.encode(jsonEncode(_seenHandshakes.toList()));
    try {
      if (!widget.vault.put(utf8.encode('seen_handshakes_v1'), bytes)) {
        _seenHandshakes.remove(packetKey);
        throw StateError('Could not save handshake replay protection');
      }
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }
  }

  void _updateDelivery(String id, String status, {Contact? from}) {
    if (!mounted || _isDisposing) return;
    final contact = _pendingTexts[id];
    if (contact == null ||
        (from != null && from.deviceId != contact.deviceId)) {
      return;
    }
    final messages = _messagesByContact[contact.deviceId];
    final i = messages?.indexWhere((m) => m.id == id && m.fromSelf) ?? -1;
    if (i < 0) return;
    if (messages![i].delivery == 'received') return;
    setState(() => messages[i] =
        ChatMessage.fromJson({...messages[i].toJson(), 'delivery': status}));
    if (status == 'received' || status == 'failed') _pendingTexts.remove(id);
    try {
      _persistHistory(contact);
    } catch (_) {
      setState(() => _connectionStatus = 'HISTORY COULD NOT BE SAVED');
    }
  }

  void _toggleHistory() {
    final next = !_keepHistory;
    if (!widget.vault.put(
        utf8.encode('keep_history_v1'), Uint8List.fromList([next ? 1 : 0]))) {
      setState(() => _connectionStatus = 'HISTORY SETTING COULD NOT BE SAVED');
      return;
    }
    setState(() => _keepHistory = next);
    try {
      for (final contact in _contacts) {
        _persistHistory(contact);
      }
    } catch (_) {
      setState(() => _connectionStatus = 'HISTORY UPDATE FAILED');
    }
  }

  Future<void> _handleDelivery(RelayDelivery delivery) async {
    if (delivery.payload.isEmpty) return;
    final packetKey = '${delivery.sender}:${delivery.packetId}';
    if (_processedPackets.contains(packetKey)) {
      _relayStream?.ack(delivery.packetId);
      return;
    }
    final tag = delivery.payload[0];
    final body = delivery.payload.sublist(1);
    if (tag == relayTagHandshake && _seenHandshakes.contains(packetKey)) {
      _relayStream?.ack(delivery.packetId);
      return;
    }

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
        _rememberHandshake(packetKey);
        _relayStream?.ack(delivery.packetId);
        return;
      }
      final session =
          NativeCrypto.instance.respondSession(widget.identity, body);
      if (session == null) return;
      _selfInitiated.remove(peer);
      _sessions.remove(delivery.sender)?.dispose();
      _sessions[delivery.sender] = session;
      if (!_contacts.any((c) => c.deviceId == delivery.sender)) {
        final newContact = Contact(
          deviceId: delivery.sender,
          label:
              '0x${delivery.sender.substring(0, delivery.sender.length.clamp(0, 8)).toUpperCase()}',
        );
        setState(() {
          _contacts = [..._contacts, newContact];
          _messagesByContact[newContact.deviceId] = [];
          _selectedContact ??= newContact;
        });
        _saveContacts();
      }
      if (delivery.packetId.startsWith('vx2-')) {
        _presenceCapable.add(peer);
      }
      if (mounted) setState(() {});
    } else if (tag == relayTagMessage) {
      final session = _sessions[delivery.sender];
      if (session == null) {
        AppLogger.warn(
            'dropped message from ${delivery.sender}: no active session');
        return;
      }
      final plaintext = session.decrypt(Uint8List.fromList(body));
      if (plaintext == null) {
        if (delivery.packetId.startsWith('vx2-presence-')) {
          _relayStream?.ack(delivery.packetId);
          return;
        }
        AppLogger.warn('failed to decrypt message from ${delivery.sender}');
        // Replaying this rejected ciphertext cannot restore lost session
        // keys. Drop the transport copy; only an encrypted text receipt
        // counts as received, and the sender can retry with fresh keys.
        _relayStream?.ack(delivery.packetId);
        setState(() => _connectionStatus =
            'MESSAGE COULD NOT BE OPENED — ASK SENDER TO RETRY');
        return;
      }
      if (_connectionStatus ==
          'MESSAGE COULD NOT BE OPENED — ASK SENDER TO RETRY') {
        setState(() => _connectionStatus = 'ONLINE');
      }
      _selfInitiated.remove(delivery.sender);
      _peerSeen[delivery.sender] = DateTime.now();
      final contact = _contacts.firstWhere(
        (c) => c.deviceId == delivery.sender,
        orElse: () =>
            Contact(deviceId: delivery.sender, label: delivery.sender),
      );
      MessageEnvelope? envelope;
      try {
        envelope = MessageEnvelope.decode(plaintext);
        await _handleEnvelope(contact, envelope, Uint8List.fromList(body));
      } finally {
        plaintext.fillRange(0, plaintext.length, 0);
        if (envelope is FileChunkEnvelope) {
          envelope.data.fillRange(0, envelope.data.length, 0);
        }
      }
    }
    if (tag == relayTagHandshake) _rememberHandshake(packetKey);
    _processedPackets.add(packetKey);
    if (_processedPackets.length > 2048) {
      _processedPackets.remove(_processedPackets.first);
    }
    _relayStream?.ack(delivery.packetId);
  }

  Future<void> _handleEnvelope(
      Contact contact, MessageEnvelope envelope, Uint8List ciphertext) async {
    switch (envelope) {
      case TextEnvelope(:final body, :final id):
        if (id != null && (id.isEmpty || id.length > 128)) {
          throw const FormatException('Invalid text ID');
        }
        final duplicate = id != null &&
            (_messagesByContact[contact.deviceId] ?? [])
                .any((m) => !m.fromSelf && m.id == id);
        if (!duplicate) {
          setState(() {
            _messagesByContact.putIfAbsent(contact.deviceId, () => []).add(
                  ChatMessage(
                    id: id ?? _newMessageId(),
                    fromSelf: false,
                    text: body,
                    cipherHex: _bytesToHex(ciphertext),
                    sentAt: DateTime.now(),
                  ),
                );
          });
          _persistHistory(contact);
        }
        if (id != null) {
          _presenceCapable.add(contact.deviceId);
          _sendEnvelope(
              contact, _sessions[contact.deviceId]!, TextReceiptEnvelope(id));
        }

      case TextReceiptEnvelope(:final id):
        _presenceCapable.add(contact.deviceId);
        _updateDelivery(id, 'received', from: contact);

      case PresenceEnvelope(:final reply):
        _presenceCapable.add(contact.deviceId);
        if (!reply) {
          _sendEnvelope(contact, _sessions[contact.deviceId]!,
              PresenceEnvelope(reply: true));
        }
        setState(() {});

      case FileOfferEnvelope(
          :final id,
          :final name,
          :final size,
          :final chunkCount,
          :final receipts
        ):
        final key = _transferKey(contact, id);
        if (id.isEmpty ||
            id.length > 128 ||
            _incomingTransfers.containsKey(key)) {
          throw const FormatException('Invalid or repeated file offer');
        }
        try {
          if (_incomingTransfers.length >= 2) {
            throw const FormatException('Too many incoming files');
          }
          final transfer = IncomingFileTransfer(
              name: name, size: size, chunkCount: chunkCount)
            ..receipts = receipts;
          _incomingTransfers[key] = transfer;
          final progress =
              TransferProgress(name: name, totalBytes: size, uploading: false)
                ..phase = TransferPhase.transferring;
          _showTransfer(key, progress);
          _armTransferExpiry(contact, id);
          _sendFileReceipt(contact, id, transfer, 'ready');
        } catch (_) {
          if (receipts) {
            _sendReceipt(contact,
                FileReceiptEnvelope(id: id, bytes: 0, stage: 'failed'));
          }
          rethrow;
        }

      case FileChunkEnvelope(:final id, :final index, :final data):
        final key = _transferKey(contact, id);
        final transfer = _incomingTransfers[key];
        if (transfer == null) {
          throw const FormatException('File offer missing or expired');
        }
        try {
          transfer.addChunk(index, data);
          _transferProgress[key]?.updateBytes(transfer.receivedBytes);
          _armTransferExpiry(contact, id);
          _sendFileReceipt(contact, id, transfer, 'received');
          if (transfer.doneReceived && transfer.isComplete) {
            await _finishIncomingFile(contact, id);
          }
        } catch (_) {
          _cancelIncoming(contact, id, failed: true);
          rethrow;
        }

      case FileDoneEnvelope(:final id):
        final transfer = _incomingTransfers[_transferKey(contact, id)];
        if (transfer == null) return;
        transfer.doneReceived = true;
        if (transfer.isComplete) await _finishIncomingFile(contact, id);

      case FileReceiptEnvelope(:final id):
        _outgoingTransfers[_transferKey(contact, id)]?.acceptReceipt(envelope);

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
    final prefix = '${contact.deviceId}:';
    for (final key in _incomingTransfers.keys
        .where((k) => k.startsWith(prefix))
        .toList()) {
      _cancelIncoming(contact, key.substring(prefix.length));
    }
    for (final entry in _outgoingTransfers.entries
        .where((e) => e.key.startsWith(prefix))
        .toList()) {
      entry.value.cancel();
    }
    _transferProgress.removeWhere((key, _) => key.startsWith(prefix));
    final session = _sessions[contact.deviceId];
    if (notifyPeer && session != null && _isRelayConnected) {
      try {
        _sendEnvelope(contact, session, WipeEnvelope());
      } catch (_) {
        // A disconnected peer must not prevent the local wipe.
        AppLogger.warn('peer wipe notification could not be sent');
      }
    }
    for (final message
        in _messagesByContact[contact.deviceId] ?? const <ChatMessage>[]) {
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
    widget.vault
        .put(utf8.encode('history:${contact.deviceId}'), utf8.encode('[]'));
  }

  Future<void> _finishIncomingFile(Contact contact, String transferId) async {
    final key = _transferKey(contact, transferId);
    final transfer = _incomingTransfers[key];
    if (transfer == null || !transfer.isComplete || transfer.saving) return;
    transfer.saving = true;
    _transferExpiry.remove(key)?.cancel();
    _transferProgress[key]?.phase = TransferPhase.saving;
    Directory? uniqueDir;
    String? savedPath;
    RandomAccessFile? output;
    try {
      final downloadsDir = await getApplicationSupportDirectory();
      final receivedDir = Directory('${downloadsDir.path}/received_files');
      await receivedDir.create(recursive: true);
      // Each transfer owns a generated directory; repeated names cannot
      // overwrite other files. The peer never controls any directory segment.
      uniqueDir = await receivedDir.createTemp('transfer-');
      savedPath = '${uniqueDir.path}/${transfer.name}';
      if (!mounted || transfer.cancelled || _exitWipeDone) return;
      output = await File(savedPath).open(mode: FileMode.write);
      for (final chunk in transfer.orderedChunks) {
        if (!mounted || transfer.cancelled || _exitWipeDone) return;
        await output.writeFrom(chunk);
      }
      await output.flush();
      await output.close();
      output = null;
      if (!mounted || transfer.cancelled || _exitWipeDone) return;
      setState(() {
        _messagesByContact.putIfAbsent(contact.deviceId, () => []).add(
              ChatMessage(
                id: _newMessageId(),
                fromSelf: false,
                sentAt: DateTime.now(),
                fileName: transfer.name,
                fileSize: transfer.size,
                filePath: savedPath!,
              ),
            );
      });
      _persistHistory(contact);
      _sendFileReceipt(contact, transferId, transfer, 'saved');
      _transferProgress[key]?.phase = TransferPhase.complete;
      uniqueDir = null; // Retain only a fully saved, tracked attachment.
    } catch (_) {
      _transferProgress[key]?.phase = TransferPhase.failed;
      _sendFileReceipt(contact, transferId, transfer, 'failed');
      _messagesByContact[contact.deviceId]
          ?.removeWhere((message) => message.filePath == savedPath);
    } finally {
      try {
        await output?.close();
      } catch (_) {/* Continue cleanup after an I/O failure. */}
      if (uniqueDir != null) {
        try {
          await uniqueDir.delete(recursive: true);
        } catch (_) {/* Best effort cleanup of this transfer only. */}
      }
      _incomingTransfers.remove(key);
      transfer.clear();
    }
  }

  void _showTransfer(String key, TransferProgress progress) {
    // Keep a small list of recent results; do not retain every progress object.
    final inactive =
        _transferProgress.entries.where((e) => !e.value.active).toList();
    for (final entry
        in inactive.take((inactive.length - 3).clamp(0, inactive.length))) {
      _transferProgress.remove(entry.key);
      _outgoingTransfers.remove(entry.key);
    }
    setState(() => _transferProgress[key] = progress);
  }

  void _sendReceipt(Contact contact, FileReceiptEnvelope receipt) {
    final session = _sessions[contact.deviceId];
    if (session == null || !_isRelayConnected || _isDisposing) return;
    try {
      _sendEnvelope(contact, session, receipt);
    } catch (_) {/* Sender times out honestly. */}
  }

  void _sendFileReceipt(
      Contact contact, String id, IncomingFileTransfer transfer, String stage) {
    if (transfer.receipts) {
      _sendReceipt(
          contact,
          FileReceiptEnvelope(
              id: id, bytes: transfer.receivedBytes, stage: stage));
    }
  }

  void _armTransferExpiry(Contact contact, String id) {
    final key = _transferKey(contact, id);
    _transferExpiry.remove(key)?.cancel();
    _transferExpiry[key] = Timer(const Duration(minutes: 2),
        () => _cancelIncoming(contact, id, failed: true));
  }

  void _cancelIncoming(Contact contact, String id, {bool failed = false}) {
    final key = _transferKey(contact, id);
    _transferExpiry.remove(key)?.cancel();
    final transfer = _incomingTransfers.remove(key);
    if (transfer != null) {
      _sendFileReceipt(contact, id, transfer, 'failed');
      // An asynchronous disk write may still own this buffer. Its finally
      // block clears it after the write closes; cancellation prevents publish.
      if (transfer.saving) {
        transfer.cancelled = true;
      } else {
        transfer.clear();
      }
    }
    _transferProgress[key]?.phase =
        failed ? TransferPhase.failed : TransferPhase.cancelled;
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
    if (!mounted || _isDisposing) {
      result.session.dispose();
      return;
    }
    final peer = result.contact.deviceId;
    // A handshake may already have arrived while Add Contact was open.
    // Keep that shared session instead of replacing it with unrelated keys.
    final alreadyConnected = _sessions.containsKey(peer);
    if (alreadyConnected) {
      result.session.dispose();
    } else {
      try {
        if (!_isRelayConnected) throw StateError('Relay disconnected');
        _relayStream!.send(
            peer,
            'vx2-${result.handshakePacketId}',
            Uint8List.fromList(
                [relayTagHandshake, ...result.handshakePayload]));
      } catch (_) {
        result.session.dispose();
        setState(() =>
            _connectionStatus = 'CONTACT NOT ADDED — RELAY OFFLINE; RETRY');
        return;
      }
      _sessions[peer] = result.session;
      _selfInitiated.add(peer);
      _sendEnvelope(
          result.contact, result.session, PresenceEnvelope(reply: false),
          messageId: 'vx2-presence-${_newMessageId()}');
    }
    setState(() {
      _contacts = [
        ..._contacts.where((c) => c.deviceId != peer),
        result.contact
      ];
      _messagesByContact.putIfAbsent(peer, () => []);
      _selectedContact = result.contact;
    });
    _saveContacts();
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
          style: TextStyle(
              color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono),
        ),
        content: Text(
          'This deletes your local session and message history with '
          '"${contact.label}". They will need to be re-added to chat again.',
          style: const TextStyle(
              color: VaultXColors.phosphorDim, fontFamily: VaultXFonts.mono),
        ),
        actions: [
          AsciiButton(
              label: 'Cancel',
              onPressed: () => Navigator.of(context).pop(false)),
          AsciiButton(
              label: 'Remove',
              onPressed: () => Navigator.of(context).pop(true)),
        ],
      ),
    );
    if (confirmed != true) return;
    _wipeContactHistory(contact, notifyPeer: false);
    _sessions.remove(contact.deviceId)?.dispose();
    _selfInitiated.remove(contact.deviceId);
    setState(() {
      _contacts =
          _contacts.where((c) => c.deviceId != contact.deviceId).toList();
      _messagesByContact.remove(contact.deviceId);
      if (_selectedContact?.deviceId == contact.deviceId) {
        _selectedContact = _contacts.isNotEmpty ? _contacts.first : null;
      }
    });
    _saveContacts();
  }

  /// True only when the WebSocket to the relay is actually open. Both
  /// message and file sends check this before encrypting/queuing anything.
  /// RelayStream also rejects writes after a disconnect.
  bool get _isRelayConnected => _relayStream?.isConnected ?? false;

  Uint8List _sendEnvelope(
      Contact contact, NativeSession session, MessageEnvelope envelope,
      {String? messageId}) {
    if (!_isRelayConnected) throw StateError('Relay disconnected');
    final plaintext = envelope.encode();
    late Uint8List ciphertext;
    try {
      ciphertext = session.encrypt(plaintext);
    } finally {
      plaintext.fillRange(0, plaintext.length, 0);
    }
    if (ciphertext.isEmpty) throw StateError('Encryption failed');
    final packetId = messageId ?? _newMessageId();
    _relayStream?.send(
      contact.deviceId,
      packetId,
      Uint8List.fromList([relayTagMessage, ...ciphertext]),
    );
    return ciphertext;
  }

  Future<NativeSession> _ensureSession(Contact contact) async {
    final existing = _sessions[contact.deviceId];
    if (existing != null) return existing;
    final bundle = await _relayHttp.fetchPreKeyBundle(contact.deviceId);
    if (!mounted || _isDisposing || !_isRelayConnected || bundle == null) {
      throw StateError('Peer is not available');
    }
    // The peer may have initiated while the HTTP lookup was in flight.
    final incoming = _sessions[contact.deviceId];
    if (incoming != null) return incoming;
    final outcome =
        NativeCrypto.instance.initiateSession(widget.identity, bundle);
    if (outcome == null) throw StateError('Handshake failed');
    try {
      _relayStream!.send(
          contact.deviceId,
          'vx2-${_newMessageId()}',
          Uint8List.fromList(
              [relayTagHandshake, ...outcome.initialMessageBytes]));
    } catch (_) {
      outcome.session.dispose();
      rethrow;
    }
    _sessions[contact.deviceId] = outcome.session;
    _selfInitiated.add(contact.deviceId);
    _sendEnvelope(contact, outcome.session, PresenceEnvelope(reply: false),
        messageId: 'vx2-presence-${_newMessageId()}');
    return outcome.session;
  }

  Future<void> _sendMessage({ChatMessage? retry, Contact? retryContact}) async {
    final text = retry?.text ?? _composerController.text.trim();
    final contact = retryContact ?? _selectedContact;
    if (text.isEmpty || contact == null || _sendingText) return;
    if (retry != null &&
        (_messagesByContact[contact.deviceId] ?? [])
            .any((m) => m.id == retry.id && m.delivery == 'received')) {
      return;
    }
    _sendingText = true;
    final id = retry?.id ?? _newMessageId();
    setState(() {
      if (retry == null) {
        _messagesByContact.putIfAbsent(contact.deviceId, () => []).add(
            ChatMessage(
                id: id,
                fromSelf: true,
                text: text,
                sentAt: DateTime.now(),
                delivery: 'pending'));
        _composerController.clear();
      }
    });
    _pendingTexts[id] = contact;
    // Older clients never send receipts. Bound bookkeeping while leaving
    // their message status honestly unconfirmed in the conversation.
    if (_pendingTexts.length > 2048) {
      _pendingTexts.remove(_pendingTexts.keys.first);
    }
    try {
      if (!_isRelayConnected) await _connectToRelay();
      if (!_isRelayConnected) throw StateError('Relay offline');
      final session = await _ensureSession(contact);
      if (!mounted || _isDisposing) return;
      // A new transport packet can be decrypted after a peer restarts. Keep
      // the logical message ID unchanged so the receiver can deduplicate it.
      final packetId = retry == null ? id : '$id-retry-${_newMessageId()}';
      _packetMessageIds[packetId] = id;
      if (_packetMessageIds.length > 2048) {
        _packetMessageIds.remove(_packetMessageIds.keys.first);
      }
      final ciphertext = _sendEnvelope(
          contact, session, TextEnvelope(text, id: id),
          messageId: packetId);
      final messages = _messagesByContact[contact.deviceId]!;
      final index = messages.indexWhere((m) => m.id == id);
      setState(() => messages[index] = ChatMessage.fromJson({
            ...messages[index].toJson(),
            'cipherHex': _bytesToHex(ciphertext),
            'delivery': 'pending'
          }));
    } catch (_) {
      if (mounted && !_isDisposing) {
        _updateDelivery(id, 'failed');
        setState(() => _connectionStatus = 'MESSAGE NOT SENT — TAP X TO RETRY');
      }
    } finally {
      _sendingText = false;
    }
    if (!mounted || _isDisposing) return;
    try {
      _persistHistory(contact);
    } catch (_) {
      setState(() => _connectionStatus =
          'MESSAGE QUEUED — LOCAL HISTORY COULD NOT BE SAVED');
    }
  }

  Future<void> _sendFile() async {
    final contact = _selectedContact;
    if (contact == null) return;
    try {
      final result = await FilePicker.pickFiles(withData: false);
      if (result == null || result.files.isEmpty || !mounted) return;
      final picked = result.files.first;
      if (picked.path == null) throw StateError('File path unavailable');
      await _sendFilePath(contact, picked.name, File(picked.path!));
    } catch (_) {
      if (mounted) {
        setState(() => _connectionStatus = 'COULD NOT OPEN FILE — TRY AGAIN');
      }
    }
  }

  Future<void> _sendDroppedFiles(List<XFile> files) async {
    // Capture the recipient before the first asynchronous file operation.
    final contact = _selectedContact;
    if (contact == null) return;
    for (final file in files) {
      if (!mounted || _exitWipeDone) return;
      await _sendFilePath(contact, file.name, File(file.path));
    }
  }

  Future<void> _sendFilePath(Contact contact, String name, File file) async {
    final session = _sessions[contact.deviceId];
    if (session == null || !_isRelayConnected) {
      if (mounted) {
        setState(() =>
            _connectionStatus = 'CONTACT OR RELAY OFFLINE — FILE NOT SENT');
      }
      return;
    }
    if (_startingUpload ||
        _outgoingTransfers.values.any((s) => s.progress.active)) {
      setState(() => _connectionStatus = 'PLEASE WAIT FOR THE CURRENT UPLOAD');
      return;
    }
    _startingUpload = true;
    try {
      final size = await file.length();
      validateFileMetadata(name, size,
          size == 0 ? 1 : (size + fileChunkSize - 1) ~/ fileChunkSize);
      if (!mounted || _exitWipeDone) return;
      final id = _newMessageId();
      final key = _transferKey(contact, id);
      final sender = FileSender(
          id: id,
          file: file,
          name: name,
          size: size,
          send: (envelope) {
            if (!mounted ||
                _exitWipeDone ||
                _sessions[contact.deviceId] != session) {
              throw StateError('Session ended');
            }
            _sendEnvelope(contact, session, envelope);
          });
      _outgoingTransfers[key] = sender;
      _showTransfer(key, sender.progress);
      await sender.run();
      if (!mounted ||
          _exitWipeDone ||
          sender.progress.phase == TransferPhase.cancelled) {
        return;
      }
      if (![TransferPhase.complete, TransferPhase.unconfirmed]
          .contains(sender.progress.phase)) {
        return;
      }
      setState(() {
        _messagesByContact
            .putIfAbsent(contact.deviceId, () => [])
            .add(ChatMessage(
              id: _newMessageId(),
              fromSelf: true,
              sentAt: DateTime.now(),
              fileName: name,
              fileSize: size,
              text: sender.progress.phase == TransferPhase.complete
                  ? 'Delivered'
                  : 'Delivery unconfirmed',
            ));
      });
      _persistHistory(contact);
    } on FormatException {
      if (mounted) {
        setState(() =>
            _connectionStatus = 'FILE NOT SENT — LIMIT 64 MiB; CHECK FILENAME');
      }
    } catch (_) {
      if (mounted) {
        setState(() =>
            _connectionStatus = 'FILE SEND FAILED — CHECK FILE AND CONNECTION');
      }
    } finally {
      _startingUpload = false;
    }
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
          style: TextStyle(
              color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono),
        ),
        content: TerminalTextField(controller: controller),
        actions: [
          AsciiButton(
              label: 'Cancel', onPressed: () => Navigator.of(context).pop()),
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
    for (final session in _sessions.values) {
      session.dispose();
    }
    _sessions.clear();
    _selfInitiated.clear();
    _peerSeen.clear();
    _presenceCapable.clear();
    _relayLatencyMs = null;
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
            style: TextStyle(
                color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono),
          ),
          content: TerminalTextField(
            controller: controller,
            hintText: 'https://.../update-manifest.json',
          ),
          actions: [
            AsciiButton(
                label: 'Cancel', onPressed: () => Navigator.of(context).pop()),
            AsciiButton(
              label: 'Save',
              onPressed: () =>
                  Navigator.of(context).pop(controller.text.trim()),
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
      update = await UpdateChecker.checkForUpdate(manifestUrl)
          .timeout(const Duration(seconds: 15));
    } on TimeoutException {
      await AppLogger.warn('update check timed out ($manifestUrl)');
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
            content: Text('Update check timed out — try again later.')),
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
          style: const TextStyle(
              color: VaultXColors.phosphor, fontFamily: VaultXFonts.mono),
        ),
        content: Text(
          resolvedUpdate.notes ?? 'A newer version of Vault X is available.',
          style: const TextStyle(
              color: VaultXColors.phosphorDim, fontFamily: VaultXFonts.mono),
        ),
        actions: [
          AsciiButton(
              label: 'Later',
              onPressed: () => Navigator.of(context).pop(false)),
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
      await UpdateChecker.downloadAndLaunchInstaller(
          resolvedUpdate.installerUrl);
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
    _reconnectTimer?.cancel();
    _healthTimer?.cancel();
    _isDisposing = true;
    // Fallback only — _wipeAllOnExit is guarded by _exitWipeDone, so this
    // is a no-op on the normal path (already ran, and got to actually
    // delay exit for the sends to flush, via the lifecycle listener
    // above). Still calling it here covers screen teardown that isn't a
    // real app exit at all (e.g. hot reload/navigation in dev), where
    // skipping it would leave history sitting un-burned.
    unawaited(_wipeAllOnExit());
    _lifecycleListener?.dispose();
    for (final timer in _transferExpiry.values) {
      timer.cancel();
    }
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
                            child: Text(
                              '[relay ${_relayLatencyMs == null ? '—' : '$_relayLatencyMs ms'}]',
                              style: const TextStyle(
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
                                selected: contact.deviceId ==
                                    _selectedContact?.deviceId,
                                online: _peerOnline(contact.deviceId),
                                onTap: () =>
                                    setState(() => _selectedContact = contact),
                                onRemove: () => _removeContact(contact),
                              ),
                          ],
                        ),
                      ),
                    Padding(
                      padding: const EdgeInsets.all(10),
                      child: AsciiButton(
                          label: '+ Add Contact', onPressed: _openAddContact),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: DropTarget(
                onDragEntered: (_) => setState(() => _isDragHovering = true),
                onDragExited: (_) => setState(() => _isDragHovering = false),
                onDragDone: (details) {
                  setState(() => _isDragHovering = false);
                  _sendDroppedFiles(details.files);
                },
                child: Stack(
                  children: [
                    TerminalPanel(
                      title: _selectedContact == null
                          ? 'terminal // no contact selected'
                          : 'terminal // ${_selectedContact!.label}',
                      padding: EdgeInsets.zero,
                      expandContent: true,
                      child: Column(
                        children: [
                          Padding(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 12, vertical: 10),
                            // Wrap rather than Row: two badges plus three
                            // buttons need ~1150px to fit on one line, wider
                            // than this panel gets once the window is
                            // resized down or the sidebar is open — Row
                            // would silently overflow off the right edge
                            // (only visible as a debug-mode warning stripe,
                            // never a crash, so easy to miss). Wrap instead
                            // lets buttons flow onto a second line.
                            child: Wrap(
                              spacing: 8,
                              runSpacing: 8,
                              crossAxisAlignment: WrapCrossAlignment.center,
                              children: [
                                const CipherBadge(
                                    label: 'ENC: CHACHA20-POLY1305'),
                                const CipherBadge(
                                    label: 'POST-QUANTUM: ENABLED'),
                                AsciiButton(
                                    label: 'My ID', onPressed: _copyMyId),
                                AsciiButton(
                                    label: 'Updates',
                                    onPressed: _checkForUpdates),
                                AsciiButton(
                                    label: 'View Log', onPressed: _openLog),
                                Tooltip(
                                    message:
                                        'On saves encrypted chat history. Off clears saved text history and keeps this conversation only until you close the app. Received files may still exist on disk.',
                                    child: AsciiButton(
                                        label:
                                            'History: ${_keepHistory ? 'ON' : 'OFF'}',
                                        onPressed: _toggleHistory)),
                                AsciiButton(
                                    label: 'Retry connection',
                                    onPressed: _connectToRelay),
                              ],
                            ),
                          ),
                          const Divider(height: 1, color: VaultXColors.border),
                          ConstrainedBox(
                            constraints: const BoxConstraints(maxHeight: 220),
                            child: SingleChildScrollView(
                                child: Column(children: [
                              for (final entry in _transferProgress.entries
                                  .where((e) =>
                                      _selectedContact != null &&
                                      e.key.startsWith(
                                          '${_selectedContact!.deviceId}:')))
                                TransferStatus(
                                    key: ValueKey(entry.key),
                                    progress: entry.value,
                                    onCancel: !entry.value.active
                                        ? null
                                        : () {
                                            final outgoing =
                                                _outgoingTransfers[entry.key];
                                            if (outgoing != null) {
                                              outgoing.cancel();
                                            } else {
                                              final contact = _selectedContact!;
                                              _cancelIncoming(
                                                  contact,
                                                  entry.key.substring(
                                                      contact.deviceId.length +
                                                          1));
                                            }
                                          }),
                            ])),
                          ),
                          Expanded(
                            child: _selectedContact == null
                                ? _NoContactSelectedHint(
                                    onStartChat: _openAddContact)
                                : ListView.builder(
                                    padding: const EdgeInsets.all(14),
                                    itemCount: (_messagesByContact[
                                                _selectedContact!.deviceId] ??
                                            [])
                                        .length,
                                    itemBuilder: (context, index) {
                                      final message = _messagesByContact[
                                          _selectedContact!.deviceId]![index];
                                      return _MessageLine(
                                        message: message,
                                        revealed: _revealedMessageIds
                                            .contains(message.id),
                                        onToggleReveal: () =>
                                            _toggleReveal(message.id),
                                        onRetry: () => _sendMessage(
                                            retry: message,
                                            retryContact: _selectedContact),
                                      );
                                    },
                                  ),
                          ),
                          Container(
                            padding: const EdgeInsets.all(12),
                            decoration: const BoxDecoration(
                              border: Border(
                                  top: BorderSide(color: VaultXColors.border)),
                            ),
                            child: Row(
                              children: [
                                Expanded(
                                  child: TerminalTextField(
                                    controller: _composerController,
                                    hintText: _selectedContact == null
                                        ? 'select a contact first...'
                                        : 'type a message, or drag & drop a file...',
                                    onSubmitted: (_) => _sendMessage(),
                                  ),
                                ),
                                const SizedBox(width: 8),
                                AsciiButton(
                                  label: 'Attach',
                                  onPressed: _selectedContact == null
                                      ? null
                                      : _sendFile,
                                ),
                                const SizedBox(width: 8),
                                AsciiButton(
                                  label: 'Send',
                                  onPressed: _selectedContact == null
                                      ? null
                                      : _sendMessage,
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                    // Hover overlay while a drag is over this panel — the
                    // only visual feedback that anything will happen if
                    // the file is dropped here, since otherwise a drop
                    // target is entirely invisible until you release.
                    if (_isDragHovering)
                      Positioned.fill(
                        child: IgnorePointer(
                          child: DecoratedBox(
                            decoration: BoxDecoration(
                              color:
                                  VaultXColors.phosphor.withValues(alpha: 0.08),
                              border: Border.all(
                                  color: VaultXColors.phosphor, width: 2),
                            ),
                            child: const Center(
                              child: Text(
                                '[ DROP FILE TO SEND ]',
                                style: TextStyle(
                                  color: VaultXColors.phosphor,
                                  fontFamily: VaultXFonts.mono,
                                  fontWeight: FontWeight.bold,
                                  fontSize: 16,
                                ),
                              ),
                            ),
                          ),
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
  final bool? online;
  final VoidCallback onTap;
  final VoidCallback onRemove;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        color:
            selected ? VaultXColors.phosphorDim.withValues(alpha: 0.15) : null,
        child: Row(
          children: [
            Expanded(
              child: Text(
                contact.label,
                style: TextStyle(
                  color: selected
                      ? VaultXColors.phosphor
                      : VaultXColors.phosphorDim,
                  fontFamily: VaultXFonts.mono,
                  fontSize: 13,
                ),
              ),
            ),
            Tooltip(
                message: online == null
                    ? 'Presence unknown — peer has not confirmed'
                    : online!
                        ? 'Online — recent encrypted response'
                        : 'Offline or unreachable',
                child: Container(
                  width: 9,
                  height: 9,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: online == null
                        ? Colors.grey
                        : online!
                            ? VaultXColors.phosphor
                            : VaultXColors.alertRed,
                  ),
                )),
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
    this.onRetry,
  });

  final ChatMessage message;
  final bool revealed;
  final VoidCallback onToggleReveal;
  final VoidCallback? onRetry;

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
    final color =
        message.fromSelf ? VaultXColors.phosphor : VaultXColors.phosphorDim;
    final time = message.sentAt.toIso8601String().substring(11, 19);

    final bodySpan = message.isFile
        ? TextSpan(
            text:
                '📎 ${message.fileName} (${_formatSize(message.fileSize ?? 0)})'
                '${message.filePath != null ? ' — click to reveal' : ''}'
                '${message.fromSelf ? ' — ${message.text ?? 'Delivery unconfirmed'}' : ''}',
            style: TextStyle(
              color: VaultXColors.phosphor,
              decoration:
                  message.filePath != null ? TextDecoration.underline : null,
            ),
            recognizer: message.filePath != null
                ? (TapGestureRecognizer()..onTap = _openFile)
                : null,
          )
        : (revealed || message.cipherHex == null)
            ? TextSpan(
                text:
                    '${message.text}${message.cipherHex != null ? '  [tap to hide]' : ''}',
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
            TextSpan(
                text: '[$time] ',
                style: const TextStyle(color: VaultXColors.phosphorDim)),
            TextSpan(
              text: '<$prefix>: ',
              style: TextStyle(color: color, fontWeight: FontWeight.bold),
            ),
            bodySpan,
            if (message.fromSelf && !message.isFile)
              TextSpan(
                text: switch (message.delivery) {
                  'received' => '  ✓✓ Received',
                  'sent' => '  ✓ Sent to relay — Retry',
                  'failed' => '  X Not sent — Retry',
                  _ => '  … Delivery unconfirmed — Retry',
                },
                style: TextStyle(
                    color: message.delivery == 'failed'
                        ? VaultXColors.alertRed
                        : VaultXColors.phosphorDim),
                recognizer: message.delivery != 'received'
                    ? (TapGestureRecognizer()..onTap = onRetry)
                    : null,
              ),
          ],
        ),
      ),
    );
  }
}
