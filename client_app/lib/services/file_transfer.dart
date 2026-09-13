// Application-level message envelope sent over a NativeSession (i.e. after
// PQXDH + Double Ratchet encryption, before it ever reaches the relay).
// Every ratchet message's plaintext is one of these, JSON-encoded — this is
// what lets both plain text chats and file transfers share the same
// session/relay plumbing (see conversation_screen.dart) instead of needing
// a second channel.
//
// Files up to maxIncomingFileBytes are split into many
// [FileChunkEnvelope]s, each individually ratchet-encrypted and relayed as
// its own packet under the relay's per-packet size cap (see
// transport_relay/router/router.go's maxPacketPayloadBytes) — the relay
// never sees or reassembles anything; that only happens here, after
// decryption, on the receiving device.
import 'dart:convert';
import 'dart:typed_data';

/// Plaintext bytes small enough that, once encrypted and base64-wrapped by
/// the relay's JSON envelope, comfortably clears the relay's per-packet
/// cap with room to spare.
const fileChunkSize = 400 * 1024;

// The receiver currently keeps chunks in memory. Bound this until encrypted
// disk spooling is implemented; never advertise unlimited file size.
const maxIncomingFileBytes = 64 * 1024 * 1024;

void validateFileMetadata(String name, int size, int chunkCount) {
  if (name.isEmpty ||
      name.length > 240 ||
      RegExp(r'[<>:"/\\|?*\x00-\x1f]').hasMatch(name) ||
      name.endsWith('.') ||
      name.endsWith(' ') ||
      RegExp(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)',
              caseSensitive: false)
          .hasMatch(name)) {
    throw const FormatException('Unsupported filename');
  }
  final expected = size == 0 ? 1 : (size + fileChunkSize - 1) ~/ fileChunkSize;
  if (size < 0 || size > maxIncomingFileBytes || chunkCount != expected) {
    throw const FormatException(
        'Invalid file size or chunk count (limit: 64 MiB)');
  }
}

sealed class MessageEnvelope {
  Map<String, dynamic> toJson();

  static MessageEnvelope fromJson(Map<String, dynamic> json) {
    switch (json['t'] as String?) {
      case 'text':
        return TextEnvelope(json['body'] as String, id: json['id'] as String?);
      case 'text_receipt':
        return TextReceiptEnvelope(json['id'] as String);
      case 'file_offer':
        return FileOfferEnvelope(
          id: json['id'] as String,
          name: json['name'] as String,
          size: json['size'] as int,
          chunkCount: json['chunks'] as int,
          receipts: json['receipts'] == true,
        );
      case 'file_chunk':
        return FileChunkEnvelope(
          id: json['id'] as String,
          index: json['index'] as int,
          data: base64Decode(json['data'] as String),
        );
      case 'file_done':
        return FileDoneEnvelope(json['id'] as String);
      case 'file_receipt':
        // Older clients already ignore receipts with no matching transfer.
        // Negotiate presence without sending them an unknown message type.
        if (json['id'] == '__vaultx_presence_v1__' &&
            json['bytes'] == 0 &&
            (json['stage'] == 'presence-request' ||
                json['stage'] == 'presence-reply')) {
          return PresenceEnvelope(reply: json['stage'] == 'presence-reply');
        }
        return FileReceiptEnvelope(
            id: json['id'] as String,
            bytes: json['bytes'] as int,
            stage: json['stage'] as String);
      case 'wipe':
        return WipeEnvelope();
      default:
        throw FormatException('unknown envelope type: ${json['t']}');
    }
  }

  Uint8List encode() => Uint8List.fromList(utf8.encode(jsonEncode(toJson())));

  static MessageEnvelope decode(Uint8List bytes) =>
      fromJson(jsonDecode(utf8.decode(bytes)) as Map<String, dynamic>);
}

class TextEnvelope extends MessageEnvelope {
  TextEnvelope(this.body, {this.id});
  final String body;
  final String? id;

  @override
  Map<String, dynamic> toJson() =>
      {'t': 'text', 'body': body, if (id != null) 'id': id};
}

/// Sent only when a text includes an ID requesting confirmation. Older
/// senders do not request receipts and never receive an unknown envelope.
class TextReceiptEnvelope extends MessageEnvelope {
  TextReceiptEnvelope(this.id);
  final String id;
  @override
  Map<String, dynamic> toJson() => {'t': 'text_receipt', 'id': id};
}

class PresenceEnvelope extends MessageEnvelope {
  PresenceEnvelope({required this.reply});
  final bool reply;
  @override
  Map<String, dynamic> toJson() => {
        't': 'file_receipt',
        'id': '__vaultx_presence_v1__',
        'bytes': 0,
        'stage': reply ? 'presence-reply' : 'presence-request'
      };
}

/// Sent once, before any chunks, so the receiver knows what's coming (name,
/// total size, how many chunks to expect) and can show progress.
class FileOfferEnvelope extends MessageEnvelope {
  FileOfferEnvelope({
    required this.id,
    required this.name,
    required this.size,
    required this.chunkCount,
    this.receipts = false,
  });

  final String id;
  final String name;
  final int size;
  final int chunkCount;
  final bool receipts;

  @override
  Map<String, dynamic> toJson() => {
        't': 'file_offer',
        'id': id,
        'name': name,
        'size': size,
        'chunks': chunkCount,
        if (receipts) 'receipts': true
      };
}

/// Only sent when the offer explicitly requests receipts. Old clients ignore
/// the optional offer field and never receive an unknown envelope type.
class FileReceiptEnvelope extends MessageEnvelope {
  FileReceiptEnvelope(
      {required this.id, required this.bytes, required this.stage});
  final String id;
  final int bytes;
  final String stage;
  @override
  Map<String, dynamic> toJson() =>
      {'t': 'file_receipt', 'id': id, 'bytes': bytes, 'stage': stage};
}

class FileChunkEnvelope extends MessageEnvelope {
  FileChunkEnvelope(
      {required this.id, required this.index, required this.data});

  final String id;
  final int index;
  final Uint8List data;

  @override
  Map<String, dynamic> toJson() =>
      {'t': 'file_chunk', 'id': id, 'index': index, 'data': base64Encode(data)};
}

/// Sent once all chunks have gone out, so the receiver knows the transfer
/// completed cleanly (versus the sender having crashed mid-transfer).
class FileDoneEnvelope extends MessageEnvelope {
  FileDoneEnvelope(this.id);
  final String id;

  @override
  Map<String, dynamic> toJson() => {'t': 'file_done', 'id': id};
}

/// Sent through the encrypted session when a device explicitly closes the
/// app, telling the peer "I'm burning our chat history on my end — burn
/// yours too." Authenticated implicitly by arriving over the already
/// established ratchet session (the relay itself never sees this, or
/// anything else, in plaintext), so it can't be spoofed by anyone who
/// doesn't already hold that session's keys.
class WipeEnvelope extends MessageEnvelope {
  @override
  Map<String, dynamic> toJson() => {'t': 'wipe'};
}

/// Splits [bytes] into [fileChunkSize]-sized pieces (the last one may be
/// smaller).
List<Uint8List> splitIntoChunks(Uint8List bytes) {
  final chunks = <Uint8List>[];
  for (var offset = 0; offset < bytes.length; offset += fileChunkSize) {
    final end = (offset + fileChunkSize < bytes.length)
        ? offset + fileChunkSize
        : bytes.length;
    chunks.add(Uint8List.sublistView(bytes, offset, end));
  }
  if (chunks.isEmpty) {
    chunks.add(Uint8List(0)); // an empty file is still one (empty) chunk
  }
  return chunks;
}

/// Accumulates chunks for one in-progress incoming file transfer.
class IncomingFileTransfer {
  IncomingFileTransfer(
      {required this.name, required this.size, required this.chunkCount}) {
    validateFileMetadata(name, size, chunkCount);
  }

  final String name;
  final int size;
  final int chunkCount;
  final Map<int, Uint8List> _chunks = {};
  int receivedBytes = 0;
  bool doneReceived = false;
  bool saving = false;
  bool cancelled = false;
  bool receipts = false;

  void addChunk(int index, Uint8List data) {
    if (cancelled || saving || index < 0 || index >= chunkCount) {
      throw const FormatException('Invalid chunk index or transfer state');
    }
    final expected =
        index == chunkCount - 1 ? size - index * fileChunkSize : fileChunkSize;
    if (data.length != expected) {
      throw const FormatException('Invalid chunk length');
    }
    final previous = _chunks[index];
    if (previous != null) {
      for (var i = 0; i < data.length; i++) {
        if (previous[i] != data[i]) {
          throw const FormatException('Conflicting duplicate chunk');
        }
      }
      return;
    }
    _chunks[index] = Uint8List.fromList(data);
    receivedBytes += data.length;
  }

  bool get isComplete =>
      !cancelled && _chunks.length == chunkCount && receivedBytes == size;

  double get progress =>
      size == 0 ? (isComplete ? 1 : 0) : receivedBytes / size;

  Iterable<Uint8List> get orderedChunks sync* {
    if (!isComplete) throw StateError('File is incomplete');
    for (var i = 0; i < chunkCount; i++) {
      yield _chunks[i]!;
    }
  }

  void clear() {
    cancelled = true;
    for (final chunk in _chunks.values) {
      chunk.fillRange(0, chunk.length, 0);
    }
    _chunks.clear();
    receivedBytes = 0;
  }

  Uint8List assemble() {
    final builder = BytesBuilder(copy: false);
    for (var i = 0; i < chunkCount; i++) {
      final chunk = _chunks[i];
      if (chunk == null) {
        throw StateError(
            'assemble() called before all chunks arrived (missing chunk $i)');
      }
      builder.add(chunk);
    }
    return builder.toBytes();
  }
}
