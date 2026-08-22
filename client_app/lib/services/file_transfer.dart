// Application-level message envelope sent over a NativeSession (i.e. after
// PQXDH + Double Ratchet encryption, before it ever reaches the relay).
// Every ratchet message's plaintext is one of these, JSON-encoded — this is
// what lets both plain text chats and file transfers share the same
// session/relay plumbing (see conversation_screen.dart) instead of needing
// a second channel.
//
// Files of any size are supported by splitting them into many
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

sealed class MessageEnvelope {
  Map<String, dynamic> toJson();

  static MessageEnvelope fromJson(Map<String, dynamic> json) {
    switch (json['t'] as String?) {
      case 'text':
        return TextEnvelope(json['body'] as String);
      case 'file_offer':
        return FileOfferEnvelope(
          id: json['id'] as String,
          name: json['name'] as String,
          size: json['size'] as int,
          chunkCount: json['chunks'] as int,
        );
      case 'file_chunk':
        return FileChunkEnvelope(
          id: json['id'] as String,
          index: json['index'] as int,
          data: base64Decode(json['data'] as String),
        );
      case 'file_done':
        return FileDoneEnvelope(json['id'] as String);
      default:
        throw FormatException('unknown envelope type: ${json['t']}');
    }
  }

  Uint8List encode() => Uint8List.fromList(utf8.encode(jsonEncode(toJson())));

  static MessageEnvelope decode(Uint8List bytes) =>
      fromJson(jsonDecode(utf8.decode(bytes)) as Map<String, dynamic>);
}

class TextEnvelope extends MessageEnvelope {
  TextEnvelope(this.body);
  final String body;

  @override
  Map<String, dynamic> toJson() => {'t': 'text', 'body': body};
}

/// Sent once, before any chunks, so the receiver knows what's coming (name,
/// total size, how many chunks to expect) and can show progress.
class FileOfferEnvelope extends MessageEnvelope {
  FileOfferEnvelope({
    required this.id,
    required this.name,
    required this.size,
    required this.chunkCount,
  });

  final String id;
  final String name;
  final int size;
  final int chunkCount;

  @override
  Map<String, dynamic> toJson() =>
      {'t': 'file_offer', 'id': id, 'name': name, 'size': size, 'chunks': chunkCount};
}

class FileChunkEnvelope extends MessageEnvelope {
  FileChunkEnvelope({required this.id, required this.index, required this.data});

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

/// Splits [bytes] into [fileChunkSize]-sized pieces (the last one may be
/// smaller).
List<Uint8List> splitIntoChunks(Uint8List bytes) {
  final chunks = <Uint8List>[];
  for (var offset = 0; offset < bytes.length; offset += fileChunkSize) {
    final end = (offset + fileChunkSize < bytes.length) ? offset + fileChunkSize : bytes.length;
    chunks.add(Uint8List.sublistView(bytes, offset, end));
  }
  if (chunks.isEmpty) chunks.add(Uint8List(0)); // an empty file is still one (empty) chunk
  return chunks;
}

/// Accumulates chunks for one in-progress incoming file transfer.
class IncomingFileTransfer {
  IncomingFileTransfer({required this.name, required this.size, required this.chunkCount});

  final String name;
  final int size;
  final int chunkCount;
  final Map<int, Uint8List> _chunks = {};

  void addChunk(int index, Uint8List data) => _chunks[index] = data;

  bool get isComplete => _chunks.length >= chunkCount;

  double get progress => chunkCount == 0 ? 1.0 : _chunks.length / chunkCount;

  Uint8List assemble() {
    final builder = BytesBuilder(copy: false);
    for (var i = 0; i < chunkCount; i++) {
      final chunk = _chunks[i];
      if (chunk == null) {
        throw StateError('assemble() called before all chunks arrived (missing chunk $i)');
      }
      builder.add(chunk);
    }
    return builder.toBytes();
  }
}
