// Dart client for transport_relay's HTTP + WebSocket surface (see
// transport_relay/router/router.go for the server side of this contract).
//
// This is the piece that turns two standalone app installs into an actual
// messenger: publishing/fetching prekey bundles, and streaming
// already-encrypted packets between devices. Nothing here ever sees
// plaintext — `payload` is always ciphertext bytes produced by
// NativeSession.encrypt (see conversation_screen.dart).
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:web_socket_channel/web_socket_channel.dart';

/// Wire-format tag prefixing every payload sent through the relay (see
/// [RelayStream.send]), so the receiving side knows whether an incoming
/// delivery is a PQXDH handshake or an ongoing Double Ratchet message
/// before it has a session to try decrypting with. See
/// `conversation_screen.dart` for where these are consumed.
const relayTagHandshake = 1;
const relayTagMessage = 2;

/// One packet delivered from the relay, addressed to us.
class RelayDelivery {
  RelayDelivery({required this.packetId, required this.sender, required this.payload});

  final String packetId;
  final String sender;
  final Uint8List payload;
}

/// A live connection to the relay's `/v1/stream` endpoint for one device
/// identity. Call [connect] once, listen to [deliveries], call [send] to
/// relay a packet to another device, and [ack] once a delivered packet has
/// been fully processed.
class RelayStream {
  RelayStream({required this.baseUrl, required this.deviceId});

  final String baseUrl;
  final String deviceId;

  WebSocketChannel? _channel;
  final _deliveriesController = StreamController<RelayDelivery>.broadcast();

  /// Packets addressed to this device, both queued-while-offline (flushed
  /// immediately on connect) and arriving live.
  Stream<RelayDelivery> get deliveries => _deliveriesController.stream;

  bool get isConnected => _channel != null;

  Future<void> connect() async {
    final wsUrl = _toWebSocketUrl(baseUrl, '/v1/stream');
    final channel = WebSocketChannel.connect(Uri.parse(wsUrl));
    await channel.ready;
    channel.sink.add(jsonEncode({'type': 'hello', 'sender': deviceId}));
    _channel = channel;
    channel.stream.listen(
      _handleIncoming,
      onDone: () => _channel = null,
      onError: (_) => _channel = null,
      cancelOnError: false,
    );
  }

  void _handleIncoming(dynamic raw) {
    final Map<String, dynamic> envelope = jsonDecode(raw as String);
    if (envelope['type'] != 'deliver') return;
    _deliveriesController.add(
      RelayDelivery(
        packetId: envelope['packet_id'] as String? ?? '',
        sender: envelope['sender'] as String? ?? '',
        payload: base64Decode(envelope['payload'] as String? ?? ''),
      ),
    );
  }

  /// Relay [payload] (opaque ciphertext) to [recipient]'s device ID.
  void send(String recipient, String packetId, Uint8List payload) {
    _channel?.sink.add(
      jsonEncode({
        'type': 'send',
        'packet_id': packetId,
        'recipient': recipient,
        'payload': base64Encode(payload),
      }),
    );
  }

  /// Confirm delivery of a packet so the relay can drop it for good.
  void ack(String packetId) {
    _channel?.sink.add(jsonEncode({'type': 'ack', 'packet_id': packetId}));
  }

  Future<void> close() async {
    await _channel?.sink.close();
    _channel = null;
    await _deliveriesController.close();
  }

  static String _toWebSocketUrl(String httpBaseUrl, String path) {
    final uri = Uri.parse(httpBaseUrl);
    final scheme = uri.scheme == 'https' ? 'wss' : 'ws';
    return Uri(scheme: scheme, host: uri.host, port: uri.port, path: path).toString();
  }
}

/// One-shot HTTP calls to the relay's prekey bundle endpoints.
class RelayHttp {
  RelayHttp({required this.baseUrl});

  final String baseUrl;

  /// Publish this device's PQXDH prekey bundle so others can start a
  /// handshake with it asynchronously.
  Future<bool> publishPreKeyBundle(String deviceId, Uint8List bundle) async {
    final response = await http.post(
      Uri.parse('$baseUrl/v1/prekeys/$deviceId'),
      body: bundle,
    );
    return response.statusCode == 204;
  }

  /// Fetch the prekey bundle a peer has published, or `null` if they
  /// haven't published one (they've never opened the app, most likely).
  Future<Uint8List?> fetchPreKeyBundle(String deviceId) async {
    final response = await http.get(Uri.parse('$baseUrl/v1/prekeys/$deviceId'));
    if (response.statusCode != 200) return null;
    return response.bodyBytes;
  }
}
