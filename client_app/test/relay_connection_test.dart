import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:client_app/services/relay_client.dart';

void main() {
  test('connection loss is observable and close is safe twice', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final connected = Completer<WebSocket>();
    server.listen((request) async {
      final socket = await WebSocketTransformer.upgrade(request);
      socket.listen((_) {
        if (!connected.isCompleted) connected.complete(socket);
      });
    });
    final stream = RelayStream(
        baseUrl: 'http://127.0.0.1:${server.port}', deviceId: 'synthetic');
    final disconnected = stream.connectionChanges.firstWhere((value) => !value);
    await stream.connect();
    final socket = await connected.future.timeout(const Duration(seconds: 3));
    expect(stream.isConnected, isTrue);
    await socket.close();
    await disconnected.timeout(const Duration(seconds: 3));
    expect(stream.isConnected, isFalse);
    await stream.close();
    await stream.close();
    await server.close(force: true);
  });

  test('relay acceptance and rejection refer to the actual packet', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) async {
      final socket = await WebSocketTransformer.upgrade(request);
      socket.listen((raw) {
        if ((jsonDecode(raw as String) as Map)['type'] == 'hello') {
          socket.add(jsonEncode({'type': 'accepted', 'packet_id': 'one'}));
          socket.add(jsonEncode({'type': 'error', 'packet_id': 'two'}));
        }
      });
    });
    final stream = RelayStream(
        baseUrl: 'http://127.0.0.1:${server.port}', deviceId: 'synthetic');
    final accepted = stream.acceptedPackets.first;
    final rejected = stream.rejectedPackets.first;
    await stream.connect();
    expect(await accepted.timeout(const Duration(seconds: 3)), 'one');
    expect(await rejected.timeout(const Duration(seconds: 3)), 'two');
    expect(stream.isConnected, isFalse);
    await stream.close();
    await server.close(force: true);
  });

  test('relay latency measures a response and rejects unavailable relay',
      () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    var healthy = true;
    server.listen((request) async {
      await Future<void>.delayed(const Duration(milliseconds: 40));
      request.response.statusCode = healthy ? 200 : 503;
      await request.response.close();
    });
    final client = RelayHttp(baseUrl: 'http://127.0.0.1:${server.port}');
    expect((await client.measureLatency()).inMilliseconds,
        greaterThanOrEqualTo(30));
    healthy = false;
    await expectLater(client.measureLatency(), throwsStateError);
    await server.close(force: true);
  });
}
