// Real widgets + native encryption + real loopback HTTP/WebSockets. No
// production identities, relay, or private conversations are used.
import 'dart:convert';
import 'dart:io';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:client_app/bridge/native_crypto.dart';
import 'package:client_app/models/contact.dart';
import 'package:client_app/screens/conversation_screen.dart';
import 'package:client_app/widgets/terminal_widgets.dart';
import 'package:client_app/theme/cypher_theme.dart';

void main() {
  setUpAll(() async {
    final loader = FontLoader(VaultXFonts.mono)
      ..addFont(rootBundle.load('assets/fonts/FiraCode-Regular.ttf'));
    await loader.load();
  });
  final relay = Platform.environment['VAULTX_TEST_RELAY'];
  for (final simultaneous in [false, true]) {
    testWidgets(
        'two people add, reply, reconnect and reopen (simultaneous: $simultaneous)',
        (tester) async {
      // Deliberately remove Flutter's network-blocking test override. Local
      // sockets run inside runAsync; UI timers still use the fake clock.
      HttpOverrides.global = null;
      expect(Uri.parse(relay!).host, '127.0.0.1');
      await tester.runAsync(NativeCrypto.ensureInitialized);
      tester.view.physicalSize = const Size(2400, 1000);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final temp = Directory.systemTemp.createTempSync('vaultx-two-user-');
      final alice = NativeCrypto.instance.generateIdentity();
      final bob = NativeCrypto.instance.generateIdentity();
      final aliceId = alice.deviceIdHex();
      final bobId = bob.deviceIdHex();
      final av = NativeCrypto.instance
          .createVault('${temp.path}/a.vault', utf8.encode('111111'))!;
      final bv = NativeCrypto.instance
          .createVault('${temp.path}/b.vault', utf8.encode('222222'))!;
      // A real forwarding proxy lets this test unplug the network without
      // fake RelayStream/session objects or touching any public server.
      final proxy = await tester
          .runAsync(() => HttpServer.bind(InternetAddress.loopbackIPv4, 0));
      var disconnected = false;
      final sockets = <WebSocket>[];
      final http = HttpClient();
      await tester.runAsync(() async {
        proxy!.listen((request) async {
          if (disconnected) {
            request.response.statusCode = 503;
            await request.response.close();
            return;
          }
          if (WebSocketTransformer.isUpgradeRequest(request)) {
            final upstream = await WebSocket.connect(
                '${relay.replaceFirst('http', 'ws')}${request.uri}');
            final downstream = await WebSocketTransformer.upgrade(request);
            sockets.addAll([upstream, downstream]);
            upstream.listen(downstream.add,
                onDone: downstream.close, onError: (_) => downstream.close());
            downstream.listen(upstream.add,
                onDone: upstream.close, onError: (_) => upstream.close());
          } else {
            final upstream = await http.openUrl(
                request.method, Uri.parse('$relay${request.uri}'));
            await upstream.addStream(request);
            final response = await upstream.close();
            request.response.statusCode = response.statusCode;
            await response.pipe(request.response);
          }
        });
      });
      addTearDown(() => tester.runAsync(() async {
            for (final socket in sockets) {
              await socket.close();
            }
            http.close(force: true);
            await proxy!.close(force: true);
          }));
      final proxyUrl = 'http://127.0.0.1:${proxy!.port}';
      av.put(utf8.encode('relay_url_v1'), utf8.encode(proxyUrl));
      bv.put(utf8.encode('relay_url_v1'), utf8.encode(proxyUrl));
      av.put(utf8.encode('keep_history_v1'), utf8.encode('\u0001'));
      bv.put(utf8.encode('keep_history_v1'), utf8.encode('\u0001'));
      Finder scope(String peer, Finder child) =>
          find.descendant(of: find.byKey(ValueKey(peer)), matching: child);
      Finder button(String peer, String label) => scope(peer,
          find.byWidgetPredicate((w) => w is AsciiButton && w.label == label));
      Future<void> settle() async {
        await tester.runAsync(
            () => Future<void>.delayed(const Duration(milliseconds: 100)));
        await tester.pump(const Duration(milliseconds: 100));
      }

      Future<void> until(bool Function() ready) async {
        for (var i = 0; i < 80 && !ready(); i++) {
          await settle();
        }
        expect(ready(), isTrue,
            reason: tester
                .widgetList<Text>(find.byType(Text))
                .map((w) => w.data ?? '')
                .where((s) =>
                    s.contains('OFFLINE') ||
                    s.contains('CONNECT') ||
                    s.contains('REJECTED') ||
                    s == 'ONLINE')
                .join(' | '));
      }

      Future<void> tap(Finder target) async {
        await tester.runAsync(() => tester.tap(target));
        await tester.pump();
        await settle();
      }

      Future<void> add(String peer, String label, String id) async {
        await tap(button(peer, '+ Add Contact'));
        await tester.pump(const Duration(seconds: 1));
        final fields = scope(peer, find.byType(TextField));
        await tester.enterText(fields.at(0), label);
        await tester.enterText(fields.at(1), id);
        await tap(button(peer, 'Add'));
        await until(() => button(peer, '+ Add Contact').evaluate().isNotEmpty);
        await tester.pump(const Duration(seconds: 1));
      }

      int count(NativeVault vault, String id) {
        final raw = vault.get(utf8.encode('history:$id'));
        if (raw == null) return 0;
        try {
          return (jsonDecode(utf8.decode(raw)) as List).length;
        } finally {
          raw.fillRange(0, raw.length, 0);
        }
      }

      await tester.runAsync(() =>
          tester.pumpWidget(Row(textDirection: TextDirection.ltr, children: [
            Expanded(
                child: MaterialApp(
                    key: const ValueKey('alice'),
                    home: ConversationScreen(
                        vault: av, identity: alice, isDecoy: false))),
            Expanded(
                child: MaterialApp(
                    key: const ValueKey('bob'),
                    home: ConversationScreen(
                        vault: bv, identity: bob, isDecoy: false))),
          ])));
      await until(() =>
          scope('alice', find.text('ONLINE')).evaluate().isNotEmpty &&
          scope('bob', find.text('ONLINE')).evaluate().isNotEmpty);
      if (simultaneous) {
        await tap(button('alice', '+ Add Contact'));
        await tap(button('bob', '+ Add Contact'));
        await tester.pump(const Duration(seconds: 1));
        await tester.enterText(
            scope('alice', find.byType(TextField)).at(0), 'Bob');
        await tester.enterText(
            scope('alice', find.byType(TextField)).at(1), bobId);
        await tester.enterText(
            scope('bob', find.byType(TextField)).at(0), 'Alice');
        await tester.enterText(
            scope('bob', find.byType(TextField)).at(1), aliceId);
        await tester.runAsync(() async {
          await tester.tap(button('alice', 'Add'));
          await tester.tap(button('bob', 'Add'));
        });
        await until(() =>
            button('alice', '+ Add Contact').evaluate().isNotEmpty &&
            button('bob', '+ Add Contact').evaluate().isNotEmpty);
        await tester.pump(const Duration(seconds: 1));
      } else {
        await add('alice', 'Bob', bobId);
      }
      await until(() {
        final contacts = bv.get(utf8.encode(Contact.vaultKey));
        return contacts != null && Contact.decodeList(contacts).isNotEmpty;
      });
      await tester.enterText(scope('alice', find.byType(TextField)).last,
          'synthetic first message');
      await tap(button('alice', 'Send'));
      await until(() => count(bv, aliceId) == 1);
      // Typical user: Bob also pastes Alice's ID after she has already added him.
      await add('bob', 'Alice', aliceId);
      expect(count(bv, aliceId), 1,
          reason: 'Adding an existing contact must retain history');
      await tester.enterText(
          scope('bob', find.byType(TextField)).last, 'synthetic reply');
      await tap(button('bob', 'Send'));
      await until(() => count(av, bobId) == 2);
      await until(() {
        final raw = av.get(utf8.encode('history:$bobId'))!;
        try {
          return (jsonDecode(utf8.decode(raw)) as List).first['delivery'] ==
              'received';
        } finally {
          raw.fillRange(0, raw.length, 0);
        }
      });
      expect(
          scope('alice', find.byTooltip('Online — recent encrypted response'))
              .evaluate(),
          isNotEmpty);
      await tap(button('alice', 'Retry connection'));
      await until(
          () => scope('alice', find.text('ONLINE')).evaluate().isNotEmpty);
      await tester.enterText(scope('alice', find.byType(TextField)).last,
          'synthetic after reconnect');
      await tap(button('alice', 'Send'));
      await until(() => count(bv, aliceId) == 3);
      final preview = Platform.environment['VAULTX_CHAT_PREVIEW_PATH'];
      if (preview != null && !simultaneous) {
        final boundary = tester.renderObject<RenderRepaintBoundary>(
            find.byType(RepaintBoundary).first);
        await tester.runAsync(() async {
          final image = await boundary.toImage();
          try {
            final data = await image.toByteData(format: ui.ImageByteFormat.png);
            await File(preview).writeAsBytes(data!.buffer.asUint8List());
          } finally {
            image.dispose();
          }
        });
      }
      await tap(button('alice', 'History: ON'));
      expect(count(av, bobId), 0, reason: 'History OFF clears saved text');
      expect(button('alice', 'History: OFF'), findsOneWidget);
      await tap(button('alice', 'History: OFF'));
      expect(count(av, bobId), 3,
          reason: 'History ON saves current conversation');
      expect(
          Contact.decodeList(bv.get(utf8.encode(Contact.vaultKey))!).length, 1);
      final aliceWire = alice.toWireBytes();
      final bobWire = bob.toWireBytes();
      await tester.runAsync(() => tester.pumpWidget(const SizedBox()));
      await settle();
      final aliceAgain = NativeCrypto.instance.loadIdentity(aliceWire)!;
      final bobAgain = NativeCrypto.instance.loadIdentity(bobWire)!;
      aliceWire.fillRange(0, aliceWire.length, 0);
      bobWire.fillRange(0, bobWire.length, 0);
      final avAgain = NativeCrypto.instance
          .unlockVault('${temp.path}/a.vault', '${temp.path}/missing-a',
              utf8.encode('111111'))!
          .vault;
      final bvAgain = NativeCrypto.instance
          .unlockVault('${temp.path}/b.vault', '${temp.path}/missing-b',
              utf8.encode('222222'))!
          .vault;
      expect(count(avAgain, bobId), 3,
          reason: 'History survives app close when enabled');
      await tester.runAsync(() =>
          tester.pumpWidget(Row(textDirection: TextDirection.ltr, children: [
            Expanded(
                child: MaterialApp(
                    key: const ValueKey('alice'),
                    home: ConversationScreen(
                        vault: avAgain, identity: aliceAgain, isDecoy: false))),
            Expanded(
                child: MaterialApp(
                    key: const ValueKey('bob'),
                    home: ConversationScreen(
                        vault: bvAgain, identity: bobAgain, isDecoy: false))),
          ])));
      await until(() =>
          scope('alice', find.text('ONLINE')).evaluate().isNotEmpty &&
          scope('bob', find.text('ONLINE')).evaluate().isNotEmpty);
      await tester.enterText(scope('alice', find.byType(TextField)).last,
          'synthetic after reopening');
      await tap(button('alice', 'Send'));
      await until(() => count(bvAgain, aliceId) == 4);
      await tester.enterText(scope('bob', find.byType(TextField)).last,
          'synthetic reopened reply');
      await tap(button('bob', 'Send'));
      await until(() => count(avAgain, bobId) == 5);
      disconnected = true;
      await tester.runAsync(() async {
        for (final socket in sockets) {
          await socket.close();
        }
      });
      await until(() => scope('alice', find.byTooltip('Offline or unreachable'))
          .evaluate()
          .isNotEmpty);
      await tester.enterText(scope('alice', find.byType(TextField)).last,
          'synthetic retry after outage');
      await tap(button('alice', 'Send'));
      await until(() =>
          scope('alice', find.text('MESSAGE NOT SENT — TAP X TO RETRY'))
              .evaluate()
              .isNotEmpty);
      expect(count(avAgain, bobId), 6);
      expect(count(bvAgain, aliceId), 5,
          reason: 'A failed send cannot claim delivery');
      disconnected = false;
      // Tap the actual visible Retry text, rather than invoking state methods.
      final retryLine = scope(
          'alice',
          find.byWidgetPredicate((w) =>
              w is RichText &&
              w.text.toPlainText().contains('X Not sent — Retry')));
      final paragraph = tester.renderObject<RenderParagraph>(retryLine);
      final text = tester.widget<RichText>(retryLine).text.toPlainText();
      final x = text.indexOf('X Not sent');
      final box = paragraph
          .getBoxesForSelection(
              TextSelection(baseOffset: x, extentOffset: x + 1))
          .first;
      await tester.runAsync(
          () => tester.tapAt(paragraph.localToGlobal(box.toRect().center)));
      await until(() => count(bvAgain, aliceId) == 6);
      expect(count(avAgain, bobId), 6,
          reason: 'Retry must reuse the existing message bubble');
      await until(() =>
          scope('alice', find.byTooltip('Online — recent encrypted response'))
              .evaluate()
              .isNotEmpty);
      final bobRestartWire = bobAgain.toWireBytes();
      await tester.runAsync(() =>
          tester.pumpWidget(Row(textDirection: TextDirection.ltr, children: [
            Expanded(
                child: MaterialApp(
                    key: const ValueKey('alice'),
                    home: ConversationScreen(
                        vault: avAgain, identity: aliceAgain, isDecoy: false))),
            const Expanded(child: SizedBox()),
          ])));
      await settle();
      final bobRestartIdentity =
          NativeCrypto.instance.loadIdentity(bobRestartWire)!;
      await tester.enterText(scope('alice', find.byType(TextField)).last,
          'synthetic queued while peer was closed');
      await tap(button('alice', 'Send'));
      final queuedLine = scope(
          'alice',
          find.byWidgetPredicate((w) =>
              w is RichText &&
              w.text.toPlainText().contains('✓ Sent to relay')));
      await until(() => queuedLine.evaluate().isNotEmpty);
      expect(count(avAgain, bobId), 7);
      bobRestartWire.fillRange(0, bobRestartWire.length, 0);
      final bobRestartVault = NativeCrypto.instance
          .unlockVault('${temp.path}/b.vault', '${temp.path}/missing-b',
              utf8.encode('222222'))!
          .vault;
      await tester.runAsync(() =>
          tester.pumpWidget(Row(textDirection: TextDirection.ltr, children: [
            Expanded(
                child: MaterialApp(
                    key: const ValueKey('alice'),
                    home: ConversationScreen(
                        vault: avAgain, identity: aliceAgain, isDecoy: false))),
            Expanded(
                child: MaterialApp(
                    key: const ValueKey('bob'),
                    home: ConversationScreen(
                        vault: bobRestartVault,
                        identity: bobRestartIdentity,
                        isDecoy: false))),
          ])));
      await until(
          () => scope('bob', find.text('ONLINE')).evaluate().isNotEmpty);
      await until(() =>
          scope('bob', find.byTooltip('Online — recent encrypted response'))
              .evaluate()
              .isNotEmpty);
      final queuedParagraph = tester.renderObject<RenderParagraph>(queuedLine);
      final queuedText = tester.widget<RichText>(queuedLine).text.toPlainText();
      final retryOffset = queuedText.lastIndexOf('Retry');
      final retryBox = queuedParagraph
          .getBoxesForSelection(TextSelection(
              baseOffset: retryOffset, extentOffset: retryOffset + 1))
          .first;
      await tester.runAsync(() => tester
          .tapAt(queuedParagraph.localToGlobal(retryBox.toRect().center)));
      await until(() => count(bobRestartVault, aliceId) == 7);
      expect(count(avAgain, bobId), 7);
      await tester.enterText(scope('alice', find.byType(TextField)).last,
          'synthetic after peer alone reopened');
      await tap(button('alice', 'Send'));
      await until(() => count(bobRestartVault, aliceId) == 8);
      await tester.runAsync(() => tester.pumpWidget(const SizedBox()));
      await settle();
      temp.deleteSync(recursive: true);
    }, skip: relay == null);
  }
}
