import 'dart:io';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:client_app/services/transfer_progress.dart';
import 'package:client_app/widgets/transfer_status.dart';
import 'package:client_app/theme/cypher_theme.dart';

void main() {
  setUpAll(() async {
    final loader = FontLoader(VaultXFonts.mono)
      ..addFont(rootBundle.load('assets/fonts/FiraCode-Regular.ttf'));
    await loader.load();
  });
  testWidgets('progress fits a narrow window and cancel is usable',
      (tester) async {
    await tester.binding.setSurfaceSize(const Size(320, 300));
    final p = TransferProgress(
        name: 'a-very-long-synthetic-filename.bin',
        totalBytes: 100,
        uploading: true);
    await tester.pumpWidget(MaterialApp(
        home: Scaffold(
            body: TransferStatus(
                progress: p,
                onCancel: () => p.phase = TransferPhase.cancelled))));
    expect(tester.takeException(), isNull);
    await tester.tap(find.text('[ CANCEL ]'));
    await tester.pump(const Duration(milliseconds: 300));
    expect(find.text('Cancelled'), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    p.dispose();
    await tester.binding.setSurfaceSize(null);
  });

  testWidgets(
      'transfer display shows measured rate, approximate ETA and unconfirmed state',
      (tester) async {
    await tester.binding.setSurfaceSize(const Size(680, 370));
    var now = Duration.zero;
    final receive = TransferProgress(
        name: 'Holiday photos.zip',
        totalBytes: 20 * 1024 * 1024,
        uploading: false,
        clock: () => now)
      ..phase = TransferPhase.transferring;
    now = const Duration(seconds: 1);
    receive.updateBytes(2 * 1024 * 1024);
    now = const Duration(seconds: 2);
    receive.updateBytes(4 * 1024 * 1024);
    final send =
        TransferProgress(name: 'Notes.pdf', totalBytes: 409600, uploading: true)
          ..updateBytes(409600)
          ..phase = TransferPhase.unconfirmed;
    final boundaryKey = GlobalKey();
    await tester.pumpWidget(MaterialApp(
        theme: buildVaultXThemeData(),
        home: RepaintBoundary(
            key: boundaryKey,
            child: Scaffold(
                body: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          const Text('VAULT X  /  TRANSFERS',
                              style: TextStyle(
                                  fontFamily: VaultXFonts.mono, fontSize: 18)),
                          const SizedBox(height: 16),
                          TransferStatus(progress: receive, onCancel: () {}),
                          TransferStatus(progress: send),
                          const SizedBox(height: 12),
                          const Text(
                              'Synthetic preview — no personal files or live connection',
                              style: TextStyle(fontSize: 11)),
                        ]))))));
    await tester.pump(const Duration(milliseconds: 300));
    expect(find.textContaining('2.0 MiB/s'), findsOneWidget);
    expect(find.textContaining('About 8s left'), findsOneWidget);
    expect(find.textContaining('delivery unconfirmed'), findsOneWidget);
    expect(tester.takeException(), isNull);
    final output = Platform.environment['VAULTX_PREVIEW_PATH'];
    if (output != null) {
      await tester.runAsync(() async {
        final boundary = boundaryKey.currentContext!.findRenderObject()!
            as RenderRepaintBoundary;
        final image = await boundary.toImage(pixelRatio: 1.5);
        final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
        await File(output).writeAsBytes(bytes!.buffer.asUint8List());
        image.dispose();
      });
    }
    await tester.pumpWidget(const SizedBox());
    receive.dispose();
    send.dispose();
    await tester.binding.setSurfaceSize(null);
  });
}
