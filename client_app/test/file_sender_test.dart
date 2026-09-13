import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:client_app/services/file_sender.dart';
import 'package:client_app/services/file_transfer.dart';
import 'package:client_app/services/transfer_progress.dart';

void main() {
  late Directory temp;
  setUp(() async {
    temp = await Directory.systemTemp.createTemp('vaultx-synthetic-');
  });
  tearDown(() async {
    await temp.delete(recursive: true);
  });
  test('streams short final chunk and only completes after saved receipt',
      () async {
    final data = Uint8List(fileChunkSize + 7)..last = 42;
    final file = await File('${temp.path}/synthetic.bin').writeAsBytes(data);
    final received = <int>[];
    late FileSender sender;
    sender = FileSender(
        id: 'test',
        file: file,
        name: 'synthetic.bin',
        size: data.length,
        send: (envelope) {
          switch (envelope) {
            case FileOfferEnvelope():
              sender.acceptReceipt(
                  FileReceiptEnvelope(id: 'test', bytes: 0, stage: 'ready'));
            case FileChunkEnvelope(:final data):
              received.addAll(data);
              sender.acceptReceipt(FileReceiptEnvelope(
                  id: 'test', bytes: received.length, stage: 'received'));
            case FileDoneEnvelope():
              expect(sender.progress.phase, isNot(TransferPhase.complete));
              sender.acceptReceipt(FileReceiptEnvelope(
                  id: 'test', bytes: received.length, stage: 'saved'));
            default:
              break;
          }
        });
    await sender.run();
    expect(received, data);
    expect(sender.progress.phase, TransferPhase.complete);
  });
  test('old peer cannot be reported as delivered', () async {
    final file = await File('${temp.path}/synthetic.bin').writeAsBytes([1, 2]);
    final sender = FileSender(
        id: 'test',
        file: file,
        name: 'synthetic.bin',
        size: 2,
        negotiateTimeout: const Duration(milliseconds: 10),
        send: (_) {});
    await sender.run();
    expect(sender.progress.phase, TransferPhase.unconfirmed);
    expect(sender.progress.eta, isNull);
  });
  test('stalled receiver stops sending further chunks', () async {
    final file = await File('${temp.path}/synthetic.bin')
        .writeAsBytes(Uint8List(fileChunkSize + 1));
    var chunks = 0;
    late FileSender sender;
    sender = FileSender(
        id: 'test',
        file: file,
        name: 'synthetic.bin',
        size: fileChunkSize + 1,
        receiptTimeout: const Duration(milliseconds: 10),
        send: (e) {
          if (e is FileOfferEnvelope) {
            sender.acceptReceipt(
                FileReceiptEnvelope(id: 'test', bytes: 0, stage: 'ready'));
          }
          if (e is FileChunkEnvelope) chunks++;
        });
    await sender.run();
    expect(chunks, 1);
    expect(sender.progress.phase, TransferPhase.failed);
  });
  test('cancellation wakes a sender waiting for the peer', () async {
    final file = await File('${temp.path}/synthetic.bin').writeAsBytes([1]);
    late FileSender sender;
    sender = FileSender(
        id: 'test',
        file: file,
        name: 'synthetic.bin',
        size: 1,
        send: (_) {
          sender.cancel();
        });
    await sender.run().timeout(const Duration(seconds: 1));
    expect(sender.progress.phase, TransferPhase.cancelled);
  });
}
