import 'dart:typed_data';

import 'package:client_app/services/file_transfer.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('file metadata cannot escape its download folder', () {
    for (final name in [
      '../outside.txt',
      r'..\outside.txt',
      '/absolute.txt',
      r'C:\outside.txt',
      'file.txt:stream',
      '.',
      '..',
      '',
      'NUL',
      'con.txt',
      'file.',
      'file ',
      'bad\u0000name',
    ]) {
      expect(
        () => IncomingFileTransfer(name: name, size: 1, chunkCount: 1),
        throwsFormatException,
        reason: 'unsafe filename must be rejected',
      );
    }
  });

  test('metadata size and chunk count must agree', () {
    for (final metadata in [
      (-1, 1),
      (1, 0),
      (1, -1),
      (1, 2),
      (fileChunkSize + 1, 1)
    ]) {
      expect(
        () => IncomingFileTransfer(
            name: 'file.bin', size: metadata.$1, chunkCount: metadata.$2),
        throwsFormatException,
      );
    }
  });

  test('invalid indexes cannot make an incomplete file look complete', () {
    final transfer =
        IncomingFileTransfer(name: 'file.bin', size: 3, chunkCount: 1);
    expect(() => transfer.addChunk(99, Uint8List(3)), throwsFormatException);
    expect(() => transfer.addChunk(-1, Uint8List(3)), throwsFormatException);
    expect(transfer.isComplete, isFalse);
  });

  test('received length must match advertised file length', () {
    final transfer =
        IncomingFileTransfer(name: 'file.bin', size: 3, chunkCount: 1);
    expect(() => transfer.addChunk(0, Uint8List(2)), throwsFormatException);
    expect(() => transfer.addChunk(0, Uint8List(4)), throwsFormatException);
    expect(transfer.isComplete, isFalse);
  });

  test('progress counts actual bytes, including a short final chunk', () {
    final transfer = IncomingFileTransfer(
        name: 'file.bin', size: fileChunkSize + 1, chunkCount: 2);
    transfer.addChunk(0, Uint8List(fileChunkSize));
    expect(transfer.progress,
        closeTo(fileChunkSize / (fileChunkSize + 1), 0.000001));
    expect(transfer.isComplete, isFalse);
    transfer.addChunk(1, Uint8List.fromList([42]));
    expect(transfer.isComplete, isTrue);
    expect(transfer.assemble().last, 42);
  });

  test('duplicate chunks cannot replace already accepted data', () {
    final transfer =
        IncomingFileTransfer(name: 'file.bin', size: 1, chunkCount: 1);
    transfer.addChunk(0, Uint8List.fromList([7]));
    transfer.addChunk(0, Uint8List.fromList([7]));
    expect(() => transfer.addChunk(0, Uint8List.fromList([9])),
        throwsFormatException);
    expect(transfer.assemble(), [7]);
  });

  test('empty files require their valid empty chunk', () {
    final transfer =
        IncomingFileTransfer(name: 'empty.bin', size: 0, chunkCount: 1);
    expect(transfer.isComplete, isFalse);
    transfer.addChunk(0, Uint8List(0));
    expect(transfer.isComplete, isTrue);
    expect(transfer.assemble(), isEmpty);
  });
}
