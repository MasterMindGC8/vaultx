import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'file_transfer.dart';
import 'transfer_progress.dart';

/// One file at a time, one encrypted chunk in flight when the peer supports
/// receipts. Legacy peers remain usable, but delivery is explicitly unknown.
class FileSender {
  FileSender(
      {required this.id,
      required this.file,
      required this.name,
      required this.size,
      required this.send,
      this.negotiateTimeout = const Duration(seconds: 3),
      this.receiptTimeout = const Duration(seconds: 30)})
      : progress =
            TransferProgress(name: name, totalBytes: size, uploading: true);
  final String id, name;
  final File file;
  final int size;
  final void Function(MessageEnvelope) send;
  final Duration negotiateTimeout, receiptTimeout;
  final TransferProgress progress;
  Completer<void>? _signal;
  FileReceiptEnvelope? _last;
  bool _cancelled = false;
  bool _doneSent = false;
  int _sentBytes = 0;

  void acceptReceipt(FileReceiptEnvelope receipt) {
    if (_cancelled ||
        receipt.id != id ||
        receipt.bytes < 0 ||
        receipt.bytes > _sentBytes ||
        !['ready', 'received', 'saved', 'failed'].contains(receipt.stage)) {
      return;
    }
    if (receipt.stage == 'saved' && (!_doneSent || receipt.bytes != size)) {
      return;
    }
    if (receipt.stage == 'received' && receipt.bytes < (_last?.bytes ?? 0)) {
      return;
    }
    _last = receipt;
    if (receipt.stage == 'saved' &&
        progress.phase == TransferPhase.unconfirmed) {
      progress.phase = TransferPhase.complete;
    }
    if (_signal?.isCompleted == false) _signal!.complete();
  }

  void cancel() {
    _cancelled = true;
    progress.phase = TransferPhase.cancelled;
    if (_signal?.isCompleted == false) _signal!.complete();
  }

  void _check() {
    if (_cancelled) throw StateError('Cancelled');
    if (_last?.stage == 'failed') {
      throw StateError('Recipient could not receive or save file');
    }
  }

  Future<void> _wait(bool Function() ready, Duration timeout) async {
    final watch = Stopwatch()..start();
    while (!ready()) {
      _check();
      final remaining = timeout - watch.elapsed;
      if (remaining <= Duration.zero) {
        throw TimeoutException('Receipt not received');
      }
      _signal = Completer<void>();
      await _signal!.future.timeout(remaining);
    }
    _check();
  }

  Future<void> run() async {
    RandomAccessFile? handle;
    try {
      final count = size == 0 ? 1 : (size + fileChunkSize - 1) ~/ fileChunkSize;
      validateFileMetadata(name, size, count);
      handle = await file.open();
      if (await handle.length() != size) {
        throw StateError('File changed before upload');
      }
      _check();
      send(FileOfferEnvelope(
          id: id, name: name, size: size, chunkCount: count, receipts: true));
      var confirmed = false;
      try {
        await _wait(() => _last?.stage == 'ready', negotiateTimeout);
        confirmed = true;
      } on TimeoutException {/* Older peers do not understand receipts. */}
      _check();
      progress.phase =
          confirmed ? TransferPhase.transferring : TransferPhase.preparing;
      for (var index = 0; index < count; index++) {
        _check();
        final length =
            index == count - 1 ? size - index * fileChunkSize : fileChunkSize;
        final chunk = Uint8List(length);
        try {
          var offset = 0;
          while (offset < length) {
            final read = await handle.readInto(chunk, offset, length);
            if (read == 0) {
              throw StateError('File became shorter during upload');
            }
            offset += read;
          }
          _check();
          _sentBytes += length;
          send(FileChunkEnvelope(id: id, index: index, data: chunk));
        } finally {
          chunk.fillRange(0, chunk.length, 0);
        }
        if (confirmed) {
          await _wait(
              () => _last?.stage == 'received' && _last!.bytes == _sentBytes,
              receiptTimeout);
        } else {
          // Yield to input, disconnect events and painting. This is not a
          // delivery ACK and does not impose an end-to-end memory bound.
          await Future<void>.delayed(const Duration(milliseconds: 20));
        }
        progress.updateBytes(_sentBytes);
      }
      _check();
      if (await handle.length() != size) {
        throw StateError('File changed during upload');
      }
      _doneSent = true;
      send(FileDoneEnvelope(id));
      if (confirmed) {
        progress.phase = TransferPhase.saving;
        await _wait(() => _last?.stage == 'saved', receiptTimeout);
        progress.phase = TransferPhase.complete;
      } else {
        progress.phase = _last?.stage == 'saved'
            ? TransferPhase.complete
            : TransferPhase.unconfirmed;
      }
    } catch (_) {
      if (!_cancelled) {
        progress.problem =
            'Transfer interrupted — check connection and file, then send again';
        progress.phase = TransferPhase.failed;
      }
    } finally {
      await handle?.close();
    }
  }
}
