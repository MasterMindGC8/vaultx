import 'package:flutter/foundation.dart';

enum TransferPhase {
  waiting,
  preparing,
  transferring,
  saving,
  complete,
  unconfirmed,
  failed,
  cancelled
}

/// A byte-based estimate, using a monotonic clock and a recent five-second
/// sample window. Queueing a socket write is never treated as delivered data.
class TransferProgress extends ChangeNotifier {
  TransferProgress(
      {required this.name,
      required this.totalBytes,
      required this.uploading,
      Duration Function()? clock}) {
    final stopwatch = Stopwatch()..start();
    _clock = clock ?? () => stopwatch.elapsed;
    _samples.add((_clock(), 0));
  }
  final String name;
  final int totalBytes;
  final bool uploading;
  late final Duration Function() _clock;
  final List<(Duration, int)> _samples = [];
  int bytes = 0;
  TransferPhase _phase = TransferPhase.waiting;
  String? problem;
  TransferPhase get phase => _phase;
  set phase(TransferPhase value) {
    if (value == TransferPhase.transferring && _phase != value) {
      _samples.clear();
      _samples.add((_clock(), bytes));
    }
    _phase = value;
    notifyListeners();
  }

  bool get active => ![
        TransferPhase.complete,
        TransferPhase.unconfirmed,
        TransferPhase.failed,
        TransferPhase.cancelled
      ].contains(phase);
  double get fraction => totalBytes == 0
      ? (phase == TransferPhase.complete ? 1 : 0)
      : bytes / totalBytes;
  void updateBytes(int value) {
    if (value < bytes || value > totalBytes) {
      throw ArgumentError('Invalid transfer progress');
    }
    if (value != bytes) {
      bytes = value;
      final now = _clock();
      _samples.add((now, bytes));
      while (_samples.length > 2 &&
          now - _samples[1].$1 > const Duration(seconds: 5)) {
        _samples.removeAt(0);
      }
      // Very fast transfers must not accumulate an unbounded sample history.
      if (_samples.length > 256) _samples.removeAt(1);
      notifyListeners();
    }
  }

  bool get stalled =>
      phase == TransferPhase.transferring &&
      _clock() - _samples.last.$1 > const Duration(seconds: 5);
  double? get bytesPerSecond {
    if (phase != TransferPhase.transferring || stalled || _samples.length < 2) {
      return null;
    }
    final elapsed =
        (_samples.last.$1 - _samples.first.$1).inMilliseconds / 1000;
    if (elapsed < 1) return null;
    final speed = (_samples.last.$2 - _samples.first.$2) / elapsed;
    return speed > 0 ? speed : null;
  }

  Duration? get eta {
    final speed = bytesPerSecond;
    if (speed == null || bytes >= totalBytes) return null;
    return Duration(seconds: ((totalBytes - bytes) / speed).ceil());
  }

  String get status => switch (phase) {
        TransferPhase.waiting => 'Waiting for recipient',
        TransferPhase.preparing => 'Preparing to send (delivery not confirmed)',
        TransferPhase.transferring => stalled
            ? 'Waiting for data — time remaining unknown'
            : (uploading ? 'Uploading — received by peer' : 'Receiving'),
        TransferPhase.saving => 'Saving file',
        TransferPhase.complete =>
          uploading ? 'Delivered and saved by peer' : 'Saved',
        TransferPhase.unconfirmed => 'Queued — delivery unconfirmed',
        TransferPhase.failed =>
          problem ?? 'Transfer interrupted — send the file again',
        TransferPhase.cancelled => 'Cancelled',
      };
}

String formatTransferBytes(num bytes) {
  if (bytes < 1024) return '${bytes.round()} B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KiB';
  return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MiB';
}
