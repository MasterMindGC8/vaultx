import 'package:flutter_test/flutter_test.dart';
import 'package:client_app/services/transfer_progress.dart';

void main() {
  test('ETA needs measured progress and becomes unknown when stalled', () {
    var now = Duration.zero;
    final p = TransferProgress(
        name: 'test.bin',
        totalBytes: 10000,
        uploading: false,
        clock: () => now);
    p.phase = TransferPhase.transferring;
    expect(p.eta, isNull);
    now = const Duration(seconds: 1);
    p.updateBytes(1000);
    now = const Duration(seconds: 2);
    p.updateBytes(2000);
    expect(p.bytesPerSecond, closeTo(1000, 1));
    expect(p.eta!.inSeconds, 8);
    now = const Duration(seconds: 9);
    expect(p.eta, isNull);
    expect(p.stalled, isTrue);
  });

  test('queueing and completion never claim an upload ETA', () {
    final p =
        TransferProgress(name: 'test.bin', totalBytes: 100, uploading: true);
    p.phase = TransferPhase.preparing;
    p.updateBytes(50);
    expect(p.eta, isNull);
    p.phase = TransferPhase.unconfirmed;
    expect(p.status, contains('unconfirmed'));
    expect(p.eta, isNull);
    expect(() => p.updateBytes(101), throwsArgumentError);
    expect(() => p.updateBytes(49), throwsArgumentError);
  });
}
