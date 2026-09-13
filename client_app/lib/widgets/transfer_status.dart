import 'dart:async';
import 'package:flutter/material.dart';
import '../services/transfer_progress.dart';
import '../theme/cypher_theme.dart';

class TransferStatus extends StatefulWidget {
  const TransferStatus({super.key, required this.progress, this.onCancel});
  final TransferProgress progress;
  final VoidCallback? onCancel;
  @override
  State<TransferStatus> createState() => _TransferStatusState();
}

class _TransferStatusState extends State<TransferStatus> {
  Timer? _timer;
  bool _dirty = true;
  @override
  void initState() {
    super.initState();
    widget.progress.addListener(_changed);
    _startTimer();
  }

  void _startTimer() {
    if (_timer?.isActive == true) return;
    _timer = Timer.periodic(const Duration(milliseconds: 250), (_) {
      if (mounted && (_dirty || widget.progress.active)) {
        _dirty = false;
        setState(() {});
      }
      if (!widget.progress.active) {
        _timer?.cancel();
      }
    });
  }

  void _changed() {
    _dirty = true;
    _startTimer();
  }

  @override
  void didUpdateWidget(TransferStatus oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.progress != widget.progress) {
      oldWidget.progress.removeListener(_changed);
      widget.progress.addListener(_changed);
      _dirty = true;
      _startTimer();
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    widget.progress.removeListener(_changed);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.progress;
    final speed = p.bytesPerSecond;
    final eta = p.eta;
    final detail =
        '${formatTransferBytes(p.bytes)} / ${formatTransferBytes(p.totalBytes)}'
        '${speed == null ? '' : ' · ${formatTransferBytes(speed)}/s'}'
        '${eta == null ? '' : ' · About ${eta.inSeconds < 60 ? '${eta.inSeconds}s' : '${(eta.inSeconds / 60).ceil()} min'} left'}';
    return Semantics(
      label: '${p.uploading ? 'Upload' : 'Download'} ${p.name}',
      value: '${p.status}. $detail',
      child: Container(
        margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
            color: VaultXColors.backgroundPanel,
            border: Border.all(color: VaultXColors.border)),
        child: DefaultTextStyle(
          style: const TextStyle(
              fontFamily: VaultXFonts.mono,
              fontSize: 11,
              color: VaultXColors.phosphor),
          child:
              Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Row(children: [
              Expanded(
                  child: Text('${p.uploading ? '↑' : '↓'} ${p.name}',
                      maxLines: 1, overflow: TextOverflow.ellipsis)),
              if (p.active && widget.onCancel != null)
                GestureDetector(
                    onTap: widget.onCancel,
                    child: const Padding(
                        padding: EdgeInsets.all(6), child: Text('[ CANCEL ]'))),
            ]),
            Text(p.status),
            const SizedBox(height: 6),
            SizedBox(
                height: 4,
                child: ColoredBox(
                    color: VaultXColors.border,
                    child: Align(
                        alignment: Alignment.centerLeft,
                        child: FractionallySizedBox(
                            widthFactor: p.fraction.clamp(0, 1),
                            child: const ColoredBox(
                                color: VaultXColors.phosphor,
                                child: SizedBox.expand()))))),
            const SizedBox(height: 6),
            Text(detail,
                style: const TextStyle(color: VaultXColors.phosphorDim)),
          ]),
        ),
      ),
    );
  }
}
