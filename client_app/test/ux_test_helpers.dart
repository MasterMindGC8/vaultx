// Shared helpers for the UX simulation test suite.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

/// `find.textContaining` only matches plain [Text] widgets, not [RichText]
/// — and most of this app's screens compose their text as [RichText] (see
/// `TerminalTextField`'s `>>` prefix, `_MessageLine`, `TerminalPrompt`), so
/// the built-in finder silently finds nothing on this app's real UI. This
/// checks both.
Finder findTextContaining(String substring) {
  return find.byWidgetPredicate((widget) {
    if (widget is Text) {
      return widget.data?.contains(substring) ?? false;
    }
    if (widget is RichText) {
      return widget.text.toPlainText().contains(substring);
    }
    return false;
  });
}

/// Taps the `[ LABEL ]`-styled AsciiButton with this label, then lets any
/// real (non-fake-clock) async work the tap triggered — file I/O, FFI,
/// network — actually run before rebuilding. `tester.pump(duration)` alone
/// only advances Dart's fake `Timer`/`Future.delayed` clock; genuine I/O
/// (e.g. `Directory.create`, an HTTP call) needs `runAsync` to get real
/// event-loop turns, per Flutter's own testing guidance.
Future<void> tapAsciiButton(WidgetTester tester, String label) async {
  await tester.tap(find.text('[ ${label.toUpperCase()} ]'));
  // Deliberately fake-clock only (no runAsync/pumpAndSettle): a screen
  // this navigates to may kick off real background work of its own (e.g.
  // ConversationScreen's relay connection attempt) that never resolves
  // under a fake clock and is fine left pending — but mixing runAsync's
  // real-time waiting with pumpAndSettle here made the resulting frame
  // count/timing vary run to run, occasionally settling on a torn-down
  // tree. Callers that specifically need real I/O to complete (e.g.
  // Directory.create from a fresh vault check) should follow up with an
  // explicit settleReal instead.
  await settleUi(tester, steps: 12, step: const Duration(milliseconds: 50));
}

/// Lets real (non-fake-clock) async work run, then rebuilds. See
/// [tapAsciiButton]'s doc for why this differs from a plain `tester.pump`.
Future<void> settleReal(
  WidgetTester tester, {
  Duration duration = const Duration(milliseconds: 400),
}) async {
  await tester.runAsync(() => Future.delayed(duration));
  await tester.pump(const Duration(milliseconds: 100));
}

/// Advances the fake clock in many small steps rather than one large jump.
///
/// `pump(bigDuration)` elapses the *entire* duration in one shot before
/// drawing a single frame — so a `setState` that only fires partway through
/// (e.g. `TerminalScreen`'s boot loop revealing line by line, or a freshly
/// mounted `TerminalPrompt` starting its own typewriter `Timer.periodic`)
/// gets its state change applied, but any *new* timer that state change's
/// widget rebuild schedules is only created at the very end of that single
/// elapse, with none of the "remaining" duration left for it to tick
/// through. Looping many small pumps instead interleaves elapse and
/// frame-draw, so newly mounted timers get their own turns too.
Future<void> settleUi(
  WidgetTester tester, {
  int steps = 20,
  Duration step = const Duration(milliseconds: 250),
}) async {
  for (var i = 0; i < steps; i++) {
    await tester.pump(step);
  }
}
