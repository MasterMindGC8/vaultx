# Vault X 1.6.6: chat reliability and status

This update improves chat reconnection and adds evidence-based delivery and
presence indicators without adding runtime dependencies.

## Using it

Open the existing **Vault X** desktop shortcut. Both people should use 1.6.6
and the same relay address. The installer for the other Windows PC is
`dist/VaultXSetup-1.6.6.exe`; its SHA-256 is in the adjacent `.sha256` file.
Close Vault X normally before running the installer. Existing vaults and
contacts are outside the application installation directory.

- **Green contact light:** an encrypted response was received recently.
- **Red:** offline or unreachable. A lost local relay connection also makes
  peers unreachable; this does not prove that their PC is switched off.
- **Grey:** presence has not been confirmed. Older clients cannot reliably
  answer presence probes. Responses are checked periodically, not instantly.
- **One tick:** the updated relay accepted the packet, including for an offline
  recipient. It does not mean the other app received it.
- **Two ticks:** the other updated app decrypted the message and returned an
  encrypted receipt. This is **not a human read receipt**.
- **X:** the send failed. Click Retry on the message.
- **Unconfirmed:** no positive receipt. Retry is also available here and on
  sent messages. Retries retain the message ID and use a new transport packet;
  the receiver deduplicates against its retained chat history.
- **Relay milliseconds:** measured HTTP health-response time, not the other
  person's ping. Failed measurements show a dash.
- **History ON:** saves chat history in the encrypted local vault.
- **History OFF:** clears saved text history and retains the conversation in
  memory until closing. Each updated app controls its own history; closing
  one does not request deletion on the other. This is not a secure-erasure
  guarantee for disk remnants, backups, or copies of received files. Legacy
  incoming wipe messages are still honored for protocol compatibility.

## Confirmed bugs addressed

1. Adding a contact that had already added you could overwrite the shared
   session, duplicate the contact, and reset visible history. Existing shared
   sessions and history are now retained.
2. A rejected encrypted packet changed ratchet state before authentication
   succeeded. A bad packet could therefore break subsequent valid messages,
   or consume a skipped message key. Decryption now commits state only after
   successful authentication; discarded states retain the existing zeroization
   behavior. Two regression tests failed before this change and pass after it.
3. Lost relay connections were not recovered automatically. Disconnects are
   detected and reconnection backs off through 2, 5, 10, then 30 seconds.
4. Saved contacts had no active chat keys after reopening. Saved chats now
   establish fresh sessions automatically, including when only one person
   restarts. Duplicate handshake processing is remembered in the encrypted
   vault with a bounded cache.
5. Connection/session existence was not evidence of the other app being
   online. Presence now uses encrypted requests and responses.

No runtime dependency was added. Receipt bookkeeping and replay caches are
bounded. This work did not benchmark throughput or claim a measured speedup.

## Verification

- Rust release tests: **22 passed**, including both rejected-packet regressions.
- Flutter tests with an empty scratch profile and real local relay: **35
  passed**. Static analysis: **no issues**.
- Go relay: `go test -race ./...` passed.
- Windows release build: passed. Packaged executable started without exiting
  during its isolated startup check; this was only a startup smoke test.
- Windows installer: compiled successfully and installed with exit code 0.
- Installation files were compared against the packaged SHA-256 manifest.
  Public release builds are checked by `.github/workflows/release.yml`.

The new two-user widget tests use two independently encrypted vaults and
identities, the real native crypto library, a real Go relay over loopback,
and a socket-forwarding proxy that can be disconnected. They exercise:

- adding each other sequentially and simultaneously, then re-adding;
- messages and replies, encrypted received receipts, and contact presence;
- disconnecting the network, failed sends, and clicking the visible retry text;
- history off/on, both apps reopening, and only one app reopening;
- retrying an old queued message after the recipient restarts, with one sender
  entry, followed by another live message.

These are actual Flutter UI interactions with live local networking, but they
are **not a successful two-physical-PC internet test**. Both widget clients
share a test process. No real users' messages or identities were used in these
tests. The release workflow already sets the test relay and scratch-profile
environment variables needed to run them.

## Compatibility and limitations

1. Update the other person's Windows app to 1.6.6. Mixed versions do not provide
   all these features, and an older app can still send its old exit-wipe request.
2. The relay must run the 1.6.6 change for single sent ticks.
   Double received ticks are end-to-end between the updated apps and can pass
   through an older relay. Without relay acceptance, the UI keeps delivery
   unconfirmed rather than inventing a sent confirmation.
3. Relay operators should verify the server architecture and deployment path
   and keep a rollback binary. Restarting the relay discards its RAM-only
   queue, so coordinate maintenance with users.
4. Offline messaging is not durable across all restarts. Chat keys live in
   memory; an old queued ciphertext can require a sender retry after the peer
   restarts. The new Retry path was tested for that case. If History was OFF
   and the sender also closed, the app cannot reconstruct the discarded text.
   Durable encrypted session/outbox storage is a separate future improvement.
5. Actual human read receipts and file-transfer resume across app restarts
   are not implemented by this update. These are possible later features,
   rather than silently expanding the current lightweight design.
6. A real two-PC test using the same public relay is still needed. Successful
   local tests do not rule out firewall, address, version, or public-service
   problems on either person's machine.

## Build and recovery

Keep a copy of the previous app and relay binaries before installing an update.
Use the release installer rather than any intermediate development builds.

The compiler was obtained from the [official Inno Setup download page](https://jrsoftware.org/isdl.php)
and its valid Pyrsys B.V. signature was checked. The bundled Microsoft runtime
installer was obtained from Microsoft's download endpoint and its Microsoft
signature was checked. The generated Vault X installer itself is not signed
with a Vault X publisher certificate.

The app's update manifest must point only to published, verified release
assets. CI builds Windows, macOS, and Linux artifacts before publication.
