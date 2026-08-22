import 'dart:convert';
import 'dart:typed_data';

/// A saved contact: their opaque device ID and a friendly label. Persisted
/// as JSON in the vault under [contactsVaultKey] — this is metadata only
/// (no keys, no messages), so plain JSON is fine here even though the vault
/// encrypts it at rest regardless.
class Contact {
  const Contact({required this.deviceId, required this.label});

  final String deviceId;
  final String label;

  Map<String, dynamic> toJson() => {'deviceId': deviceId, 'label': label};

  factory Contact.fromJson(Map<String, dynamic> json) =>
      Contact(deviceId: json['deviceId'] as String, label: json['label'] as String);

  static const vaultKey = 'contacts_v1';

  static List<Contact> decodeList(List<int> bytes) {
    final decoded = jsonDecode(utf8.decode(bytes)) as List<dynamic>;
    return decoded
        .map((e) => Contact.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  static Uint8List encodeList(List<Contact> contacts) {
    return Uint8List.fromList(
      utf8.encode(jsonEncode(contacts.map((c) => c.toJson()).toList())),
    );
  }
}
