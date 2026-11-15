/// Where the signed-in session (its refresh token) is kept between launches.
///
/// Keep it somewhere private: on Flutter, `flutter_secure_storage` —
///
/// ```dart
/// final class SecureAuthStorage implements WincheAuthStorage {
///   final _store = const FlutterSecureStorage();
///   @override
///   Future<String?> read(String key) => _store.read(key: key);
///   @override
///   Future<void> write(String key, String value) => _store.write(key: key, value: value);
///   @override
///   Future<void> delete(String key) => _store.delete(key: key);
/// }
/// ```
abstract interface class WincheAuthStorage {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

/// Keeps the session in memory only: signed out on every launch. The default.
final class WincheMemoryAuthStorage implements WincheAuthStorage {
  final Map<String, String> _values = {};

  @override
  Future<String?> read(String key) async => _values[key];

  @override
  Future<void> write(String key, String value) async => _values[key] = value;

  @override
  Future<void> delete(String key) async => _values.remove(key);
}
