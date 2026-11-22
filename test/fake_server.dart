import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

/// A small stand-in for Winche Auth's REST API.
final class FakeAuthServer {
  final Map<String, ({String uid, String password, String? displayName})> users = {};
  final Map<String, String> refreshTokens = {};   // refresh token → uid
  final List<String> calls = [];
  bool down = false;
  final Set<String> mfaUsers = {};   // emails that need a second step
  final Map<String, List<int>?> photos = {};   // uid → uploaded photo
  final Map<String, ({String url, String source})> photoUrls = {};   // uid → the user's photoUrl
  int _next = 0;

  late final http.Client client = MockClient((request) async {
    final path = request.url.path.replaceFirst('/auth/v1/', '');
    calls.add(path);
    if (down) throw http.ClientException('connection refused');
    if (path == 'me/photo') {
      final uid = _uidOf(request);
      if (uid == null) return _error(401, 'UNAUTHENTICATED', 'Sign in first.');
      final email = users.entries.firstWhere((e) => e.value.uid == uid).key;
      photos[uid] = request.method == 'POST' ? request.bodyBytes : null;
      if (photos[uid] == null) {
        photoUrls.remove(uid);
      } else {
        photoUrls[uid] = (url: 'https://api.example.com/auth/v1/photos/p$uid', source: 'upload');
      }
      return http.Response(jsonEncode(_user(email)), 200, headers: {'content-type': 'application/json'});
    }
    final body = request.body.isEmpty ? <String, Object?>{} : jsonDecode(request.body) as Map<String, Object?>;
    switch (path) {
      case 'signUp':
        final email = body['email'] as String;
        if (users.containsKey(email)) return _error(409, 'EMAIL_EXISTS', 'An account with that email already exists.');
        if ((body['password'] as String).length < 10) return _error(400, 'WEAK_PASSWORD', 'Passwords need at least 10 characters.');
        users[email] = (uid: 'u${++_next}', password: body['password'] as String, displayName: body['displayName'] as String?);
        return _tokens(email);
      case 'signIn':
        final user = users[body['email']];
        if (user == null || user.password != body['password']) return _error(401, 'INVALID_CREDENTIALS', 'The email or password is wrong.');
        if (mfaUsers.contains(body['email'])) {
          return _error(401, 'MFA_REQUIRED', 'Enter the code.', details: {'mfaToken': 'mfa:${body['email']}', 'factors': ['totp', 'recovery']});
        }
        return _tokens(body['email'] as String);
      case 'signIn/mfa':
        final token = body['mfaToken'] as String;
        if (body['code'] != '123456') return _error(401, 'INVALID_MFA_CODE', "That code isn't right.");
        return _tokens(token.substring(4));
      case 'signIn/anonymous':
        final email = 'guest${++_next}';
        users[email] = (uid: 'g$_next', password: '', displayName: null);
        return _tokens(email, anonymous: true);
      case 'signIn/custom':
        if (body['token'] != 'good-custom-token') return _error(401, 'INVALID_CUSTOM_TOKEN', "The custom token isn't valid.");
        users['ext'] = (uid: 'ext-42', password: '', displayName: null);
        return _tokens('ext');
      case 'token':
        final uid = refreshTokens.remove(body['refreshToken']);
        if (uid == null) return _error(401, 'INVALID_REFRESH_TOKEN', 'The session has ended.');
        return _tokens(users.entries.firstWhere((e) => e.value.uid == uid).key);
      case 'signOut':
        refreshTokens.remove(body['refreshToken']);
        return http.Response('', 204);
      case 'me':
        if (request.method == 'PATCH') {
          final uid = _uidOf(request);
          final email = users.entries.firstWhere((e) => e.value.uid == uid).key;
          // A patch, as on the server: a field left out stays, an explicit null clears it.
          final old = users[email]!;
          users[email] = (
            uid: uid!,
            password: old.password,
            displayName: body.containsKey('displayName') ? body['displayName'] as String? : old.displayName,
          );
          if (body.containsKey('photoUrl')) {
            final url = body['photoUrl'] as String?;
            photos.remove(uid);
            if (url == null) {
              photoUrls.remove(uid);
            } else {
              photoUrls[uid] = (url: url, source: 'link');
            }
          }
          return http.Response(jsonEncode(_user(email)), 200, headers: {'content-type': 'application/json'});
        }
        return http.Response('', 204);
      case 'providers':
        return http.Response(jsonEncode({
          'emailPassword': true, 'emailLink': false, 'anonymous': true,
          'providers': [{'name': 'google', 'kind': 'google', 'displayName': 'Google'}],
        }), 200);
    }
    return _error(404, 'NOT_FOUND', 'No such endpoint: $path');
  });

  /// Ends every session of [uid], as disabling them on the server would.
  void revoke(String uid) => refreshTokens.removeWhere((_, u) => u == uid);

  String? _uidOf(http.Request request) {
    final token = request.headers['Authorization']?.substring(7);
    if (token == null) return null;
    final payload = jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(token.split('.')[1])))) as Map<String, Object?>;
    return payload['uid'] as String?;
  }

  Map<String, Object?> _user(String email, {bool anonymous = false}) {
    final u = users[email]!;
    return {
      'uid': u.uid, 'email': anonymous ? null : email, 'emailVerified': false, 'displayName': u.displayName,
      'photoUrl': photoUrls[u.uid]?.url, 'photoSource': photoUrls[u.uid]?.source,
      'isAnonymous': anonymous, 'providers': [anonymous ? 'anonymous' : 'password'], 'customClaims': <String, Object?>{},
      'createdAt': '2026-11-12T10:00:00Z', 'lastSignInAt': '2026-11-12T10:00:00Z',
    };
  }

  http.Response _tokens(String email, {bool anonymous = false}) {
    final u = users[email]!;
    final refresh = 'r${++_next}';
    refreshTokens[refresh] = u.uid;
    final payload = base64Url.encode(utf8.encode(jsonEncode({'uid': u.uid, 'sub': u.uid, 'n': _next}))).replaceAll('=', '');
    return http.Response(jsonEncode({
      'accessToken': 'h.$payload.s', 'expiresIn': 900, 'expiresAt': '2026-11-12T10:15:00Z', 'refreshToken': refresh,
      'user': _user(email, anonymous: anonymous),
    }), 200, headers: {'content-type': 'application/json'});
  }

  /// As Winche Auth answers: the shared kind as `code`, its own code as `reason`.
  static http.Response _error(int status, String reason, String message, {Map<String, Object?>? details}) =>
      http.Response(
          jsonEncode({
            'error': {'code': _kind[status] ?? 'invalid-argument', 'reason': reason, 'message': message, 'details': ?details},
          }),
          status,
          headers: {'content-type': 'application/json'});

  static const _kind = {400: 'invalid-argument', 401: 'unauthenticated', 403: 'permission-denied', 404: 'not-found', 409: 'already-exists', 429: 'resource-exhausted'};
}
