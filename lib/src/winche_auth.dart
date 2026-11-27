import 'dart:async';
import 'dart:convert';

import 'package:winche_core/winche_core.dart';

import 'exception.dart';
import 'models.dart';
import 'storage.dart';

/// Signs users in to Winche Auth and keeps their tokens fresh for the app's
/// other Winche services (`winche_database`, `winche_storage`).
///
/// ```dart
/// Winche.initializeApp(options: WincheOptions(baseUrl: Uri.parse('https://api.example.com')));
/// final auth = WincheAuth.instance;   // or WincheAuth.instanceFor(app, storage: SecureAuthStorage())
/// await auth.signInWithEmail('ann@example.com', 'correct horse battery');
/// auth.authStateChanges().listen((user) => …);
/// ```
///
/// The session is kept in a [WincheAuthStorage] (memory by default: pass a
/// secure one to stay signed in between launches) and restored on start,
/// without the network. Access tokens last minutes; [getAuthToken] refreshes
/// one shortly before it expires, one refresh at a time.
///
/// Only an answer from the server ends a session (the refresh token was
/// revoked, the user disabled or deleted); a dropped connection never does —
/// [getAuthToken] throws instead, as `winche_core` requires.
final class WincheAuth extends WincheService with WincheIdentitySource {
  /// Refresh when the access token has less than this left.
  static const Duration refreshMargin = Duration(seconds: 60);

  final WincheAuthStorage _storage;
  final DateTime Function() _now;

  _Session? _session;
  Future<String?>? _refreshing;
  late final Future<void> ready = _restore();
  bool _unread = false;   // the saved session couldn't be read yet (a locked keychain)
  bool _deletePending = false;   // signed out while it couldn't be deleted (locked): deleted when it can be
  Future<void>? _rereading;
  int _changes = 0;   // sessions set here: a later read never overrides one
  final StreamController<WincheUser?> _authChanges = StreamController<WincheUser?>.broadcast(sync: true);
  final StreamController<WincheUser?> _userChanges = StreamController<WincheUser?>.broadcast(sync: true);

  WincheAuth._(super.app, {WincheAuthStorage? storage, DateTime Function()? clock})
      : _storage = storage ?? WincheMemoryAuthStorage(),
        _now = clock ?? DateTime.now {
    unawaited(ready);
  }

  /// The auth service of the default app, created on first use.
  static WincheAuth get instance => instanceFor(Winche.app);

  /// The auth service of [app], created on first use with [storage] (where the
  /// session is kept; memory by default). Later calls return the same service
  /// and ignore it. Requests go through `app.http`: tests replace the network
  /// with `app.http.useClient`.
  static WincheAuth instanceFor(WincheApp app, {WincheAuthStorage? storage, DateTime Function()? clock}) {
    return WincheService.instanceFor(app, () => WincheAuth._(app, storage: storage, clock: clock));
  }

  // ── state ─────────────────────────────────────────────────────────────────

  /// The signed-in user, or null. Null until [ready] completes.
  WincheUser? get currentUser => _session?.user;

  @override
  WincheIdentity? get activeIdentity => _session?.identity;

  /// The signed-in user now, then whenever someone signs in or out.
  Stream<WincheUser?> authStateChanges() => _replaying(_authChanges);

  /// The signed-in user now, then on every change: sign-in, sign-out, and
  /// changes to their profile, email or sign-in methods.
  Stream<WincheUser?> userChanges() => _replaying(_userChanges);

  // ── tokens ────────────────────────────────────────────────────────────────

  @override
  Future<String?> getAuthToken({bool forceRefresh = false}) async {
    await ready;
    if (_deletePending) await _retryDelete();
    if (_unread) await (_rereading ??= _restore().whenComplete(() => _rereading = null));
    final session = _session;
    if (session == null) return null;
    if (!forceRefresh && session.expiresAt.difference(_now()) > refreshMargin) return session.accessToken;
    return _refreshing ??= _refresh(session).whenComplete(() => _refreshing = null);
  }

  /// The signed-in user's token claims (uid, email, custom claims, …), decoded
  /// from the current access token without checking it.
  Future<Map<String, Object?>?> getTokenClaims({bool forceRefresh = false}) async {
    final token = await getAuthToken(forceRefresh: forceRefresh);
    if (token == null) return null;
    final payload = token.split('.')[1];
    return jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(payload)))) as Map<String, Object?>;
  }

  Future<String?> _refresh(_Session session) async {
    final Map<String, Object?> body;
    try {
      body = await _post('token', {'refreshToken': session.refreshToken});
    } on WincheAuthException catch (e) {
      if (_endsSession(e) && identical(_session, session)) {
        // The server says this session is over: an authoritative sign-out.
        await _setSession(null);
        return null;
      }
      rethrow;
    }
    if (!identical(_session, session)) return getAuthToken();   // signed out or switched meanwhile
    await _setSession(_Session.fromTokens(body, _now()));
    return _session?.accessToken;
  }

  /// Whether a refusal of the refresh token is the server saying this session
  /// is over (revoked, the user disabled or deleted). Anything else — no
  /// answer, a server failure, too many attempts — leaves the user signed in.
  static bool _endsSession(WincheAuthException e) =>
      e.code == WincheErrorCode.unauthenticated || e.code == WincheErrorCode.permissionDenied || e.code == WincheErrorCode.notFound;

  // ── signing in ────────────────────────────────────────────────────────────

  /// What this app's server offers: email and password, email links,
  /// anonymous, and which Google, Apple or OpenID Connect providers.
  Future<WincheAuthProviders> providers() async => WincheAuthProviders.fromJson(await _get('providers'));

  /// Creates an account and signs in. When the server requires a verified email,
  /// this throws `EMAIL_NOT_VERIFIED`: the account exists and a link is on its way.
  Future<WincheUser> signUpWithEmail(String email, String password, {String? displayName}) =>
      _signIn('signUp', {'email': email, 'password': password, 'displayName': ?displayName});

  Future<WincheUser> signInWithEmail(String email, String password) =>
      _signIn('signIn', {'email': email, 'password': password});

  /// Signs in as a new guest. Link a password or provider later to keep the account.
  Future<WincheUser> signInAnonymously() => _signIn('signIn/anonymous', const {});

  /// Signs in with a custom token from the app's own server (made there with
  /// `IWincheAuth.CreateCustomTokenAsync`), as the user it names.
  Future<WincheUser> signInWithCustomToken(String token) => _signIn('signIn/custom', {'token': token});

  /// Exchanges an ID token from Google Sign-In, Sign in with Apple or an
  /// OpenID Connect login for a Winche session. [provider] is `google`,
  /// `apple`, or the provider's name on the server; pass the raw [nonce] if
  /// you gave one to the provider.
  ///
  /// If an account with the same verified email exists, this throws
  /// `ACCOUNT_EXISTS_WITH_OTHER_METHOD`: sign in the old way and
  /// [linkWithIdToken].
  Future<WincheUser> signInWithIdToken(String provider, String idToken, {String? nonce}) =>
      _signIn('signIn/idp', {'provider': provider, 'idToken': idToken, 'nonce': ?nonce});

  /// Emails a one-time sign-in link (when the server has email links on).
  Future<void> sendSignInLink(String email) => _post('sendSignInLink', {'email': email});

  /// Finishes an email-link sign-in: pass the link the app was opened with, or its code.
  Future<WincheUser> signInWithEmailLink(String linkOrCode) => _signIn('signIn/link', {'code': codeFrom(linkOrCode)});

  /// Ends the session here and on the server. Signed out locally even if the
  /// server can't be reached.
  Future<void> signOut() async {
    await ready;
    final session = _session;
    if (session == null) {
      if (_unread) {
        // Signed out before the saved session could be read: never restore it.
        _unread = false;
        _changes++;
        _deletePending = true;
        await _retryDelete();
      }
      return;
    }
    await _setSession(null);
    try {
      await _post('signOut', {'refreshToken': session.refreshToken});
    } on WincheAuthException {
      // Signed out here; the server's session expires on its own.
    }
  }

  // ── two-step sign-in ──────────────────────────────────────────────────────

  /// Finishes a sign-in that threw [WincheMfaRequiredException], with a code
  /// from the user's authenticator app or one of their recovery codes.
  Future<WincheUser> resolveMfa(WincheMfaRequiredException required, String code) =>
      _signIn('signIn/mfa', {'mfaToken': required.mfaToken, 'code': code});

  /// Whether the signed-in user has two-step sign-in on.
  Future<WincheMfaStatus> mfaStatus() async {
    final body = await _authed((t) => _send('GET', 'me/mfa', null, token: t));
    return WincheMfaStatus(body['enabled'] as bool? ?? false, (body['recoveryCodesLeft'] as num?)?.toInt() ?? 0);
  }

  /// Starts adding an authenticator app: show the QR code, then
  /// [confirmTotpEnrollment] with the first code the app shows.
  Future<WincheTotpEnrollment> startTotpEnrollment() async {
    final body = await _authed((t) => _post('me/mfa/totp/start', const {}, token: t));
    return WincheTotpEnrollment(body['secret'] as String, Uri.parse(body['otpauthUri'] as String));
  }

  /// Turns two-step sign-in on and returns the recovery codes. Show them once,
  /// and ask the user to keep them somewhere safe.
  Future<List<String>> confirmTotpEnrollment(String code) async {
    final body = await _authed((t) => _post('me/mfa/totp/confirm', {'code': code}, token: t));
    await _refreshUser();
    return [for (final c in body['recoveryCodes'] as List<Object?>) c as String];
  }

  /// New recovery codes (the old ones stop working), with a current code.
  Future<List<String>> regenerateRecoveryCodes(String code) async {
    final body = await _authed((t) => _post('me/mfa/recoveryCodes', {'code': code}, token: t));
    return [for (final c in body['recoveryCodes'] as List<Object?>) c as String];
  }

  /// Turns two-step sign-in off, with a current code (or a recovery code).
  Future<void> disableMfa(String code) async {
    await _authed((t) => _post('me/mfa/disable', {'code': code}, token: t));
    await _refreshUser();
  }

  Future<void> _refreshUser() async {
    try {
      await _setUser(WincheUser.fromJson(await _authed((t) => _send('GET', 'me', null, token: t))));
    } on WincheAuthException {
      // Done on the server; currentUser catches up at the next reload.
    }
  }

  // ── emailed links ─────────────────────────────────────────────────────────

  /// Emails a reset link. The same answer whether or not the address has an account.
  Future<void> sendPasswordReset(String email) => _post('sendPasswordReset', {'email': email});

  /// Sets a new password with the code from a reset link. Every session ends:
  /// sign in again afterwards.
  Future<void> resetPassword(String linkOrCode, String newPassword) =>
      _post('resetPassword', {'code': codeFrom(linkOrCode), 'newPassword': newPassword});

  /// What a link's code is for, without using it.
  Future<WincheActionCodeInfo> checkActionCode(String linkOrCode) async {
    final body = await _post('action/check', {'code': codeFrom(linkOrCode)});
    return WincheActionCodeInfo(body['mode'] as String, body['email'] as String);
  }

  /// Uses a verify-email, confirm-new-email or undo-change code, then refreshes
  /// the signed-in user (if any).
  Future<WincheActionCodeInfo> applyActionCode(String linkOrCode) async {
    final body = await _post('action/apply', {'code': codeFrom(linkOrCode)});
    if (_session != null) {
      try {
        await reload();
      } on WincheAuthException {
        // Applied; the user refreshes next time.
      }
    }
    return WincheActionCodeInfo(body['mode'] as String, body['email'] as String);
  }

  // ── the signed-in user ────────────────────────────────────────────────────

  /// Emails the signed-in user a verify link.
  Future<void> sendEmailVerification() => _authed((t) => _post('sendVerification', const {}, token: t));

  /// Fetches the user again (after verifying the email elsewhere, say) and a
  /// fresh token carrying the change.
  Future<WincheUser?> reload() async {
    await getAuthToken(forceRefresh: true);
    return currentUser;
  }

  /// Changes the signed-in user's [displayName] and/or [photoUrl] (a link to
  /// a picture kept elsewhere). Only the fields passed change: fields left out
  /// stay as they are, so `updateProfile(displayName: 'Ann')` keeps the photo.
  /// [clearDisplayName] / [clearPhotoUrl] remove a field instead (not together
  /// with a new value for it). To remove a photo uploaded with [updatePhoto],
  /// use [removePhoto].
  Future<WincheUser> updateProfile({
    String? displayName,
    String? photoUrl,
    bool clearDisplayName = false,
    bool clearPhotoUrl = false,
  }) async {
    if (clearDisplayName && displayName != null) {
      throw ArgumentError('Pass displayName or clearDisplayName, not both.');
    }
    if (clearPhotoUrl && photoUrl != null) {
      throw ArgumentError('Pass photoUrl or clearPhotoUrl, not both.');
    }
    final patch = <String, Object?>{
      if (displayName != null || clearDisplayName) 'displayName': displayName,
      if (photoUrl != null || clearPhotoUrl) 'photoUrl': photoUrl,
    };
    final body = await _authed((t) => _send('PATCH', 'me', patch, token: t));
    await _setUser(WincheUser.fromJson(body));
    return currentUser!;
  }

  /// Uploads [image] as the signed-in user's photo, kept by Winche Auth: JPEG,
  /// PNG or WebP, at most 100 KB, so shrink it first (256 × 256 is plenty).
  /// [WincheUser.photoUrl] then points at it, a new address each time.
  Future<WincheUser> updatePhoto(List<int> image) async {
    final body = await _authed((t) => _send('POST', 'me/photo', null, token: t, bytes: image));
    await _setUser(WincheUser.fromJson(body));
    return currentUser!;
  }

  /// Removes the photo uploaded with [updatePhoto]; a sign-in provider's picture
  /// comes back at the next sign-in with it.
  Future<WincheUser> removePhoto() async {
    final body = await _authed((t) => _send('DELETE', 'me/photo', null, token: t));
    await _setUser(WincheUser.fromJson(body));
    return currentUser!;
  }

  /// Changes the password; the user's other sessions end, this one continues.
  Future<WincheUser> changePassword(String currentPassword, String newPassword) => _signIn(
      'me/password', {'currentPassword': currentPassword, 'newPassword': newPassword},
      authed: true);

  /// Emails [newEmail] a link; the change happens when it's opened (then
  /// [reload]), and the old address is told, with an undo link.
  Future<void> changeEmail(String newEmail) => _authed((t) => _post('me/email', {'newEmail': newEmail}, token: t));

  /// Gives a guest (or anyone) a password sign-in, keeping their uid.
  Future<WincheUser> linkWithPassword(String email, String password) =>
      _signIn('link/password', {'email': email, 'password': password}, authed: true);

  /// Links a Google, Apple or OpenID Connect account to the signed-in user.
  Future<WincheUser> linkWithIdToken(String provider, String idToken, {String? nonce}) =>
      _signIn('link/idp', {'provider': provider, 'idToken': idToken, 'nonce': ?nonce}, authed: true);

  /// Removes a provider from the signed-in user (never their last way in).
  Future<WincheUser> unlink(String provider) async {
    final body = await _authed((t) => _post('unlink', {'provider': provider}, token: t));
    await _setUser(WincheUser.fromJson(body));
    return currentUser!;
  }

  /// Deletes the signed-in user's account and signs out.
  Future<void> deleteAccount() async {
    await _authed((t) => _send('DELETE', 'me', null, token: t));
    await _setSession(null);
  }

  // ── plumbing ──────────────────────────────────────────────────────────────

  /// The code in an emailed link (`…#mode=…&code=…` for Winche's own page,
  /// `…?mode=…&code=…` for the app's), or [linkOrCode] itself.
  static String codeFrom(String linkOrCode) {
    final uri = Uri.tryParse(linkOrCode.trim());
    if (uri == null) return linkOrCode.trim();
    final fragment = uri.fragment.isEmpty ? const <String, String>{} : Uri.splitQueryString(uri.fragment);
    return fragment['code'] ?? uri.queryParameters['code'] ?? linkOrCode.trim();
  }

  Future<WincheUser> _signIn(String path, Map<String, Object?> body, {bool authed = false}) async {
    await ready;
    final tokens = authed ? await _authed((t) => _post(path, body, token: t)) : await _post(path, body);
    await _setSession(_Session.fromTokens(tokens, _now()));
    return currentUser!;
  }

  /// Runs [call] with the user's token. A bare `unauthenticated` (no reason)
  /// is Winche Auth refusing that token, its session ended or the token stale:
  /// one forced refresh tells which. If the refresh ends the session the user
  /// is signed out and the refusal is thrown; otherwise [call] runs once more
  /// with the new token. Refusals with a reason are thrown as they are.
  Future<T> _authed<T>(Future<T> Function(String token) call) async {
    final token = await getAuthToken();
    if (token == null) throw WincheUnboundException();
    final session = _session;
    try {
      return await call(token);
    } on WincheAuthException catch (e) {
      if (e.code != WincheErrorCode.unauthenticated || e.reason != null || !identical(_session, session)) rethrow;
      final fresh = await getAuthToken(forceRefresh: true);
      if (fresh == null || fresh == token) rethrow;
      // Someone else signed in while it refreshed: never retried as them.
      if (_session?.user.uid != session?.user.uid) rethrow;
      return call(fresh);
    }
  }

  Future<void> _setUser(WincheUser user) async {
    final session = _session;
    if (session == null) return;
    await _setSession(session.withUser(user));
  }

  /// A sign-out whose delete the storage refused (a locked keychain): the saved session is deleted now if it can be,
  /// and the server's session it names ended too; else left pending, tried again on the next token asked for.
  Future<void> _retryDelete() async {
    String? saved;
    final changes = _changes;
    try {
      saved = await _storage.read(_storageKey);
      // Signed in (or out) while it was read: what's saved now is that session's, never deleted here.
      if (_changes != changes || !_deletePending) return;
      await _storage.delete(_storageKey);
    } catch (_) {
      return;   // still locked
    }
    _deletePending = false;
    try {
      final refresh = saved == null ? null : _Session.fromJson(jsonDecode(saved) as Map<String, Object?>).refreshToken;
      if (refresh != null) await _post('signOut', {'refreshToken': refresh});
    } catch (_) {
      // Deleted here; the server's session expires on its own.
    }
  }

  /// Saves [next], then tells core and listeners what changed.
  Future<void> _setSession(_Session? next) async {
    final previous = _session;
    _session = next;
    _unread = false;
    _deletePending = false;   // what's saved now is this
    _changes++;
    if (next == null) {
      await _storage.delete(_storageKey);
    } else {
      await _storage.write(_storageKey, jsonEncode(next.toJson()));
    }
    if (previous?.user.uid != next?.user.uid) {
      notifyIdentityChanged(next?.identity);
      _authChanges.add(next?.user);
    } else if (next != null && previous?.accessToken != next.accessToken) {
      notifyTokenRotated();
    }
    _userChanges.add(next?.user);
  }

  /// Reads the saved session. If the storage can't be read now (a keychain
  /// locked while the app launches in the background), the session is kept
  /// and the user is signed out for now: [getAuthToken] reads it again. Only a
  /// saved value that isn't a session is deleted.
  Future<void> _restore() async {
    final changes = _changes;
    final String? saved;
    try {
      saved = await _storage.read(_storageKey);
    } catch (_) {
      _unread = _changes == changes;
      return;
    }
    if (_changes != changes) return;   // signed in or out meanwhile
    _unread = false;
    if (saved == null) return;
    final _Session session;
    try {
      session = _Session.fromJson(jsonDecode(saved) as Map<String, Object?>);
    } catch (_) {
      try {
        await _storage.delete(_storageKey);   // not a session: start signed out
      } catch (_) {}
      return;
    }
    if (_changes != changes) return;
    _session = session;
    notifyIdentityChanged(_session!.identity);
    _authChanges.add(_session!.user);
    _userChanges.add(_session!.user);
  }

  String get _storageKey => 'winche_auth.${app.name}';

  /// The service's id in `WincheOptions.endpoints`.
  static const serviceId = 'auth';

  Uri _endpoint(String path) {
    final base = (app.options ?? const WincheOptions()).endpointFor(serviceId, path: '/auth/v1');
    final prefix = base.path.endsWith('/') ? base.path : '${base.path}/';
    return base.replace(path: '$prefix$path');
  }

  Future<Map<String, Object?>> _get(String path) => _send('GET', path, null);

  Future<Map<String, Object?>> _post(String path, Map<String, Object?> body, {String? token}) => _send('POST', path, body, token: token);

  /// Through `app.http`, adding this service's own token where one is needed:
  /// its 401s mean a wrong password or a missing second step, not a stale
  /// token, and it refreshes tokens itself before they expire.
  Future<Map<String, Object?>> _send(String method, String path, Map<String, Object?>? body, {String? token, List<int>? bytes}) async {
    final WincheResponse response;
    try {
      response = await app.http.send(WincheRequest(method, _endpoint(path),
          json: body,
          bytes: bytes,
          headers: {
            'accept': 'application/json',
            if (bytes != null) 'content-type': 'application/octet-stream',
            'x-winche-client': 'winche_auth-dart',
            if (token != null) 'authorization': 'Bearer $token',
          },
          auth: WincheRequestAuth.none,
          service: serviceId));
    } on WincheHttpException catch (e) {
      throw WincheAuthException.from(e);
    }
    Object? json;
    try {
      json = response.json;
    } on FormatException {
      json = null;
    }
    return json is Map<String, Object?> ? json : const {};
  }

  Stream<WincheUser?> _replaying(StreamController<WincheUser?> source) {
    late final StreamController<WincheUser?> out;
    StreamSubscription<WincheUser?>? sub;
    out = StreamController<WincheUser?>(
      onListen: () async {
        await ready;   // currentUser reflects every change made before this point
        if (out.isClosed) return;
        out.add(currentUser);
        sub = source.stream.listen(out.add, onError: out.addError, onDone: out.close);
      },
      onCancel: () async => sub?.cancel(),
    );
    return out.stream;
  }

  @override
  Future<void> dispose() async {
    await _authChanges.close();
    await _userChanges.close();
    await super.dispose();
  }
}

final class _Session {
  final String accessToken;
  final DateTime expiresAt;
  final String refreshToken;
  final WincheUser user;

  _Session(this.accessToken, this.expiresAt, this.refreshToken, this.user);

  factory _Session.fromTokens(Map<String, Object?> body, DateTime now) => _Session(
        body['accessToken'] as String,
        now.add(Duration(seconds: (body['expiresIn'] as num?)?.toInt() ?? 900)),
        body['refreshToken'] as String,
        WincheUser.fromJson(body['user'] as Map<String, Object?>),
      );

  factory _Session.fromJson(Map<String, Object?> json) => _Session(
        json['accessToken'] as String,
        DateTime.parse(json['expiresAt'] as String),
        json['refreshToken'] as String,
        WincheUser.fromJson(json['user'] as Map<String, Object?>),
      );

  Map<String, Object?> toJson() => {
        'v': 1,
        'accessToken': accessToken,
        'expiresAt': expiresAt.toUtc().toIso8601String(),
        'refreshToken': refreshToken,
        'user': user.toJson(),
      };

  _Session withUser(WincheUser user) => _Session(accessToken, expiresAt, refreshToken, user);

  WincheIdentity get identity => WincheIdentity(user.uid, claims: {
        'email': ?user.email,
        'emailVerified': user.emailVerified,
        'displayName': ?user.displayName,
        'isAnonymous': user.isAnonymous,
        'providers': user.providers,
      });
}
