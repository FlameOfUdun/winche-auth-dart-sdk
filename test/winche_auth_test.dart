import 'dart:async';

import 'package:test/test.dart';
import 'package:winche_auth/winche_auth.dart';
import 'package:winche_core/testing.dart';
import 'package:winche_core/winche_core.dart';

import 'fake_server.dart';

void main() {
  final options = WincheOptions(baseUrl: Uri.parse('https://api.test'));
  late FakeAuthServer server;
  late DateTime now;
  var appCount = 0;

  setUp(() {
    server = FakeAuthServer();
    now = DateTime.utc(2026, 11, 12, 10);
  });

  WincheApp newApp() => WincheApp('test-${appCount++}', options: options);
  WincheAuth authFor(WincheApp app, {WincheAuthStorage? storage}) =>
      WincheAuth.instanceFor((app..http.useClient(server.client)), storage: storage, clock: () => now);

  test('honours the winche_core auth contract', () async {
    final report = await WincheAuthContract.check(
      options: options,
      create: (app) => WincheAuth.instanceFor(app..http.useClient(server.client)),
      signIn: (auth) async {
        server.users['ann@example.com'] = (uid: 'u-ann', password: 'correct horse battery', displayName: null);
        await (auth as WincheAuth).signInWithEmail('ann@example.com', 'correct horse battery');
      },
      signOut: (auth) => (auth as WincheAuth).signOut(),
      induceTransientTokenFailure: (auth) async => server.down = true,
    );
    expect(report.isSuccess, isTrue, reason: report.toString());
  });

  test('signs up and in, and reports server errors by code', () async {
    final app = newApp();
    final auth = authFor(app);
    final user = await auth.signUpWithEmail('ann@example.com', 'correct horse battery', displayName: 'Ann');
    expect(user.uid, 'u1');
    expect(user.displayName, 'Ann');
    expect(auth.currentUser?.email, 'ann@example.com');
    await app.settled;
    expect(auth.activeIdentity?.id, 'u1');
    expect((await auth.getTokenClaims())?['uid'], 'u1');

    await expectLater(auth.signUpWithEmail('ann@example.com', 'another long one'),
        throwsA(isA<WincheAuthException>().having((e) => e.reason, 'reason', WincheAuthReason.emailExists).having((e) => e.code, 'code', WincheErrorCode.alreadyExists).having((e) => e.statusCode, 'status', 409)));
    await expectLater(auth.signInWithEmail('ann@example.com', 'wrong password'),
        throwsA(isA<WincheAuthException>().having((e) => e.reason, 'reason', WincheAuthReason.invalidCredentials).having((e) => e.isTransient, 'transient', false)));
    await app.dispose();
  });

  test('stays signed in across launches, without the network', () async {
    final storage = WincheMemoryAuthStorage();
    final first = newApp();
    server.users['ann@example.com'] = (uid: 'u-ann', password: 'correct horse battery', displayName: null);
    await authFor(first, storage: storage).signInWithEmail('ann@example.com', 'correct horse battery');
    await first.dispose();

    server.down = true;
    final second = WincheApp(first.name, options: options);
    final auth = authFor(second, storage: storage);
    await auth.ready;
    expect(auth.currentUser?.uid, 'u-ann');
    expect(await auth.getAuthToken(), isNotNull);   // still fresh: no network needed
    await second.settled;
    expect(auth.activeIdentity?.id, 'u-ann');
    await second.dispose();
  });

  test('refreshes shortly before expiry, once for concurrent callers', () async {
    final app = newApp();
    final auth = authFor(app);
    await auth.signUpWithEmail('ann@example.com', 'correct horse battery');
    final first = await auth.getAuthToken();
    expect(server.calls.where((c) => c == 'token'), isEmpty);

    now = now.add(const Duration(minutes: 14, seconds: 30));   // inside the refresh margin
    final results = await Future.wait([auth.getAuthToken(), auth.getAuthToken(), auth.getAuthToken()]);
    expect(server.calls.where((c) => c == 'token'), hasLength(1));
    expect(results.toSet(), hasLength(1));
    expect(results.first, isNot(first));
    expect(await auth.getAuthToken(), results.first);   // fresh again
    await app.dispose();
  });

  test('a revoked session signs out; a dropped connection does not', () async {
    final app = newApp();
    final auth = authFor(app);
    final changes = <String?>[];
    final sub = auth.authStateChanges().listen((u) => changes.add(u?.uid));
    await auth.signUpWithEmail('ann@example.com', 'correct horse battery');

    server.down = true;
    await expectLater(auth.getAuthToken(forceRefresh: true),
        throwsA(isA<WincheAuthException>().having((e) => e.isTransient, 'transient', true)));
    expect(auth.currentUser, isNotNull);

    server.down = false;
    server.revoke('u1');
    expect(await auth.getAuthToken(forceRefresh: true), isNull);
    expect(auth.currentUser, isNull);
    await app.settled;
    expect(auth.activeIdentity, isNull);
    await pumpEventQueue();
    expect(changes, [null, 'u1', null]);
    await sub.cancel();
    await app.dispose();
  });

  test('signing out works offline; profile updates reach userChanges', () async {
    final app = newApp();
    final auth = authFor(app);
    await auth.signUpWithEmail('ann@example.com', 'correct horse battery');
    final names = <String?>[];
    final sub = auth.userChanges().listen((u) => names.add(u?.displayName));
    await pumpEventQueue();
    await auth.updateProfile(displayName: 'Ann K');
    expect(auth.currentUser?.displayName, 'Ann K');

    server.down = true;
    await auth.signOut();
    expect(auth.currentUser, isNull);
    expect(await auth.getAuthToken(), isNull);
    await pumpEventQueue();
    expect(names, [null, 'Ann K', null]);
    await expectLater(auth.updateProfile(displayName: 'x'), throwsA(isA<WincheUnboundException>()));
    await sub.cancel();
    await app.dispose();
  });

  test('guests, providers and link codes', () async {
    final app = newApp();
    final auth = authFor(app);
    final guest = await auth.signInAnonymously();
    expect(guest.isAnonymous, isTrue);
    await expectLater(
      auth.signInWithCustomToken('forged'),
      throwsA(isA<WincheAuthException>().having((e) => e.reason, 'reason', WincheAuthReason.invalidCustomToken)),
    );
    expect((await auth.signInWithCustomToken('good-custom-token')).uid, 'ext-42');
    final providers = await auth.providers();
    expect(providers.anonymous, isTrue);
    expect(providers.providers.single.name, 'google');

    expect(WincheAuth.codeFrom('https://api.test/auth/v1/action?mode=resetPassword&code=abc_123'), 'abc_123');
    expect(WincheAuth.codeFrom('myapp://finish?mode=signIn&code=xyz'), 'xyz');
    expect(WincheAuth.codeFrom('https://api.test/auth/v1/action#mode=verifyEmail&code=frag_1'), 'frag_1');
    expect(WincheAuth.codeFrom('  plain-code '), 'plain-code');
    await app.dispose();
  });

  test('two-step sign-in: the first step throws, resolveMfa finishes', () async {
    final app = newApp();
    final auth = authFor(app);
    server.users['ann@example.com'] = (uid: 'u-ann', password: 'correct horse battery', displayName: null);
    server.mfaUsers.add('ann@example.com');

    WincheMfaRequiredException? required;
    try {
      await auth.signInWithEmail('ann@example.com', 'correct horse battery');
    } on WincheMfaRequiredException catch (e) {
      required = e;
    }
    expect(required?.factors, ['totp', 'recovery']);
    expect([required?.code, required?.reason], [WincheErrorCode.unauthenticated, WincheAuthReason.mfaRequired]);
    expect(auth.currentUser, isNull);   // not signed in yet

    await expectLater(auth.resolveMfa(required!, '000000'),
        throwsA(isA<WincheAuthException>().having((e) => e.reason, 'reason', WincheAuthReason.invalidMfaCode)));
    final user = await auth.resolveMfa(required, '123456');
    expect(user.uid, 'u-ann');
    expect(auth.currentUser?.uid, 'u-ann');
    await app.dispose();
  });

  test('a clear message when no auth endpoint is set', () async {
    final app = WincheApp('no-endpoint', options: const WincheOptions());
    final auth = WincheAuth.instanceFor(app..http.useClient(server.client));
    await expectLater(auth.signInAnonymously(), throwsA(isA<StateError>()));
    await app.dispose();
  });

  test('its errors are WincheExceptions with a reason, and an unreachable server is unavailable', () async {
    final app = newApp();
    final auth = authFor(app);
    await expectLater(auth.signInWithEmail('nobody@example.com', 'whatever long'),
        throwsA(isA<WincheException>().having((e) => e.code, 'code', WincheErrorCode.unauthenticated).having((e) => (e as WincheAuthException).reason, 'reason', 'INVALID_CREDENTIALS')));
    server.down = true;
    await expectLater(auth.signInWithEmail('nobody@example.com', 'whatever long'),
        throwsA(isA<WincheAuthException>().having((e) => e.code, 'code', WincheErrorCode.unavailable).having((e) => e.isTransient, 'transient', true)));
    await app.dispose();
  });

  test('a server failure or a limit on refreshing never signs the user out; an ended session does', () async {
    final app = newApp();
    final auth = authFor(app);
    server.users['ann@example.com'] = (uid: 'u-ann', password: 'correct horse battery', displayName: null);
    await auth.signInWithEmail('ann@example.com', 'correct horse battery');
    server.down = true;
    await expectLater(auth.getAuthToken(forceRefresh: true), throwsA(isA<WincheAuthException>()));
    expect(auth.currentUser, isNotNull);
    server.down = false;
    server.refreshTokens.clear();   // the server forgets the session
    expect(await auth.getAuthToken(forceRefresh: true), isNull);
    expect(auth.currentUser, isNull);
    await app.dispose();
  });
}
