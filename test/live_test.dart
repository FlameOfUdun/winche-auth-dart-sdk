@Tags(['live'])
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:test/test.dart';
import 'package:winche_auth/winche_auth.dart';
import 'package:winche_core/winche_core.dart';

/// Against a running emulator: `winche emulators start`, then
/// `WINCHE_EMULATOR=localhost:9090 dart test --tags live`.
void main() {
  final target = Platform.environment['WINCHE_EMULATOR'];
  final skip = target == null ? 'set WINCHE_EMULATOR=host:port with `winche emulators start` running' : false;

  test('signs up, refreshes, signs in with a fake Google token, and out', () async {
    final host = target!.split(':');
    final app = WincheApp('live-${DateTime.now().microsecondsSinceEpoch}',
        options: WincheOptions.emulator(host: host[0], port: int.parse(host[1])));
    final auth = WincheAuth.instanceFor(app);
    final email = 'dart-${DateTime.now().microsecondsSinceEpoch}@example.com';

    final user = await auth.signUpWithEmail(email, 'live-secret', displayName: 'Dart Test');
    expect(user.email, email);
    expect((await auth.getTokenClaims())?['uid'], user.uid);
    final refreshed = await auth.getAuthToken(forceRefresh: true);
    expect((await auth.getTokenClaims())?['email'], email);
    expect(refreshed, isNotNull);

    await expectLater(auth.signInWithEmail(email, 'wrong-secret'),
        throwsA(isA<WincheAuthException>().having((e) => e.reason, 'reason', WincheAuthReason.invalidCredentials)));

    // The emulator accepts unsigned Google tokens for audience "winche-emulator".
    String b64(Object o) => base64Url.encode(utf8.encode(jsonEncode(o))).replaceAll('=', '');
    final idToken = '${b64({'alg': 'none'})}.${b64({
      'iss': 'https://accounts.google.com', 'aud': 'winche-emulator', 'sub': 'dart-${DateTime.now().microsecondsSinceEpoch}',
      'email': 'g-$email', 'email_verified': true, 'exp': DateTime.now().add(const Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000,
    })}.';
    final google = await auth.signInWithIdToken('google', idToken);
    expect(google.providers, ['google']);
    expect(google.emailVerified, isTrue);
    await app.settled;
    expect(auth.activeIdentity?.id, google.uid);

    await auth.signOut();
    expect(auth.currentUser, isNull);
    await app.dispose();
  }, skip: skip);

  test('adds an authenticator app; sign-in then needs its code', () async {
    final host = target!.split(':');
    final app = WincheApp('live-mfa-${DateTime.now().microsecondsSinceEpoch}',
        options: WincheOptions.emulator(host: host[0], port: int.parse(host[1])));
    final auth = WincheAuth.instanceFor(app);
    final email = 'mfa-${DateTime.now().microsecondsSinceEpoch}@example.com';
    await auth.signUpWithEmail(email, 'live-secret');

    final enrollment = await auth.startTotpEnrollment();
    expect(enrollment.otpauthUri.scheme, 'otpauth');
    final recovery = await auth.confirmTotpEnrollment(totp(enrollment.secret));
    expect(recovery, hasLength(10));
    expect(auth.currentUser?.mfaEnabled, isTrue);
    expect((await auth.mfaStatus()).recoveryCodesLeft, 10);
    await auth.signOut();

    WincheMfaRequiredException? required;
    try {
      await auth.signInWithEmail(email, 'live-secret');
    } on WincheMfaRequiredException catch (e) {
      required = e;
    }
    expect(required, isNotNull);
    await auth.resolveMfa(required!, recovery.first);   // the app's code was used at enrolment; a recovery code works now
    expect((await auth.getTokenClaims())?['mfa'], isTrue);
    expect((await auth.mfaStatus()).recoveryCodesLeft, 9);

    await auth.disableMfa(recovery[1]);
    expect(auth.currentUser?.mfaEnabled, isFalse);
    await app.dispose();
  }, skip: skip);
}

/// The authenticator app's current code (RFC 6238).
String totp(String base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  final bytes = <int>[];
  var buffer = 0, bits = 0;
  for (final c in base32.split('')) {
    buffer = (buffer << 5) | alphabet.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bytes.add((buffer >> (bits - 8)) & 0xFF);
      bits -= 8;
    }
  }
  final step = DateTime.now().millisecondsSinceEpoch ~/ 1000 ~/ 30;
  final counter = List<int>.generate(8, (i) => (step >> (8 * (7 - i))) & 0xFF);
  final hash = Hmac(sha1, bytes).convert(counter).bytes;
  final o = hash.last & 0x0F;
  final value = ((hash[o] & 0x7F) << 24) | (hash[o + 1] << 16) | (hash[o + 2] << 8) | hash[o + 3];
  return (value % 1000000).toString().padLeft(6, '0');
}
