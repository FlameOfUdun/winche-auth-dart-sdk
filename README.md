# winche_auth

Dart client for [Winche Auth](https://github.com/FlameOfUdun/winche-auth): sign users in and keep their tokens fresh
for `winche_database` and `winche_storage`. Pure Dart, so it runs in Flutter apps on every platform, on the web and on
servers.

```dart
import 'package:winche_auth/winche_auth.dart';
import 'package:winche_core/winche_core.dart';

void main() async {
  Winche.initializeApp(options: WincheOptions(baseUrl: Uri.parse('https://api.example.com')));

  final auth = WincheAuth.instanceFor(Winche.app, storage: SecureAuthStorage());   // see "Staying signed in"
  auth.authStateChanges().listen((user) => print(user == null ? 'signed out' : 'signed in as ${user.uid}'));

  await auth.signInWithEmail('ann@example.com', 'correct horse battery');
}
```

`WincheDatabase.instance` and `WincheStorage.instance` pick the signed-in user up through `winche_core`: there's
nothing to wire.

Requests go to `/auth/v1` under the server's address (or `WincheOptions.endpoints['auth']`) through the app's shared
`app.http`; tests replace the network with `app.http.useClient`.

## Installation

```bash
dart pub add winche_core winche_auth
```

Or add them to `pubspec.yaml`:

```yaml
dependencies:
  winche_core: ^1.0.0
  winche_auth: ^0.1.0
```

`winche_core` is not optional. It owns the app, the endpoints and the session every Winche package binds to, so an
app always imports it directly.

## Signing in

| | |
|---|---|
| `signUpWithEmail(email, password, displayName:)` | a new account, signed in |
| `signInWithEmail(email, password)` | |
| `signInAnonymously()` | a guest; link a password or provider later to keep the account |
| `signInWithIdToken('google' / 'apple' / '<oidc name>', idToken, nonce:)` | exchange a provider's ID token |
| `sendSignInLink(email)`, `signInWithEmailLink(link)` | sign in from an emailed link |
| `signInWithCustomToken(token)` | a token from your own server (`IWincheAuth.CreateCustomTokenAsync`), as the user it names |
| `signOut()` | here and on the server (signed out here even offline) |
| `providers()` | what the server offers, for building a sign-in screen |

For Google and Apple, sign in with their own SDKs (`google_sign_in`, `sign_in_with_apple`) and pass the **ID token**
here. If an account with the same verified email already exists, sign-in throws
`ACCOUNT_EXISTS_WITH_OTHER_METHOD`: sign in the old way, then `linkWithIdToken`.

## The signed-in user

`currentUser` (uid, email, emailVerified, displayName, photoUrl, isAnonymous, providers, customClaims),
`authStateChanges()` (sign-in and out), `userChanges()` (any change), `getTokenClaims()`, `reload()`,
`updateProfile()`, `updatePhoto(bytes)` / `removePhoto()` (a small image Winche Auth keeps: shrink it to 256 × 256 first), `changePassword()`, `changeEmail()` (the new address confirms; the old one gets an undo link),
`sendEmailVerification()`, `linkWithPassword()`, `linkWithIdToken()`, `unlink()`, `deleteAccount()`.

## Users in database documents

With `winche_database`, a document can point at a user: store a user reference with `Link.user(uid)`, and a read
that expands the field brings the user's profile with the document:

```dart
import 'package:winche_database/winche_database.dart';

await db.doc('visits/v1').set({'author': Link.user(auth.currentUser!.uid)});

final visit = await db.doc('visits/v1').expand(['author']).get();
final author = visit.data()!['author'] as Link;   // always a Link: kind LinkKind.user, target the uid
print(author.data()?['displayName']);
```

- **What's in it:** to signed-in users, anyone's public profile: `uid`, `displayName`, `photoUrl`, and the custom
  claims the server lists as public (`o.PublicProfileClaims`, none by default). A user's own reference brings their
  whole account. Signed out, nothing: `data()` is null, the uid is still `target`.
- Nested references work too: `expand(['patient.doctor.account'])` follows documents to the user at the end.
- A listener on the document emits again when the user's profile changes.
- A plain uid string is never expanded: store uids with `Link.user`. In rules, a user reference still equals its uid
  (`resource.data.author == request.auth.uid`).

## Two-step sign-in

When the server has it on (`o.Mfa()`), a user can add an authenticator app:

```dart
final enrollment = await auth.startTotpEnrollment();     // show enrollment.otpauthUri as a QR code
final recoveryCodes = await auth.confirmTotpEnrollment(codeFromTheApp);   // show these once
```

From then on, signing in throws `WincheMfaRequiredException` after the first step. Ask for a code and finish:

```dart
try {
  await auth.signInWithEmail(email, password);
} on WincheMfaRequiredException catch (required) {
  await auth.resolveMfa(required, await askForCode());   // the app's code, or a recovery code
}
```

`mfaStatus()`, `regenerateRecoveryCodes(code)` and `disableMfa(code)` manage it; `currentUser.mfaEnabled` says whether
it's on, and the token carries `mfa: true` after a two-step sign-in.

## Emailed links

`sendPasswordReset(email)` and `resetPassword(link, newPassword)`; `checkActionCode(link)` and `applyActionCode(link)`
for verify, confirm-new-email and undo links when they open your app rather than Winche Auth's own page. Every method
that takes a link also takes just its code.

## Tokens

`getAuthToken()` returns the access token, refreshing it shortly before it expires — one refresh at a time however many
callers ask. Only the server ends a session (its refresh token revoked, the user disabled or deleted); a dropped
connection or a server failure makes `getAuthToken` throw a `WincheAuthException` and the user stays signed in.

## Staying signed in

The session is kept in a `WincheAuthStorage`: memory by default (signed out on every launch). In Flutter, keep it in the
platform's secure storage:

```dart
final class SecureAuthStorage implements WincheAuthStorage {
  final _store = const FlutterSecureStorage();
  @override
  Future<String?> read(String key) => _store.read(key: key);
  @override
  Future<void> write(String key, String value) => _store.write(key: key, value: value);
  @override
  Future<void> delete(String key) => _store.delete(key: key);
}
```

A saved session is restored on start without the network (`await auth.ready`).

## Errors

`WincheAuthException`, a `WincheException`: `code` is the kind every Winche package shares (`unauthenticated`,
`alreadyExists`, `invalidArgument`, `unavailable` when the server couldn't be reached, …), `reason` Winche Auth's own
(`WincheAuthReason.invalidCredentials`, `.emailExists`, `.weakPassword`, `.emailNotVerified`, `.userDisabled`,
`.lockedOut`, `.accountExistsWithOtherMethod`, `.invalidCode`, …), and `message` a sentence for people.

```dart
try {
  await auth.signUpWithEmail(email, password);
} on WincheAuthException catch (e) {
  if (e.reason == WincheAuthReason.emailExists) showSignIn();
  else if (e.isTransient) showTryAgain();
  else showError(e.message);
}
```

## The emulator

```dart
Winche.initializeApp(options: WincheOptions.emulator());   // localhost:9090; host: '10.0.2.2' on Android
```

To keep your generated options and use the emulator in debug builds, call `app.useEmulator()` straight after
`initializeApp`, before `WincheAuth` is created (on Android, `localhost` becomes `10.0.2.2`).

`winche emulators start` runs Winche Auth too. Emails aren't sent (their links are printed), and Google and Apple
sign-in take fake ID tokens: `winche emulators idtoken google ann@example.com`.

## Tests

`dart test` runs against a fake server, including `winche_core`'s auth contract. With an emulator running,
`WINCHE_EMULATOR=localhost:9090 dart test --tags live` runs against it too.
