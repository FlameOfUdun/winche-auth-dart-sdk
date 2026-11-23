# Changelog

## 0.2.0

* `updatePhoto(bytes)` and `removePhoto()`: the signed-in user's photo, kept by
  Winche Auth (JPEG, PNG or WebP, at most 100 KB: shrink it first). Needs
  Winche Auth 2.1 (Winche Server 4). `WincheUser.photoSource` says where
  `photoUrl` came from (`upload`, `link`, `provider:<name>`).
* `updateProfile()` sends only the fields passed: a field left out stays (a
  rename no longer clears an uploaded photo). `clearDisplayName` /
  `clearPhotoUrl` remove a field; `removePhoto()` removes an uploaded photo.
* A call to Winche Auth's own `me` endpoints refused with a bare
  `unauthenticated` (Winche Auth 2.1: the session was ended by signing out
  everywhere, an admin, or the email's owner claiming the account) refreshes
  the token once: if the session is over the user is signed out
  (`currentUser` null, `userChanges` emits null) and the error is thrown;
  if only the token was stale, the call is retried once. Errors with a
  `reason` are unchanged.
* A saved session that can't be read on start (a keychain locked while the app
  launches in the background) is kept, not deleted: `ready` completes signed
  out for now, and the next `getAuthToken` reads it again and restores the
  user, unless they signed in or out meanwhile. Only a saved value that isn't
  a session is deleted.

## 0.1.0

Docs: **Users in database documents**: `Link.user(uid)` in a document, expanded by `winche_database` into the user's
public profile (their whole account for themselves).

First release: email and password, anonymous, email-link, Google, Apple and OpenID Connect sign-in against Winche Auth;
linking and unlinking; profile, password and email changes; reset and verify links; tokens refreshed one at a time and
shared with `winche_database` and `winche_storage` through `winche_core`; sessions kept in a `WincheAuthStorage`.
Two-step sign-in: `startTotpEnrollment`, `confirmTotpEnrollment`, `WincheMfaRequiredException` and `resolveMfa`,
`mfaStatus`, `regenerateRecoveryCodes`, `disableMfa`. Needs `winche_core` 1.0: an identity source, its endpoint
`/auth/v1` under `WincheOptions.baseUrl` (or `endpoints['auth']`), requests through `app.http`, and
`WincheAuthException` a `WincheException` with the shared `code` and Winche Auth's own `reason` (`WincheAuthReason`).
Links to Winche's own action page carry the code after `#` (never in a server log); `codeFrom` reads either form.
`WincheAuthReason.requiresRecentSignIn`: changing the email, deleting the account, adding a second step and unlinking
need a sign-in from the last five minutes. `signInWithCustomToken` signs in with a token from the app's own server
(`WincheAuthReason.invalidCustomToken` when it isn't valid).
