# Changelog

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
