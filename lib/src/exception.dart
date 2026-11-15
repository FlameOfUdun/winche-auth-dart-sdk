import 'package:winche_core/winche_core.dart';

/// A Winche Auth request that failed.
///
/// [code] is the shared kind (`unauthenticated`, `alreadyExists`,
/// `invalidArgument`, `unavailable` when the server couldn't be reached, …);
/// [reason] is Winche Auth's own, precise code — one of [WincheAuthReason] —
/// for the cases an app tells apart (a wrong password, an email in use, a weak
/// password). [message] is a sentence for people.
final class WincheAuthException extends WincheException {
  /// Creates an exception.
  const WincheAuthException(super.code, super.message, {this.reason, this.statusCode, this.details = const {}});

  /// Winche Auth's own code, e.g. [WincheAuthReason.invalidCredentials]; null
  /// when the server wasn't reached.
  final String? reason;

  /// The HTTP status, or null when there was no answer.
  final int? statusCode;

  /// Extra values the server sent with the error.
  final Map<String, Object?> details;

  /// [error] in Winche Auth's terms; an `MFA_REQUIRED` becomes a [WincheMfaRequiredException].
  factory WincheAuthException.from(WincheHttpException error) {
    if (error.reason == WincheAuthReason.mfaRequired && error.details['mfaToken'] is String) {
      return WincheMfaRequiredException(
        error.details['mfaToken'] as String,
        [for (final f in (error.details['factors'] as List<Object?>? ?? const ['totp'])) f as String],
        error.message,
      );
    }
    return WincheAuthException(error.code, error.message, reason: error.reason, statusCode: error.status, details: error.details);
  }

  @override
  String toString() => 'WincheAuthException(${code.wireName}${reason == null ? '' : '/$reason'}): $message';
}

/// A sign-in passed its first step, and the user has two-step sign-in on: ask
/// for a code from their authenticator app (or a recovery code) and call
/// `WincheAuth.resolveMfa(this, code)` within a few minutes.
final class WincheMfaRequiredException extends WincheAuthException {
  /// Proof of the first step, for `WincheAuth.resolveMfa`.
  final String mfaToken;

  /// What the second step can be: `totp` (an authenticator app), `recovery`.
  final List<String> factors;

  /// Creates the exception.
  const WincheMfaRequiredException(this.mfaToken, this.factors, String message)
    : super(WincheErrorCode.unauthenticated, message, reason: WincheAuthReason.mfaRequired, statusCode: 401);
}

/// Winche Auth's own error codes: a [WincheAuthException.reason].
abstract final class WincheAuthReason {
  /// A wrong email or password (they look the same, on purpose).
  static const invalidCredentials = 'INVALID_CREDENTIALS';

  /// An account with that email already exists.
  static const emailExists = 'EMAIL_EXISTS';

  /// Not an email address.
  static const invalidEmail = 'INVALID_EMAIL';

  /// The password is too weak.
  static const weakPassword = 'WEAK_PASSWORD';

  /// The account is disabled.
  static const userDisabled = 'USER_DISABLED';

  /// There's no such account.
  static const userNotFound = 'USER_NOT_FOUND';

  /// Too many failed attempts on this account, for now.
  static const lockedOut = 'LOCKED_OUT';

  /// Too many attempts from this address, for now.
  static const tooManyAttempts = 'TOO_MANY_ATTEMPTS';

  /// The session has ended (signed out elsewhere, or expired).
  static const invalidRefreshToken = 'INVALID_REFRESH_TOKEN';

  /// That sign-in method is off on this server.
  static const signInMethodNotEnabled = 'SIGN_IN_METHOD_NOT_ENABLED';

  /// The email is already used by another sign-in method.
  static const accountExistsWithOtherMethod = 'ACCOUNT_EXISTS_WITH_OTHER_METHOD';

  /// The provider's account is already linked to another user.
  static const credentialAlreadyInUse = 'CREDENTIAL_ALREADY_IN_USE';

  /// The emailed link or code isn't valid (any more).
  static const invalidCode = 'INVALID_CODE';

  /// The email must be verified first.
  static const emailNotVerified = 'EMAIL_NOT_VERIFIED';

  /// A second step is needed: see [WincheMfaRequiredException].
  static const mfaRequired = 'MFA_REQUIRED';

  /// The authenticator or recovery code isn't right.
  static const invalidMfaCode = 'INVALID_MFA_CODE';

  /// The provider requires a second step and this sign-in had none: sign in
  /// with the provider again using its one-time code.
  static const secondStepRequired = 'SECOND_STEP_REQUIRED';

  /// The sign-up or sign-in was refused by the server's own rules.
  static const denied = 'DENIED';

  /// The action (changing the email, deleting the account, adding a second
  /// step, unlinking) needs a sign-in from the last few minutes: sign in again,
  /// then retry.
  static const requiresRecentSignIn = 'REQUIRES_RECENT_SIGN_IN';

  /// The custom token isn't valid, or has expired.
  static const invalidCustomToken = 'INVALID_CUSTOM_TOKEN';
}
