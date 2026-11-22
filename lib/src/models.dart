/// A Winche Auth user, as the server last described them.
final class WincheUser {
  /// The user's id: what rules see as `request.auth.uid`.
  final String uid;
  final String? email;
  final bool emailVerified;
  final String? displayName;
  final String? photoUrl;

  /// Where [photoUrl] came from: `upload` ([WincheAuth.updatePhoto]), `link`,
  /// `provider:<name>` (a sign-in provider's picture), or null.
  final String? photoSource;
  final bool isAnonymous;

  /// Whether two-step sign-in (an authenticator app) is on.
  final bool mfaEnabled;

  /// How they can sign in: `password`, `anonymous`, `google`, `apple`, or an
  /// OpenID Connect provider's name.
  final List<String> providers;

  /// Set by the app's server or the console; what rules see as
  /// `request.auth.token.*`.
  final Map<String, Object?> customClaims;
  final DateTime? createdAt;
  final DateTime? lastSignInAt;

  WincheUser({
    required this.uid,
    this.email,
    this.emailVerified = false,
    this.displayName,
    this.photoUrl,
    this.photoSource,
    this.isAnonymous = false,
    this.mfaEnabled = false,
    List<String> providers = const [],
    Map<String, Object?> customClaims = const {},
    this.createdAt,
    this.lastSignInAt,
  })  : providers = List.unmodifiable(providers),
        customClaims = Map.unmodifiable(customClaims);

  factory WincheUser.fromJson(Map<String, Object?> json) => WincheUser(
        uid: json['uid'] as String,
        email: json['email'] as String?,
        emailVerified: json['emailVerified'] as bool? ?? false,
        displayName: json['displayName'] as String?,
        photoUrl: json['photoUrl'] as String?,
        photoSource: json['photoSource'] as String?,
        isAnonymous: json['isAnonymous'] as bool? ?? false,
        mfaEnabled: json['mfaEnabled'] as bool? ?? false,
        providers: [for (final p in (json['providers'] as List<Object?>? ?? const [])) p as String],
        customClaims: Map<String, Object?>.from(json['customClaims'] as Map<Object?, Object?>? ?? const {}),
        createdAt: _date(json['createdAt']),
        lastSignInAt: _date(json['lastSignInAt']),
      );

  Map<String, Object?> toJson() => {
        'uid': uid,
        'email': email,
        'emailVerified': emailVerified,
        'displayName': displayName,
        'photoUrl': photoUrl,
        'photoSource': photoSource,
        'isAnonymous': isAnonymous,
        'mfaEnabled': mfaEnabled,
        'providers': providers,
        'customClaims': customClaims,
        'createdAt': createdAt?.toIso8601String(),
        'lastSignInAt': lastSignInAt?.toIso8601String(),
      };

  static DateTime? _date(Object? v) => v is String ? DateTime.tryParse(v) : null;

  @override
  String toString() => 'WincheUser($uid${email == null ? '' : ', $email'})';
}

/// What a sign-in screen can offer: `GET /auth/v1/providers`.
final class WincheAuthProviders {
  final bool emailPassword;
  final bool emailLink;
  final bool anonymous;

  /// Google, Apple and OpenID Connect providers: name (for
  /// `signInWithIdToken`), kind (`google`, `apple`, `oidc`) and a display name.
  final List<({String name, String kind, String displayName})> providers;

  const WincheAuthProviders({required this.emailPassword, required this.emailLink, required this.anonymous, required this.providers});

  factory WincheAuthProviders.fromJson(Map<String, Object?> json) => WincheAuthProviders(
        emailPassword: json['emailPassword'] as bool? ?? false,
        emailLink: json['emailLink'] as bool? ?? false,
        anonymous: json['anonymous'] as bool? ?? false,
        providers: [
          for (final p in (json['providers'] as List<Object?>? ?? const []))
            (
              name: (p as Map<String, Object?>)['name'] as String,
              kind: p['kind'] as String,
              displayName: p['displayName'] as String? ?? p['name'] as String,
            ),
        ],
      );
}

/// A new authenticator app: type [secret] into it, or show [otpauthUri] as a QR code.
final class WincheTotpEnrollment {
  final String secret;
  final Uri otpauthUri;
  const WincheTotpEnrollment(this.secret, this.otpauthUri);
}

/// Whether two-step sign-in is on, and how many recovery codes are left.
final class WincheMfaStatus {
  final bool enabled;
  final int recoveryCodesLeft;
  const WincheMfaStatus(this.enabled, this.recoveryCodesLeft);
}

/// What an emailed link's code is for: [mode] is `verifyEmail`,
/// `verifyAndChangeEmail`, `recoverEmail`, `resetPassword` or `signIn`.
final class WincheActionCodeInfo {
  final String mode;
  final String email;
  const WincheActionCodeInfo(this.mode, this.email);
}
