// Compile-time configuration sourced from --dart-define-from-file.
//
// Run the app with:
//   flutter run --dart-define-from-file=dart_defines.json
//
// `String.fromEnvironment` is a const constructor — values must be present
// at compile time, so they're inlined into the build. There's no .env
// loader at runtime; that's the idiomatic Flutter pattern.

class KenniConfig {
  const KenniConfig({
    required this.issuer,
    required this.clientId,
    required this.redirectUri,
    required this.postLogoutRedirectUri,
  });

  final String issuer;
  final String clientId;
  final String redirectUri;
  final String postLogoutRedirectUri;

  String get discoveryUrl => '$issuer/.well-known/openid-configuration';

  static const _issuer = String.fromEnvironment('KENNI_ISSUER');
  static const _clientId = String.fromEnvironment('KENNI_CLIENT_ID');
  static const _redirectUri = String.fromEnvironment('KENNI_REDIRECT_URI');
  static const _postLogoutRedirectUri = String.fromEnvironment(
    'KENNI_POST_LOGOUT_REDIRECT_URI',
  );

  /// Throws on the first missing value with an actionable error message,
  /// instead of bubbling up an empty-string failure deep in flutter_appauth.
  factory KenniConfig.fromEnvironment() {
    String require(String name, String value) {
      if (value.isEmpty) {
        throw StateError(
          'Missing required dart-define: $name. Run with '
          '--dart-define-from-file=dart_defines.json (see .example).',
        );
      }
      return value;
    }

    return KenniConfig(
      issuer: require('KENNI_ISSUER', _issuer),
      clientId: require('KENNI_CLIENT_ID', _clientId),
      redirectUri: require('KENNI_REDIRECT_URI', _redirectUri),
      postLogoutRedirectUri: require(
        'KENNI_POST_LOGOUT_REDIRECT_URI',
        _postLogoutRedirectUri,
      ),
    );
  }
}

const kenniScopes = <String>['openid', 'profile', 'national_id', 'offline_access'];
