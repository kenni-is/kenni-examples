import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:flutter_appauth/flutter_appauth.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'config.dart';
import 'jwt.dart';

/// Single SecureStorage entry that holds the JSON-encoded token bundle.
const _tokensKey = 'kenni.tokens.v1';

class _StoredTokens {
  const _StoredTokens({
    required this.idToken,
    required this.accessToken,
    this.refreshToken,
    this.expiresAt,
  });

  final String idToken;
  final String accessToken;
  final String? refreshToken;
  final DateTime? expiresAt;

  Map<String, dynamic> toJson() => {
        'id_token': idToken,
        'access_token': accessToken,
        'refresh_token': refreshToken,
        'expires_at': expiresAt?.toIso8601String(),
      };

  factory _StoredTokens.fromJson(Map<String, dynamic> json) => _StoredTokens(
        idToken: json['id_token'] as String,
        accessToken: json['access_token'] as String,
        refreshToken: json['refresh_token'] as String?,
        expiresAt: json['expires_at'] == null
            ? null
            : DateTime.parse(json['expires_at'] as String),
      );
}

class AuthController extends ChangeNotifier {
  AuthController(this._config);

  final KenniConfig _config;
  final FlutterAppAuth _appAuth = const FlutterAppAuth();
  final FlutterSecureStorage _storage = const FlutterSecureStorage();

  bool _isReady = false;
  bool _isLoading = false;
  String? _error;
  _StoredTokens? _tokens;
  // iOS-only: after a local-only sign-out, force the next authorize
  // request to require fresh credentials. The underlying AppAuth iOS
  // SDK uses `ASWebAuthenticationSession`, which shows Apple's hardcoded
  // "wants to use <domain> to sign in" consent prompt on RP-initiated
  // logout — see RP-initiated logout note below for why we hide that
  // button on iOS. Without `prompt=login`, the next sign-in silently
  // re-auths via the WebAuthSession cookie jar, making the local
  // sign-out feel fake. Cleared on successful sign-in.
  bool _forceReauth = false;

  /// Whether the current platform exposes RP-initiated logout. Hidden on
  /// iOS because Apple's consent prompts (ASWebAuthenticationSession's
  /// hardcoded "sign in" wording, plus Safari's custom-scheme "Open in
  /// App?" prompt if you swap to `Linking.openURL`) make the flow
  /// unusable without Universal Links. Android Chrome Custom Tabs have
  /// neither prompt.
  bool get supportsRpInitiatedLogout => !Platform.isIOS;

  bool get isReady => _isReady;
  bool get isLoading => _isLoading;
  bool get isAuthenticated => _tokens != null;
  String? get error => _error;

  /// Decoded id_token claims, or null when signed out / decode fails.
  Map<String, dynamic>? get profile {
    final t = _tokens;
    if (t == null) return null;
    try {
      return decodeJwtPayload(t.idToken);
    } catch (_) {
      return null;
    }
  }

  String? get displayName {
    final p = profile;
    final name = p?['name'];
    return name is String && name.isNotEmpty ? name : null;
  }

  Future<void> load() async {
    try {
      final raw = await _storage.read(key: _tokensKey);
      if (raw != null) {
        _tokens = _StoredTokens.fromJson(
          jsonDecode(raw) as Map<String, dynamic>,
        );
      }
    } catch (_) {
      // Corrupt entry — start signed-out.
    } finally {
      _isReady = true;
      notifyListeners();
    }
  }

  Future<void> _persist(_StoredTokens? next) async {
    _tokens = next;
    if (next != null) {
      await _storage.write(key: _tokensKey, value: jsonEncode(next.toJson()));
    } else {
      await _storage.delete(key: _tokensKey);
    }
    notifyListeners();
  }

  Future<void> signIn() async {
    _error = null;
    _isLoading = true;
    notifyListeners();
    try {
      final result = await _appAuth.authorizeAndExchangeCode(
        AuthorizationTokenRequest(
          _config.clientId,
          _config.redirectUri,
          discoveryUrl: _config.discoveryUrl,
          scopes: kenniScopes,
          promptValues: _forceReauth && Platform.isIOS ? const ['login'] : null,
        ),
      );
      if (result.idToken == null || result.accessToken == null) {
        throw StateError('Token endpoint did not return id_token + access_token.');
      }
      await _persist(
        _StoredTokens(
          idToken: result.idToken!,
          accessToken: result.accessToken!,
          refreshToken: result.refreshToken,
          expiresAt: result.accessTokenExpirationDateTime,
        ),
      );
      // Successful sign-in clears the iOS force-reauth flag.
      _forceReauth = false;
    } on FlutterAppAuthUserCancelledException {
      // User cancelled the in-app browser — not an error to display.
    } catch (e) {
      _error = e.toString();
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Local-only sign-out. Clears stored tokens, leaves the Kenni session
  /// alive. On iOS the next sign-in will force `prompt=login` so the
  /// local sign-out actually requires fresh credentials; on Android the
  /// user has the option to use [signOutRemote] for a real RP-initiated
  /// logout, so we don't override their next sign-in.
  Future<void> signOutLocal() async {
    _error = null;
    if (Platform.isIOS) _forceReauth = true;
    await _persist(null);
  }

  /// RP-initiated logout. Captures the current tokens, clears local state
  /// first (so a failed remote logout still leaves the local session
  /// cleared), then redirects through Kenni's end_session_endpoint to
  /// drop the IdP session cookie too.
  Future<void> signOutRemote() async {
    _error = null;
    final captured = _tokens;
    await _persist(null);

    if (captured == null) return;

    try {
      await _appAuth.endSession(
        EndSessionRequest(
          idTokenHint: captured.idToken,
          postLogoutRedirectUrl: _config.postLogoutRedirectUri,
          discoveryUrl: _config.discoveryUrl,
        ),
      );
    } on FlutterAppAuthUserCancelledException {
      // User dismissed the WebView — local session is still cleared.
    } catch (e) {
      _error = e.toString();
      notifyListeners();
    }
  }
}
