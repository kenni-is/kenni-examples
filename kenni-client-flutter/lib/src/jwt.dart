import 'dart:convert';

/// Minimal base64url JWT payload decoder. Display-only — token signature
/// verification happens server-side at the token endpoint as part of the
/// OIDC code exchange (flutter_appauth performs it).
Map<String, dynamic> decodeJwtPayload(String token) {
  final parts = token.split('.');
  if (parts.length < 2) {
    throw const FormatException('Malformed JWT: missing payload segment');
  }
  final padded = base64Url.normalize(parts[1]);
  final json = utf8.decode(base64Url.decode(padded));
  return jsonDecode(json) as Map<String, dynamic>;
}
