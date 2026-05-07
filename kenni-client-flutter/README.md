# Kenni — Flutter example

Sign in with Kenni from a Flutter app, using
[`flutter_appauth`](https://pub.dev/packages/flutter_appauth) (the
canonical wrapper around Google's AppAuth iOS/Android SDKs).
Demonstrates:

- Login (Authorization Code + PKCE — public client, no secret).
- RP-initiated logout (clears the local session **and** Kenni's session
  via `end_session_endpoint`).

The corresponding doc is
[Flutter](https://developers.kenni.is/docs/guides/flutter).

This is a **public client** — register it in the
[developer portal](https://developers.kenni.is) as a **Native**
application type. There is no `client_secret`; security comes from PKCE.

## What to register in the Kenni developer portal

In the [developer portal](https://developers.kenni.is), open your application
and add the following:

| Setting | Value |
|---|---|
| **Application type** | Native |
| **Redirect URI** | `is.kenni.flutter://callback` |
| **Post-logout redirect URI** | `is.kenni.flutter://post-logout` |
| **Scopes** | `openid`, `profile`, `national_id`, `offline_access` |

Both URIs use the custom URL scheme `is.kenni.flutter`. To change the
scheme (e.g. for your own app), update the four places listed in
**Platform configuration** below — keep them all in sync.

## Run

This example targets Flutter **3.38.1+** / Dart **3.10+**. Bootstrap the
platform folders, then build to a real device or simulator:

```bash
# 1. Bootstrap iOS + Android platform folders. flutter create won't
#    overwrite the lib/, pubspec.yaml, dart_defines.example.json,
#    .gitignore, README, or analysis_options.yaml that ship in this
#    directory — it only adds the missing native scaffolding.
flutter create \
  --org is.kenni \
  --project-name kenni_client_flutter \
  --platforms=ios,android \
  .

# 2. Apply the platform configuration below (Info.plist + build.gradle).

# 3. Pin dependencies and copy the dart-define template.
flutter pub get
cp dart_defines.example.json dart_defines.json
# Edit dart_defines.json — set KENNI_ISSUER and KENNI_CLIENT_ID for your
# application.

# 4. Run.
flutter run --dart-define-from-file=dart_defines.json
```

## Environment / configuration

Flutter's idiomatic config story is **`--dart-define-from-file`**
(stable since Flutter 3.7). Values surface in Dart code via
`String.fromEnvironment('…')` — they're inlined into the build at
compile time, so there's no runtime env loader and no extra package.
See [`lib/src/config.dart`](./lib/src/config.dart).

[`dart_defines.example.json`](./dart_defines.example.json) lists every
value with documentation. Copy to `dart_defines.json` (gitignored) and
fill in your values; rebuild the app after editing.

## Platform configuration

`flutter create` produces platform skeletons; you have to add the URL
scheme and the AppAuth manifest placeholder yourself.

### iOS — `ios/Runner/Info.plist`

Add the `CFBundleURLTypes` entry inside the top-level `<dict>`:

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleTypeRole</key>
    <string>Editor</string>
    <key>CFBundleURLName</key>
    <string>is.kenni.flutter</string>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>is.kenni.flutter</string>
    </array>
  </dict>
</array>
```

### Android — `android/app/build.gradle` (or `build.gradle.kts`)

Inside `android.defaultConfig`, add the AppAuth redirect-scheme
placeholder:

```gradle
defaultConfig {
    // ...
    manifestPlaceholders = [appAuthRedirectScheme: 'is.kenni.flutter']
}
```

Kotlin DSL variant:

```kotlin
defaultConfig {
    // ...
    manifestPlaceholders["appAuthRedirectScheme"] = "is.kenni.flutter"
}
```

`minSdkVersion` must be **24** or higher (flutter_appauth 12 requires
Android 7.0). `flutter create` defaults to 21 in older Flutter versions
— bump it if needed.

## What each button does

- **Continue with Kenni** — `FlutterAppAuth.authorizeAndExchangeCode()`
  opens the system browser tab at Kenni's authorization endpoint.
  After the user authenticates, the OS routes the redirect back into
  the app via the custom URL scheme; AppAuth performs the code
  exchange in one round trip and returns id/access/refresh tokens.
  Tokens persist in `flutter_secure_storage` (Keychain on iOS,
  EncryptedSharedPreferences on Android) so a relaunch doesn't bounce
  the user back through Kenni.
- **Sign out** (iOS) / **Sign out (local)** (Android) — Clears the
  secure-storage entry only. Kenni's session cookie stays alive, so
  the next sign-in would normally be silent. **On iOS** the next
  authorize request is forced to send `prompt=login` (via
  `AuthorizationTokenRequest.promptValues = ['login']`) — fresh
  credentials required. **On Android** the user has the option to use
  the **RP-initiated logout** button to fully sign out, so we don't
  override their next sign-in.
- **RP-initiated logout** *(Android only)* — Clears the local session
  first (so a failed remote logout still leaves the local session
  cleared), then calls `FlutterAppAuth.endSession()` with
  `id_token_hint` and `post_logout_redirect_uri`. AppAuth opens
  Chrome Custom Tabs, Kenni clears its session, and the OS routes the
  post-logout redirect back into the app. Hidden on iOS — see below.

## iOS vs Android — RP-initiated logout

**Android** uses Chrome Custom Tabs. Cookies are shared with Chrome
without a consent prompt, the tab auto-dismisses on the post-logout
redirect, and the user stays in the app the whole time. The canonical
RP-initiated logout flow.

**iOS** does not surface an RP-initiated logout button. The underlying
AppAuth iOS SDK uses `ASWebAuthenticationSession`, which shows Apple's
hardcoded *"<App> wants to use kenni.is to sign in"* consent prompt —
useless UX on a sign-out flow, and the wording is not configurable.
Opening the end-session URL in Safari directly only trades it for a
different prompt: *"Open this page in '<App>'?"* fires when Kenni
redirects to `is.kenni.flutter://post-logout`. The only clean fix is
**Universal Links** (a real HTTPS domain you control + an
[`apple-app-site-association`](https://developer.apple.com/documentation/xcode/supporting-associated-domains)
file hosted at `/.well-known/apple-app-site-association` + the
`applinks:` entitlement). That infrastructure is out of scope for this
example. If you control a domain and need the flow in production,
swap `is.kenni.flutter://post-logout` for
`https://your-domain/post-logout`, host the AASA file, and Safari
hands the URL to your app silently.

For everything else, **Sign out** + `prompt=login` on next sign-in is
the practical iOS pattern, and what most production iOS apps ship.
The `signOutRemote` code in `lib/src/auth.dart` stays implemented for
educational purposes (and Android calls it) — reading the source still
teaches the protocol-level flow, even though iOS doesn't expose the
button.

## JSON output panel

When signed in, the panel under the buttons shows the decoded id_token
claims (`sub`, `name`, `national_id`, …). Decoding is **display-only**;
the id_token signature is verified by the underlying AppAuth SDK during
the code exchange.
