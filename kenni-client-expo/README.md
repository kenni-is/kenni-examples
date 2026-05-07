# Kenni — Expo (React Native) example

Sign in with Kenni from an Expo app, using
[`expo-auth-session`](https://docs.expo.dev/versions/latest/sdk/auth-session/)
(the standard OAuth/OIDC client for Expo). Demonstrates:

- Login (Authorization Code + PKCE — public client, no secret).
- RP-initiated logout (clears the local session, revokes the refresh
  token, **and** clears Kenni's session via `end_session_endpoint`).

The corresponding doc is
[Expo (React Native)](https://developers.kenni.is/docs/guides/expo).

This is a **public client** — register it in the
[developer portal](https://developers.kenni.is) as a **Native** application
type. There is no `client_secret`; security comes from PKCE.

## What to register in the Kenni developer portal

In the [developer portal](https://developers.kenni.is), open your application
and add the following:

| Setting | Value |
|---|---|
| **Application type** | Native |
| **Redirect URI** | `is.kenni.expo://callback` |
| **Post-logout redirect URI** | `is.kenni.expo://post-logout` |
| **Scopes** | `openid`, `profile`, `national_id`, `offline_access` |

Both URIs use the custom URL scheme `is.kenni.expo` defined in
[`app.config.ts`](./app.config.ts). The scheme is **derived from
`KENNI_REDIRECT_URI`** so changing the scheme means editing one env var,
and `app.config.ts` propagates it into the native build.

## Run

This example targets a **development build** (`expo run:ios` /
`expo run:android`) — custom URL schemes are how Kenni redirects back
into the app, and Expo Go does not load custom schemes.

```bash
cp .env.example .env
# Edit .env — set KENNI_ISSUER and KENNI_CLIENT_ID for your application.

yarn install
yarn ios       # or: yarn android
```

The first build takes a few minutes (CocoaPods on iOS, Gradle on
Android). After that, `yarn start` is enough — Metro re-uses the build.

## Environment variables

See [`.env.example`](./.env.example) — every variable is documented inline.

The variables are read at config-resolution time by
[`app.config.ts`](./app.config.ts) and forwarded to app code via Expo's
`extra` (see [`src/config.ts`](./src/config.ts)). No `EXPO_PUBLIC_`
prefix needed. **Restart the bundler after editing `.env`** so
`app.config.ts` re-reads `process.env`.

## What each button does

- **Continue with Kenni** — `useAuthRequest().promptAsync()` opens the
  in-app browser at Kenni's authorization endpoint. After the user
  authenticates, the browser redirects to `KENNI_REDIRECT_URI`, the
  custom URL scheme routes the redirect back into the app, and
  `exchangeCodeAsync` swaps the code for tokens. Tokens persist in
  `SecureStore` so a relaunch doesn't bounce the user back through Kenni.
- **Sign out** (iOS) / **Sign out (local)** (Android) — Clears the
  SecureStore entry only. Kenni's session cookie stays alive, so the
  next sign-in would normally be silent. **On iOS** this would defeat
  the sign-out (Kenni's cookie auto-authenticates the user on the next
  attempt), so the next authorize request is forced to send
  `prompt=login` — fresh credentials required. **On Android** Chrome
  Custom Tabs share cookies with Chrome in a way that lets the user use
  the **RP-initiated logout** button to fully sign out, so we don't
  override their next sign-in.
- **RP-initiated logout** *(Android only)* — Clears the local session
  first (so a failed remote logout still leaves the local session
  cleared), revokes the refresh token at Kenni's revocation endpoint,
  then opens `end_session_endpoint` in Chrome Custom Tabs with
  `id_token_hint`, `post_logout_redirect_uri`, and `client_id`. Kenni
  clears its session and redirects to `KENNI_POST_LOGOUT_REDIRECT_URI`,
  which closes the WebView back to the app. Hidden on iOS — see below.

## iOS vs Android — RP-initiated logout

**Android** uses `WebBrowser.openAuthSessionAsync` (Chrome Custom Tabs).
Cookies are shared with Chrome without a consent prompt, the WebView
auto-dismisses on the post-logout redirect, and the user stays in the
app the whole time. The canonical RP-initiated logout flow.

**iOS** does not surface an RP-initiated logout button at all. Apple's
design makes a clean version impossible without Universal Links:

- `ASWebAuthenticationSession` (the API behind
  `WebBrowser.openAuthSessionAsync`) shows a hardcoded
  *"<App> wants to use kenni.is to sign in"* consent prompt. Wording is
  not configurable — useless UX on a sign-out flow.
- `Linking.openURL` opens Safari directly and skips the consent prompt,
  but when Kenni redirects to `is.kenni.expo://post-logout` the OS
  shows its custom-scheme confirmation: *"Open this page in
  'kenni-client-expo'?"*. Also unfixable with custom schemes.

The only way to get a seamless RP-initiated logout on iOS is
**Universal Links** (a real HTTPS domain you control + an
[apple-app-site-association](https://developer.apple.com/documentation/xcode/supporting-associated-domains)
file hosted on it + the `applinks:` entitlement on your app). That
infrastructure is out of scope for this example. If you control a
domain and need this flow in production, the change is mechanical:
swap `is.kenni.expo://post-logout` for `https://your-domain/post-logout`,
host the AASA file, and Safari hands the URL to your app silently.

For everything else, **Sign out** + `prompt=login` on next sign-in is
the practical iOS pattern, and it's what most production iOS apps
ship.

## JSON output panel

When signed in, the panel under the buttons shows the decoded id_token
claims (`sub`, `name`, `national_id`, …) — what an Expo client can
prove about the signed-in user without making a single network call.

Decoding is **display-only**; the id_token signature is verified
server-side at the token endpoint as part of the OIDC code exchange.
