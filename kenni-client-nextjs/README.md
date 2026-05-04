# Kenni — Next.js (better-auth) example

Sign in with Kenni from a Next.js App Router app, using
[`better-auth`](https://www.better-auth.com)'s `genericOAuth` plugin.
Demonstrates:

- Login (Authorization Code + PKCE).
- RP-initiated logout (clears the local session **and** Kenni's session).
- Calling a protected API endpoint with the user's access token.
- A client-credentials grant (M2M).

The corresponding doc is
[Next.js / better-auth](https://developers.kenni.is/docs/guides/better-auth).

This example runs better-auth in
[stateless mode](https://better-auth.com/docs/concepts/session-management#stateless-session-management) —
no database. Session and account state live in signed cookies. To switch to
a database-backed setup, add a `database:` option to `auth.ts` and run
`npx @better-auth/cli@latest migrate`.

## What to register in the Kenni developer portal

In the [developer portal](https://developers.kenni.is), open your application
and add the following:

| Setting | Value |
|---|---|
| **Redirect URI** | `http://localhost:3000/api/auth/oauth2/callback/kenni` |
| **Post-logout redirect URI** | `http://localhost:3000/` |
| **Scopes** | `openid`, `profile`, `national_id`, `offline_access`, plus your API scope (if any) |

**Continue with Kenni** runs the plain authorization code flow. **Continue with Delegation** and **Switch delegation** call the same provider but pass `additionalData: { prompt: "delegation" }`, which `auth.ts` forwards into the authorization URL via `authorizationUrlParams`, so the user is sent through the company / custom delegation chooser. Both share one redirect URI. (This is a Next.js-specific demonstration of delegation; the other library examples don't include it.)

If you want to try the **client-credentials grant**, register a *second*
application in the portal as a machine-to-machine client and put its
credentials in `KENNI_M2M_CLIENT_ID` / `KENNI_M2M_CLIENT_SECRET`, plus the
scope it should request in `KENNI_M2M_SCOPE`.

## Run

```bash
cp .env.example .env.local
# Edit .env.local — at minimum, set KENNI_ISSUER, KENNI_CLIENT_ID,
# KENNI_CLIENT_SECRET, BETTER_AUTH_SECRET.

yarn install
yarn dev
```

Open <http://localhost:3000> and click **Continue with Kenni**.

## Environment variables

See [`.env.example`](./.env.example) — every variable is documented inline.
The two optional features (API call, client credentials) are auto-hidden in
the UI when their env vars are not set, so you can run the example with just
the four required Kenni variables.

## What each button does

- **Continue with Kenni** — `authClient.signIn.oauth2({ providerId: 'kenni' })`.
  Triggers the Authorization Code + PKCE flow.
- **Call protected resource** — calls `/api/me`, which retrieves your Kenni
  access token via `auth.api.getAccessToken` (auto-refreshing if expired) and
  uses it to call this app's own `/api/protected-resource`. That endpoint
  verifies the token (issuer, audience, expiry, scope) against Kenni's JWKS
  and returns a small JSON payload.
- **Client credentials grant** — POSTs `grant_type=client_credentials` to
  Kenni's token endpoint with HTTP Basic auth and decodes the resulting
  access token's claims for display.
- **Sign out (local)** — clears the better-auth session cookie only. Kenni's
  session cookie is untouched, so the next sign-in is silent.
- **RP-initiated logout** — navigates to `/api/sign-out`, which (a) reads
  the user's id_token from better-auth via `auth.api.getAccessToken`,
  (b) clears the local session, and (c) redirects the browser to Kenni's
  discovered `end_session_endpoint` with `id_token_hint`,
  `post_logout_redirect_uri`, and `client_id` so Kenni clears its session
  too.
