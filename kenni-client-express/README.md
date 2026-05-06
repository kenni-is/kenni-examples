# Kenni — Node.js / Express example

Sign in with Kenni from an Express app, using
[`openid-client`](https://github.com/panva/node-openid-client) — the
reference OIDC library for Node and the same one Auth.js / NextAuth /
better-auth wrap internally.

Demonstrates:

- Login (Authorization Code + PKCE).
- RP-initiated logout (clears the local session **and** Kenni's session).
- Calling a protected API endpoint with the user's access token.
- A client-credentials grant (M2M).

The corresponding doc is
[Node.js / Express](https://developers.kenni.is/docs/guides/express).

Sessions live in `express-session`'s default in-memory store — fine for a
demo; swap in `connect-redis` (or any other store) for production.

## What to register in the Kenni developer portal

In the [developer portal](https://developers.kenni.is), open your application
and add the following:

| Setting | Value |
|---|---|
| **Redirect URI** | `http://localhost:3002/auth/callback` |
| **Post-logout redirect URI** | `http://localhost:3002/` |
| **Scopes** | `openid`, `profile`, `national_id`, `offline_access`, plus your API scope (if any) |

If you want to try the **client-credentials grant**, register a *second*
application in the portal as a machine-to-machine client and put its
credentials in `KENNI_M2M_CLIENT_ID` / `KENNI_M2M_CLIENT_SECRET`, plus the
scope it should request in `KENNI_M2M_SCOPE`.

## Run

```bash
npm install

cp .env.example .env
# Edit .env — at minimum, set SESSION_SECRET, KENNI_ISSUER,
# KENNI_CLIENT_ID, KENNI_CLIENT_SECRET.

npm run dev
```

Open <http://localhost:3002> and click **Continue with Kenni**.

## Environment variables

See [`.env.example`](./.env.example) — every variable is documented inline.
The two optional features (API call, client credentials) are auto-hidden in
the UI when their env vars are not set, so you can run the example with just
`SESSION_SECRET` plus the three required Kenni variables.

## What each button does

- **Continue with Kenni** — `GET /auth/login` calls
  `openid.buildAuthorizationUrl(...)` and redirects, after stashing the PKCE
  verifier and state on the session.
- **Call protected resource** — `GET /api/me` retrieves the user's Kenni
  access token from the session and uses it to call this app's own
  `/api/protected-resource`. That endpoint verifies the bearer token via
  `jose.jwtVerify` against the cached JWKS (issuer, audience, signature,
  expiry) and additionally checks that the configured `KENNI_API_SCOPE` is
  on the token.
- **Client credentials grant** — `POST /api/client-credentials` POSTs
  `grant_type=client_credentials` to Kenni's discovered token endpoint with
  HTTP Basic auth and decodes the resulting access token's claims for
  display.
- **Sign out (local)** — `req.session.destroy()`. Kenni's session cookie is
  untouched, so the next sign-in is silent.
- **RP-initiated logout** — destroys the local session and then redirects
  the browser to the URL produced by `openid.buildEndSessionUrl(...)`,
  which embeds `id_token_hint`, `post_logout_redirect_uri`, and
  `client_id` so Kenni clears its session too.
