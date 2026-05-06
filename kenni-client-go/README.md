# Kenni — Go example

Sign in with Kenni from a Go HTTP server, using
[`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2) for the OAuth
flow plus [`github.com/coreos/go-oidc/v3`](https://github.com/coreos/go-oidc)
for ID-token / access-token verification and JWKS handling.

Demonstrates:

- Login (Authorization Code + PKCE).
- RP-initiated logout (clears the local session **and** Kenni's session).
- Calling a protected API endpoint with the user's access token.
- A client-credentials grant (M2M).

The corresponding doc is
[Go](https://developers.kenni.is/docs/guides/go).

Sessions are kept in-memory in this example (a `map` keyed by an opaque
session ID stored in an HttpOnly cookie). Restart the server and you'll need
to sign in again — fine for a demo. For production, swap `sessionStore` in
`session.go` for Redis / a database / signed cookies.

## What to register in the Kenni developer portal

In the [developer portal](https://developers.kenni.is), open your application
and add the following:

| Setting | Value |
|---|---|
| **Redirect URI** | `http://localhost:8081/auth/callback` |
| **Post-logout redirect URI** | `http://localhost:8081/` |
| **Scopes** | `openid`, `profile`, `national_id`, `offline_access`, plus your API scope (if any) |

If you want to try the **client-credentials grant**, register a *second*
application in the portal as a machine-to-machine client and put its
credentials in `KENNI_M2M_CLIENT_ID` / `KENNI_M2M_CLIENT_SECRET`, plus the
scope it should request in `KENNI_M2M_SCOPE`.

## Run

```bash
cp .env.example .env
# Edit .env — at minimum, set KENNI_ISSUER, KENNI_CLIENT_ID, KENNI_CLIENT_SECRET.

go run .
```

Open <http://localhost:8081> and click **Continue with Kenni**.

This module declares `go 1.24` and pulls in the latest `go-oidc/v3` and
`golang.org/x/oauth2`. If your local `go` is older, `GOTOOLCHAIN=auto`
(the default) downloads a newer toolchain on demand.

## Environment variables

See [`.env.example`](./.env.example) — every variable is documented inline.
The two optional features (API call, client credentials) are auto-hidden in
the UI when their env vars are not set, so you can run the example with just
the three required Kenni variables.

## What each button does

- **Continue with Kenni** — `GET /auth/login` builds the Authorization Code +
  PKCE URL via `oauth2.Config.AuthCodeURL` and redirects.
- **Call protected resource** — `GET /api/me` retrieves the user's Kenni
  access token (auto-refreshed via `oauth2.Config.TokenSource` if expired)
  and uses it to call this app's own `/api/protected-resource`. That
  endpoint verifies the bearer token via `provider.Verifier` (issuer,
  audience, signature, expiry) and additionally checks that the configured
  `KENNI_API_SCOPE` is present on the token.
- **Client credentials grant** — `POST /api/client-credentials` POSTs
  `grant_type=client_credentials` to Kenni's discovered token endpoint with
  HTTP Basic auth and decodes the resulting access token's claims for
  display.
- **Sign out (local)** — clears the local session cookie only. Kenni's
  session cookie is untouched, so the next sign-in is silent.
- **RP-initiated logout** — clears the local session and then redirects the
  browser to Kenni's discovered `end_session_endpoint` with `id_token_hint`,
  `post_logout_redirect_uri`, and `client_id` so Kenni clears its session
  too.
