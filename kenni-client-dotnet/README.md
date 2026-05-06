# Kenni — ASP.NET Core (.NET 10) example

Sign in with Kenni from an ASP.NET Core MVC app, using the built-in
`Microsoft.AspNetCore.Authentication.OpenIdConnect` and
`Microsoft.AspNetCore.Authentication.JwtBearer` packages.

Demonstrates:

- Login (Authorization Code + PKCE).
- RP-initiated logout (clears the local cookie session **and** Kenni's session).
- Calling a protected API endpoint with the user's access token.
- A client-credentials grant (M2M).

## What to register in the Kenni developer portal

In the [developer portal](https://developers.kenni.is), open your application
and add the following:

| Setting | Value |
|---|---|
| **Redirect URI** | `http://localhost:5000/signin-oidc` |
| **Post-logout redirect URI** | `http://localhost:5000/signout-callback-oidc` |
| **Scopes** | `openid`, `profile`, `national_id`, `offline_access`, plus your API scope (if any) |

(`/signin-oidc` and `/signout-callback-oidc` are the default callback paths
the OpenIdConnect handler mounts; they're configurable via
`OpenIdConnectOptions.CallbackPath` / `SignedOutCallbackPath` if you'd
rather not use them.)

If you want to try the **client-credentials grant**, register a *second*
application in the portal as a machine-to-machine client and put its
credentials in `KENNI_M2M_CLIENT_ID` / `KENNI_M2M_CLIENT_SECRET`, plus the
scope it should request in `KENNI_M2M_SCOPE`.

## Run

```bash
cp .env.example .env
# Edit .env — at minimum, set KENNI_ISSUER, KENNI_CLIENT_ID, KENNI_CLIENT_SECRET.

dotnet run
```

Open <http://localhost:5000> and click **Continue with Kenni**.

## Environment variables

See [`.env.example`](./.env.example) — every variable is documented inline.
The two optional features (API call, client credentials) are auto-hidden in
the UI when their env vars are not set, so you can run the example with just
the three required Kenni variables.

## What each button does

- **Continue with Kenni** — challenges the OpenIdConnect handler, which
  redirects to Kenni for Authorization Code + PKCE.
- **Call protected resource** — calls `/api/me`, which retrieves the user's
  Kenni access token from the OIDC cookie session and uses it to call
  `/api/protected-resource`. That endpoint verifies the bearer token via
  `AddJwtBearer` (issuer, audience, signature, expiry) and additionally
  enforces the configured `KENNI_API_SCOPE` via an authorization policy.
- **Client credentials grant** — POSTs `grant_type=client_credentials` to
  Kenni's discovered token endpoint with HTTP Basic auth and decodes the
  resulting access token's claims for display.
- **Sign out (local)** — clears the local cookie session only. Kenni's
  session cookie is untouched, so the next sign-in is silent.
- **RP-initiated logout** — clears the local cookie session and then
  redirects the browser to Kenni's `end_session_endpoint` with
  `id_token_hint`, `post_logout_redirect_uri`, and `client_id` (the
  OpenIdConnect handler builds the URL automatically when you call
  `SignOut("oidc")`).
