# Kenni — React (SPA) example

Sign in with Kenni from a single-page React app, using
[`react-oidc-context`](https://github.com/authts/react-oidc-context) (a thin
hook-based wrapper around `oidc-client-ts`). Demonstrates:

- Login (Authorization Code + PKCE — public client, no secret).
- RP-initiated logout (clears the local user **and** Kenni's session).

The corresponding doc is
[React (SPA)](https://developers.kenni.is/docs/guides/react).

This is a **public client** — register it in the [developer portal](https://developers.kenni.is)
as a **Web (SPA)** application type. There is no `client_secret`; security
comes from PKCE.

## What to register in the Kenni developer portal

In the [developer portal](https://developers.kenni.is), open your application
and add the following:

| Setting | Value |
|---|---|
| **Application type** | Web (SPA) |
| **Redirect URI** | `http://localhost:3001/callback` |
| **Post-logout redirect URI** | `http://localhost:3001/` |
| **Scopes** | `openid`, `profile`, `national_id`, `offline_access` |

## Run

```bash
cp .env.example .env.local
# Edit .env.local — set KENNI_ISSUER and KENNI_CLIENT_ID for your application.

yarn install
yarn dev
```

Open <http://localhost:3001> and click **Continue with Kenni**.

## Environment variables

See [`.env.example`](./.env.example) — every variable is documented inline.

The variables are read at build time and inlined into the client bundle.
There are no secrets here (SPA is a public client), so this is safe.

`vite.config.ts` sets `envPrefix: 'KENNI_'`, which makes Vite expose
`KENNI_*` env vars to client code instead of the default `VITE_*`. This lets
this example use the same `KENNI_*` names as every other example in this
repo.

## What each button does

- **Continue with Kenni** — `auth.signinRedirect()`. Triggers the
  Authorization Code + PKCE flow. After Kenni redirects back to `/callback`,
  `react-oidc-context` exchanges the code for tokens, stores the user in
  `localStorage`, and `onSigninCallback` rewrites the URL back to `/`.
- **Sign out (local)** — `auth.removeUser()`. Clears the local user (token
  cache) only. Kenni's session cookie is untouched, so the next sign-in is
  silent.
- **RP-initiated logout** — `auth.signoutRedirect({ extraQueryParams: { client_id } })`.
  Redirects the browser to Kenni's `end_session_endpoint` with the
  `id_token_hint`, `post_logout_redirect_uri`, and `client_id`. Kenni
  clears its session and redirects back to `KENNI_POST_LOGOUT_REDIRECT_URI`.
  `oidc-client-ts` does not include `client_id` automatically, so we forward
  it via `extraQueryParams` — Kenni requires it on the end-session request.

## JSON output panel

When signed in, the panel under the buttons shows
`auth.user.profile` — the OIDC claims from the id_token (sub, name,
national_id, …). This is what an SPA can prove about the signed-in user
without making a single network call.
