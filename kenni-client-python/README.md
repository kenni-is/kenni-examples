# Kenni — Python (Flask + Authlib) example

Sign in with Kenni from a Flask app, using
[Authlib](https://docs.authlib.org/) — the de facto OIDC client library for
Python.

Demonstrates:

- Login (Authorization Code + PKCE).
- RP-initiated logout (clears the local session **and** Kenni's session).
- Calling a protected API endpoint with the user's access token.
- A client-credentials grant (M2M).

The corresponding doc is
[Python](https://developers.kenni.is/docs/guides/python).

Sessions live in Flask's signed-cookie session — no database. Tokens are
stored on the session, visible to anyone with the cookie. Fine for a demo;
for production move tokens server-side (Redis / DB) or switch to encrypted
cookies via [`flask-session`](https://flask-session.readthedocs.io/).

The Authlib API used here is identical for **FastAPI / Starlette** apps —
swap the `flask_client` import for `starlette_client`, make the route bodies
`async`, and the rest is the same.

## What to register in the Kenni developer portal

In the [developer portal](https://developers.kenni.is), open your application
and add the following:

| Setting | Value |
|---|---|
| **Redirect URI** | `http://localhost:5001/auth/callback` |
| **Post-logout redirect URI** | `http://localhost:5001/` |
| **Scopes** | `openid`, `profile`, `national_id`, `offline_access`, plus your API scope (if any) |

If you want to try the **client-credentials grant**, register a *second*
application in the portal as a machine-to-machine client and put its
credentials in `KENNI_M2M_CLIENT_ID` / `KENNI_M2M_CLIENT_SECRET`, plus the
scope it should request in `KENNI_M2M_SCOPE`.

## Run

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

cp .env.example .env
# Edit .env — at minimum, set FLASK_SECRET, KENNI_ISSUER,
# KENNI_CLIENT_ID, KENNI_CLIENT_SECRET.

.venv/bin/python app.py
```

(We use the explicit `.venv/bin/...` paths so the example works regardless
of whether your shell has `python` aliased elsewhere — a common source of
"module not found" surprises after `source .venv/bin/activate`.)

Open <http://localhost:5001> and click **Continue with Kenni**.

## Environment variables

See [`.env.example`](./.env.example) — every variable is documented inline.
The two optional features (API call, client credentials) are auto-hidden in
the UI when their env vars are not set, so you can run the example with just
`FLASK_SECRET` plus the three required Kenni variables.

## What each button does

- **Continue with Kenni** — `GET /auth/login` calls
  `oauth.kenni.authorize_redirect`, which builds the Authorization Code +
  PKCE URL and redirects.
- **Call protected resource** — `GET /api/me` retrieves the user's Kenni
  access token from the session and uses it to call this app's own
  `/api/protected-resource`. That endpoint verifies the bearer token via
  Authlib's JWT decoder against the cached JWKS (issuer, audience,
  signature, expiry) and additionally checks that the configured
  `KENNI_API_SCOPE` is on the token.
- **Client credentials grant** — `POST /api/client-credentials` POSTs
  `grant_type=client_credentials` to Kenni's discovered token endpoint with
  HTTP Basic auth and decodes the resulting access token's claims for
  display.
- **Sign out (local)** — `session.clear()`. Kenni's session cookie is
  untouched, so the next sign-in is silent.
- **RP-initiated logout** — clears the local session, then redirects the
  browser to Kenni's discovered `end_session_endpoint` with `id_token_hint`,
  `post_logout_redirect_uri`, and `client_id` so Kenni clears its session
  too.
