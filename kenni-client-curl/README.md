# Kenni — curl example (no framework)

Walk through every step of an OpenID Connect / OAuth 2.0 integration with
Kenni using nothing but `bash`, `curl`, `openssl`, and `jq`. There's no web
server (other than a tiny `python3 -m http.server` that hosts the redirect
landing page) and no library — every script issues, by hand, the HTTP
request that the protocol calls for.

This example exists to make the *protocol* concrete. Every framework guide
in this repo is, ultimately, a way to delegate the work below to a library.

The corresponding doc is
[No framework (curl)](https://developers.kenni.is/docs/guides/curl).

## When this is (and isn't) useful

This **is not a production-shaped reference.** Don't ship a Kenni
integration as a pile of bash scripts. The other examples in this repo
(Express, Spring, .NET, Python, Go, Next.js) are the ones modelled on what
you'd actually deploy — pick whichever one matches your stack.

This **is** useful for:

- **Learning the protocol.** Reading "Spring auto-configures OIDC discovery
  and token exchange" tells you nothing about what's happening on the wire.
  Stepping through these scripts once shows you exactly which HTTP requests
  go where, what each parameter is for, and what the responses look like.
- **Debugging your real integration.** When your library setup misbehaves
  with an unhelpful error ("Invalid credentials", "redirect_uri_mismatch",
  "invalid_token", an empty 401), running the same flow by hand isolates
  whether the problem is your library config, your portal registration, or
  Kenni itself. The numbered scripts give you a known-good baseline to
  bisect against.
- **Bootstrapping an integration in a stack we don't have an example for.**
  Ruby, Rust, Elixir, PHP — the protocol is the same. If you can read the
  curl + JSON, you can write the equivalent in any language.
- **Manually issuing tokens for a script or test.** `06-client-credentials.sh`
  in particular is a self-contained way to grab an M2M access token from
  the terminal — handy for poking at a Kenni-protected API during
  development.

It is **not** useful as a deployment template, a starting skeleton, or a
reference for how to structure an OIDC client in a real application.
Sessions live in plaintext files under `.session/`, the JWT verifier is a
demonstration of the algorithm rather than a hardened implementation, and
shell-only OIDC has no story for concurrency, refresh races, or anything
else a real server has to handle.

Demonstrates:

- **Login** (Authorization Code + PKCE): `01-discover.sh` → `02-login.sh` → `03-exchange.sh`.
- **User-info call**: `04-userinfo.sh`.
- **Bearer-protected API**: `05-protected-resource.sh` — locally verifies an
  access-token JWT against Kenni's JWKS (RS256 signature, `iss`, `aud`,
  `exp`, required scope), then renders the JSON payload an actual API
  endpoint would return.
- **Refresh-token grant**: `07-refresh.sh`.
- **Client-credentials grant** (M2M): `06-client-credentials.sh`.
- **RP-initiated logout**: `08-logout.sh`.

Session state (discovery doc, JWKS, PKCE verifier, tokens, …) lives in
`.session/`. Each script reads from / writes to that directory.

## What to register in the Kenni developer portal

Open your application in the [developer portal](https://developers.kenni.is)
and add:

| Setting | Value |
|---|---|
| **Redirect URI** | `http://localhost:8000/callback` |
| **Post-logout redirect URI** | `http://localhost:8000/` |
| **Scopes** | `openid`, `profile`, `national_id`, `offline_access`, plus your API scope (if any) |

For the **client-credentials grant**, register a *second* application in the
portal as a machine-to-machine client and put its credentials in
`KENNI_M2M_CLIENT_ID` / `KENNI_M2M_CLIENT_SECRET`, plus the scope it should
request in `KENNI_M2M_SCOPE`.

## Run

You'll need `bash` (the scripts work on macOS's bash 3.2 and on Linux bash
4+), `curl`, `openssl`, `jq`, `xxd`, and `python3` (only for the static
server).

```bash
cp .env.example .env
# Edit .env — at minimum, set KENNI_ISSUER, KENNI_CLIENT_ID, KENNI_CLIENT_SECRET.

# Terminal 1 — static-file server for the redirect landing page.
./serve.sh

# Terminal 2 — walk through the flow.
./01-discover.sh
./02-login.sh                                 # opens the Kenni login in your browser
# Sign in. The browser redirects to http://localhost:8000/callback?code=…&state=…
# That page shows you the exact command to run next.
./03-exchange.sh '<paste the full callback URL here>'

./04-userinfo.sh                              # GET /oidc/me with the access token
./05-protected-resource.sh                    # only when KENNI_API_SCOPE is set
./06-client-credentials.sh                    # only when KENNI_M2M_* are set
./07-refresh.sh                               # use the refresh token

./08-logout.sh                                # RP-initiated logout
```

## What each script does

- **`01-discover.sh`** — `GET /.well-known/openid-configuration` and `GET <jwks_uri>`. Caches both in `.session/`.
- **`02-login.sh`** — Generates a PKCE verifier + S256 challenge, plus `state` and `nonce`. Builds the authorization URL with `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`. Opens it in your browser.
- **`03-exchange.sh`** — Parses the callback URL you paste in. Verifies the returned `state` matches the one we sent. POSTs `grant_type=authorization_code` with `code_verifier` to the token endpoint. Verifies the returned `id_token` (signature against JWKS, `iss`, `aud`, `exp`, `nonce`).
- **`04-userinfo.sh`** — `GET /oidc/me` with `Authorization: Bearer <access_token>`.
- **`05-protected-resource.sh`** — Demonstrates the *server* side of an API call. Pulls the user's access token, then verifies it locally as a Kenni-issued JWT: signature against the cached JWKS (RS256), `iss = KENNI_ISSUER`, `aud = KENNI_API_AUDIENCE`, `exp` in the future, required `KENNI_API_SCOPE` on the `scope` claim. On success, renders a small JSON payload (the kind a real API endpoint would return). Skipped unless `KENNI_API_SCOPE` is set in `.env` — Kenni access tokens become JWTs only when an API scope is requested at sign-in.
- **`06-client-credentials.sh`** — `POST grant_type=client_credentials` to the token endpoint with HTTP Basic auth on `KENNI_M2M_CLIENT_ID:KENNI_M2M_CLIENT_SECRET`. Decodes the resulting access-token claims for display. Skipped unless all `KENNI_M2M_*` values are set.
- **`07-refresh.sh`** — `POST grant_type=refresh_token`. Replaces the cached tokens.
- **`08-logout.sh`** — Clears the local session (deletes the cached tokens) *then* redirects the browser to Kenni's discovered `end_session_endpoint` with `id_token_hint`, `post_logout_redirect_uri`, and `client_id`. Order matters: clear local state *before* the redirect so a failed RP-logout still leaves you signed out locally.

## What "verifying a JWT in bash" actually entails

`05-protected-resource.sh` and `03-exchange.sh` both verify a JWT signature
without a library. The code is in [`lib.sh`](./lib.sh) (`verify_jwt_rs256`)
and follows the standard recipe:

1. Split the token on `.` into header, payload, and signature.
2. Read the JOSE header's `alg` (must be `RS256`) and `kid`.
3. Find the matching key in the cached JWKS by `kid`.
4. Convert the JWK's `n` and `e` (base64url-encoded RSA modulus and
   exponent) into a PEM-encoded SubjectPublicKeyInfo via
   `openssl asn1parse -genconf` followed by `openssl rsa -pubout`. The
   modulus needs a leading `00` byte if its high bit is set (ASN.1
   INTEGER is two's-complement).
5. Decode the base64url signature into raw bytes.
6. Run `printf '%s' "<header>.<payload>" | openssl dgst -sha256 -verify
   pubkey.pem -signature sig.bin`.

Plus the claim checks (`iss`, `aud`, `exp`, scope) — all done with `jq` and
`date +%s`. None of this is bash-specific magic; every OIDC library on the
list does these same steps under the hood.

## Environment variables

See [`.env.example`](./.env.example) — every variable is documented inline.
The two optional features (API call, client credentials) are skipped by the
relevant scripts when their env vars are not set, so you can run the example
with just the five required Kenni variables.
