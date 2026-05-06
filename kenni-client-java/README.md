# Kenni — Java / Spring Boot example

Sign in with Kenni from a Spring Boot 3 app, using Spring Security's OAuth 2.0
Client + Resource Server starters.

Demonstrates:

- Login (Authorization Code + PKCE).
- RP-initiated logout (clears the local session **and** Kenni's session).
- Calling a protected API endpoint with the user's access token.
- A client-credentials grant (M2M).

The corresponding doc is
[Java / Spring Boot](https://developers.kenni.is/docs/guides/spring-boot).

Sessions live in Spring's default in-memory `HttpSession` — fine for a demo.
For production, swap in `spring-session-data-redis` or similar.

## What to register in the Kenni developer portal

In the [developer portal](https://developers.kenni.is), open your application
and add the following:

| Setting | Value |
|---|---|
| **Redirect URI** | `http://localhost:8080/login/oauth2/code/kenni` |
| **Post-logout redirect URI** | `http://localhost:8080/` |
| **Scopes** | `openid`, `profile`, `national_id`, `offline_access`, plus your API scope (if any) |

(`/login/oauth2/code/{registrationId}` is the Spring-mounted callback path
for OAuth2 Login. It comes from the `redirect-uri` template in
`application.yml`.)

If you want to try the **client-credentials grant**, register a *second*
application in the portal as a machine-to-machine client and put its
credentials in `KENNI_M2M_CLIENT_ID` / `KENNI_M2M_CLIENT_SECRET`, plus the
scope it should request in `KENNI_M2M_SCOPE`.

## Run

```bash
cp application-local.yml.example application-local.yml
# Edit application-local.yml — at minimum, set issuer, client-id, client-secret.

./gradlew bootRun
```

Open <http://localhost:8080> and click **Continue with Kenni**.

`application-local.yml` is gitignored. `application.yml` imports it via
`spring.config.import: optional:file:application-local.yml`, so no profile
flag is required — Spring just picks it up at startup.

## Configuration

The required and optional properties live under `app.kenni.*`. `KenniProperties`
binds them as a typed record; `application-local.yml.example` documents every
field inline.

| Property | Env var | What it does |
|---|---|---|
| `app.kenni.issuer` | `KENNI_ISSUER` | OIDC issuer URL (no trailing slash). |
| `app.kenni.client-id` | `KENNI_CLIENT_ID` | OAuth client id. |
| `app.kenni.client-secret` | `KENNI_CLIENT_SECRET` | OAuth client secret. |
| `app.kenni.api-scope` | `KENNI_API_SCOPE` | Enables "Call protected resource". Also added to sign-in scopes. |
| `app.kenni.api-audience` | `KENNI_API_AUDIENCE` | Audience expected on incoming Kenni access tokens. Defaults to `<client-id>-api`. |
| `app.kenni.m2m-client-id` | `KENNI_M2M_CLIENT_ID` | Enables "Client credentials grant" (with `m2m-client-secret` and `m2m-scope`). |
| `app.kenni.m2m-client-secret` | `KENNI_M2M_CLIENT_SECRET` | M2M client secret. |
| `app.kenni.m2m-scope` | `KENNI_M2M_SCOPE` | Scope to request in the client-credentials grant. |

If you'd rather skip the YAML file and supply values via environment variables,
the env vars in the right column work identically — Spring resolves them into
the same `${...}` placeholders in `application.yml`. (Common for IDE run
configurations and 12-factor-style production deployment.)

## What each button does

- **Continue with Kenni** — links to `/oauth2/authorization/kenni`, the path
  Spring's OAuth2-Client filter mounts for the `kenni` registration. It
  handles state + PKCE + the redirect to Kenni. PKCE has to be wired
  explicitly via `OAuth2AuthorizationRequestCustomizers.withPkce()` — Spring
  Security 6 only auto-enables it for *public* clients, not for confidential
  clients like this one. See `KenniSecurityConfig#pkceAwareAuthorizationRequestResolver`.
- **Call protected resource** — `GET /api/me` retrieves the user's Kenni
  access token via `@RegisteredOAuth2AuthorizedClient("kenni")` and uses it
  to call this app's own `/api/protected-resource`. That endpoint sits
  behind a separate Spring `SecurityFilterChain` configured as an OAuth2
  Resource Server — `NimbusJwtDecoder` validates issuer/signature/expiry,
  a `JwtClaimValidator` enforces the configured audience, and the URL-level
  `hasAuthority("SCOPE_<api-scope>")` rule enforces the scope.
- **Client credentials grant** — `POST /api/client-credentials` POSTs
  `grant_type=client_credentials` to Kenni's discovered token endpoint
  (read from the `kenni` `ClientRegistration`) with HTTP Basic auth, then
  decodes the resulting access token's claims for display.
- **Sign out (local)** — invalidates the `HttpSession` and redirects home.
  Kenni's session cookie is untouched, so the next sign-in is silent.
- **RP-initiated logout** — invalidates the local session and redirects the
  browser to the URL built from Kenni's discovered `end_session_endpoint`
  with `id_token_hint`, `post_logout_redirect_uri`, and `client_id`.
