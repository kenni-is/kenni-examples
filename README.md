# Kenni Examples

Reference example apps for integrating with [Kenni](https://kenni.is) — one per integration guide, all built to the same spec, all using the latest version of the recommended library for that stack.

To run any example you'll need a Kenni team and a client application. Create both in the [Kenni Developer Portal](https://developers.kenni.is). The integration guides live at [developers.kenni.is/docs](https://developers.kenni.is/docs) — each example below maps to one guide.

## Server apps

Full demo: login, RP-initiated logout, an `/api/protected-resource` endpoint that verifies a Kenni access token, and a client-credentials grant.

| Stack | Example | Guide |
|---|---|---|
| Next.js + better-auth | [`kenni-client-nextjs`](./kenni-client-nextjs) | [Next.js / better-auth](https://developers.kenni.is/docs/guides/better-auth) |
| Node.js / Express + `openid-client` | [`kenni-client-express`](./kenni-client-express) | [Node.js / Express](https://developers.kenni.is/docs/guides/express) |
| Java / Spring Boot | [`kenni-client-java`](./kenni-client-java) | [Spring Boot](https://developers.kenni.is/docs/guides/spring-boot) |
| C# / ASP.NET Core MVC | [`kenni-client-dotnet`](./kenni-client-dotnet) | [.NET MVC](https://developers.kenni.is/docs/guides/dotnet) |
| Go (`oauth2` + `go-oidc`) | [`kenni-client-go`](./kenni-client-go) | [Go](https://developers.kenni.is/docs/guides/go) |
| Python / Flask + Authlib | [`kenni-client-python`](./kenni-client-python) | [Python](https://developers.kenni.is/docs/guides/python) |
| No framework (bash + curl) | [`kenni-client-curl`](./kenni-client-curl) | [No framework](https://developers.kenni.is/docs/guides/no-framework) |

## Client apps

Login + RP-initiated logout only — no server component.

| Stack | Example | Guide |
|---|---|---|
| React SPA (Vite + `react-oidc-context`) | [`kenni-client-react`](./kenni-client-react) | [React](https://developers.kenni.is/docs/guides/react) |
| Expo / React Native | [`kenni-client-expo`](./kenni-client-expo) | [Expo](https://developers.kenni.is/docs/guides/expo) |
| Flutter (`flutter_appauth`) | [`kenni-client-flutter`](./kenni-client-flutter) | [Flutter](https://developers.kenni.is/docs/guides/flutter) |

Each example's `README.md` documents the local port, the redirect URIs to register in the portal, and the `KENNI_*` env vars to set.
