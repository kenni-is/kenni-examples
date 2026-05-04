import * as jose from "jose";

import { discover } from "@kenni-example/lib/discovery";
import { env } from "@kenni-example/lib/env";

// Lazily-built JWKS keyset, keyed off the discovered jwks_uri.
let jwksPromise: Promise<ReturnType<typeof jose.createRemoteJWKSet>> | null = null;
function getJwks() {
  if (!jwksPromise) {
    jwksPromise = discover().then((d) =>
      jose.createRemoteJWKSet(new URL(d.jwks_uri)),
    );
  }
  return jwksPromise;
}

export async function GET(req: Request) {
  if (!env.KENNI_API_SCOPE) {
    return Response.json(
      { error: "KENNI_API_SCOPE is not configured on this app." },
      { status: 503 },
    );
  }

  const authz = req.headers.get("authorization");
  const token = authz?.toLowerCase().startsWith("bearer ")
    ? authz.slice(7).trim()
    : null;
  if (!token) {
    return Response.json(
      { error: "Missing Authorization: Bearer header." },
      { status: 401 },
    );
  }

  let payload: jose.JWTPayload;
  try {
    const jwks = await getJwks();
    const result = await jose.jwtVerify(token, jwks, {
      issuer: env.KENNI_ISSUER,
      audience: env.KENNI_API_AUDIENCE,
    });
    payload = result.payload;
  } catch (error) {
    return Response.json(
      { error: "Token verification failed.", detail: String(error) },
      { status: 401 },
    );
  }

  const scopes = String(payload.scope ?? "").split(" ").filter(Boolean);
  if (!scopes.includes(env.KENNI_API_SCOPE)) {
    return Response.json(
      {
        error: `Token is missing required scope '${env.KENNI_API_SCOPE}'.`,
        scopes,
      },
      { status: 403 },
    );
  }

  return Response.json({
    message: "Halló!",
    served_by: "Next.js / better-auth example",
    sub: payload.sub,
    national_id: payload.national_id,
    scopes,
    expires_at: payload.exp
      ? new Date(payload.exp * 1000).toISOString()
      : null,
  });
}
