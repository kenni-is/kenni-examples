import * as jose from "jose";

import { discover } from "@kenni-example/lib/discovery";
import { env, features } from "@kenni-example/lib/env";

export async function POST() {
  if (!features.clientCredentials) {
    return Response.json(
      {
        error:
          "Client credentials feature is not configured. Set KENNI_M2M_CLIENT_ID, KENNI_M2M_CLIENT_SECRET, and KENNI_M2M_SCOPE.",
      },
      { status: 503 },
    );
  }

  const { token_endpoint } = await discover();

  // Send credentials via Basic auth (RFC 6749 §2.3.1 preferred form).
  const basic = Buffer.from(
    `${encodeURIComponent(env.KENNI_M2M_CLIENT_ID)}:${encodeURIComponent(env.KENNI_M2M_CLIENT_SECRET)}`,
  ).toString("base64");

  const body = new URLSearchParams({
    grant_type: "client_credentials",
    scope: env.KENNI_M2M_SCOPE,
  });

  const response = await fetch(token_endpoint, {
    method: "POST",
    headers: {
      authorization: `Basic ${basic}`,
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body,
  });

  const tokenSet = await response.json();
  if (!response.ok) {
    return Response.json(
      { error: "Token endpoint rejected the request.", detail: tokenSet },
      { status: response.status },
    );
  }

  // Decode (don't verify) so the demo shows what's inside the token.
  let claims: jose.JWTPayload | null = null;
  try {
    claims = jose.decodeJwt(tokenSet.access_token);
  } catch {
    /* opaque token — leave claims null */
  }

  return Response.json({
    token_type: tokenSet.token_type,
    expires_in: tokenSet.expires_in,
    scope: tokenSet.scope,
    claims,
  });
}
