import { getToken } from "next-auth/jwt";
import { NextRequest } from "next/server";
import * as jose from "jose";

import { cookies } from "@kenni-example/utils/cookies";

const issuer = process.env.KENNI_ISSUER;
const jwksUri = process.env.KENNI_ISSUER_JWKS_URI;
const clientId = process.env.KENNI_CLIENT_ID;

const jwks = jose.createRemoteJWKSet(new URL(jwksUri as string));

export async function GET(req: NextRequest) {
  const { accessToken } =
    (await getToken({ req, cookieName: cookies.sessionToken.name })) ?? {};

  if (!accessToken) {
    return Response.json({ data: "access denied" }, { status: 401 });
  }

  let payload;
  try {
    const res = await jose.jwtVerify(accessToken, jwks, {
      issuer,
      audience: `${clientId}-api`,
    });
    payload = res.payload;
  } catch (error) {
    return Response.json({ data: error }, { status: 403 });
  }

  return Response.json({ data: payload });
}
