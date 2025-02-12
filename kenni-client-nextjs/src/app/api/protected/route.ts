import { getToken } from "next-auth/jwt";
import { NextRequest } from "next/server";
import * as jose from "jose";

import { cookies } from "@kenni-example/utils/cookies";

const issuer = process.env.KENNI_ISSUER;
const clientId = process.env.KENNI_CLIENT_ID;
const apiScope = process.env.KENNI_API_SCOPE;
const secret = process.env.AUTH_SECRET;

const jwks = jose.createRemoteJWKSet(new URL(`${issuer}/oidc/jwks`));

export async function GET(req: NextRequest) {
  const { accessToken } =
    (await getToken({ req, cookieName: cookies.sessionToken.name, secret })) ??
    {};

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

    if (apiScope && !(payload?.scope as string).split(" ").includes(apiScope)) {
      throw new Error("required scope not present");
    }
  } catch (error) {
    return Response.json({ data: error }, { status: 403 });
  }

  return Response.json({ data: payload });
}
