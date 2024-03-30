import * as oidcClient from "openid-client";

const issuer = process.env.KENNI_ISSUER as string;

const clientId = process.env.KENNI_M2M_CLIENT_ID;
const clientSecret = process.env.KENNI_M2M_CLIENT_SECRET;

export async function GET() {
  if (!clientId || !clientSecret) {
    return Response.json(
      { data: "client credentials not found" },
      { status: 401 }
    );
  }

  // Discovered issuer should be cached
  const oidcIssuer = await oidcClient.Issuer.discover(issuer);
  const client = new oidcIssuer.Client({
    client_id: clientId,
    client_secret: clientSecret,
  });

  const tokenSet = await client.grant({
    grant_type: "client_credentials",
    scope: "@test-1/test",
  });

  return Response.json({ data: tokenSet });
}
