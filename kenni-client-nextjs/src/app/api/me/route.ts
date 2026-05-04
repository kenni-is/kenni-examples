import { headers } from "next/headers";

import { auth } from "@kenni-example/lib/auth";
import { env, features } from "@kenni-example/lib/env";

// Server route that retrieves the user's stored Kenni access token (better-auth
// auto-refreshes it if expired) and uses it to call our own /api/protected-resource.
// We do this server-side because the access token never leaves the server.
export async function GET(req: Request) {
  if (!features.apiCall) {
    return Response.json(
      { error: "KENNI_API_SCOPE is not configured on this app." },
      { status: 503 },
    );
  }

  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) {
    return Response.json({ error: "Not signed in." }, { status: 401 });
  }

  let accessToken: string;
  try {
    const result = await auth.api.getAccessToken({
      body: { providerId: "kenni", userId: session.user.id },
    });
    if (!result.accessToken) throw new Error("no access token returned");
    accessToken = result.accessToken;
  } catch (error) {
    return Response.json(
      { error: "Could not retrieve access token.", detail: String(error) },
      { status: 500 },
    );
  }

  const origin = new URL(req.url).origin;
  const response = await fetch(`${origin}/api/protected-resource`, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  const body = await response.json();
  return Response.json(body, { status: response.status });
}
