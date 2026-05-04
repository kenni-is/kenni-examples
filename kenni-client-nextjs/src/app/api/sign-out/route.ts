import { headers } from "next/headers";

import { auth } from "@kenni-example/lib/auth";
import { discover } from "@kenni-example/lib/discovery";
import { env } from "@kenni-example/lib/env";

// GET /api/sign-out
//
// 1. Fetches the user's id_token from better-auth (stored in the account cookie).
// 2. Clears the local better-auth session.
// 3. Redirects the browser to Kenni's end_session_endpoint with id_token_hint,
//    post_logout_redirect_uri, and client_id so Kenni clears its session too.
//
// We do steps 1 and 2 even if no id_token is found, so a stale local session
// gets cleaned up regardless.
export async function GET(req: Request) {
  const requestHeaders = await headers();
  const session = await auth.api.getSession({ headers: requestHeaders });

  let idToken: string | undefined;
  if (session) {
    try {
      const result = await auth.api.getAccessToken({
        body: { providerId: "kenni", userId: session.user.id },
        headers: requestHeaders,
      });
      idToken = result.idToken;
    } catch {
      /* no Kenni account on this session — fine, we still want to sign out */
    }

    await auth.api.signOut({ headers: requestHeaders });
  }

  const postLogoutRedirectUri =
    new URL(req.url).searchParams.get("post_logout_redirect_uri") ??
    new URL(req.url).origin;

  const { end_session_endpoint } = await discover();
  const url = new URL(end_session_endpoint);
  url.searchParams.set("client_id", env.KENNI_CLIENT_ID);
  url.searchParams.set("post_logout_redirect_uri", postLogoutRedirectUri);
  if (idToken) url.searchParams.set("id_token_hint", idToken);

  return Response.redirect(url.toString());
}
