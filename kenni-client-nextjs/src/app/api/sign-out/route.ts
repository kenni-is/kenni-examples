import { Issuer } from "openid-client";

export const GET = async (req: Request) => {
  const { searchParams } = new URL(req.url);
  const issuer = process.env.KENNI_ISSUER;

  if (!issuer) {
    throw new Error("Issuer is not set");
  }

  const hint = searchParams.get("hint");
  const postLogoutRedirectUri =
    searchParams.get("post_logout_redirect_uri") ?? "http://localhost:3000";

  const { metadata } = await Issuer.discover(issuer);
  const url = `${metadata.end_session_endpoint}?id_token_hint=${hint}&post_logout_redirect_uri=${postLogoutRedirectUri}`;

  return Response.redirect(url);
};
