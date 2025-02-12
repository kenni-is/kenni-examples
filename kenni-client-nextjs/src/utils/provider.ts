import { OAuthConfig, OAuthUserConfig } from "@auth/core/providers";

const issuer = process.env.KENNI_ISSUER;
const scope = process.env.KENNI_SCOPE;
const redirectUri = process.env.KENNI_REDIRECT_URI;
const clientId = process.env.KENNI_CLIENT_ID;
const clientSecret = process.env.KENNI_CLIENT_SECRET;
const apiScope = process.env.KENNI_API_SCOPE;

export interface KenniProfile extends Record<string, any> {
  sub: string;
  name: string;
  idToken: string;
  accessToken: string;
  refreshToken: string;
}

export default function Kenni(
  options: OAuthUserConfig<KenniProfile>
): OAuthConfig<KenniProfile> {
  return {
    id: "kenni",
    name: "Kenni NextJs Example",
    type: "oidc",
    issuer,
    authorization: {
      params: {
        scope: `${scope} ${apiScope}`,
        redirect_uri: redirectUri,
        ui_locale: "is", // Optional. Valid options, "is" or "en"
      },
    },
    clientId,
    clientSecret,
    idToken: true,
    checks: ["pkce", "state"],
    profile: (profile, tokens) => {
      return {
        id: profile.sub,
        sub: profile.sub,
        name: profile.name,
        accessToken: tokens.access_token ?? "",
        idToken: tokens.id_token ?? "",
        refreshToken: tokens.refresh_token ?? "",
      };
    },
  };
}
