import { env } from "./env";

type Discovery = {
  token_endpoint: string;
  end_session_endpoint: string;
  jwks_uri: string;
  issuer: string;
};

let cached: Promise<Discovery> | null = null;

export function discover(): Promise<Discovery> {
  if (!cached) {
    cached = fetch(`${env.KENNI_ISSUER}/.well-known/openid-configuration`)
      .then((r) => {
        if (!r.ok) throw new Error(`discovery failed: HTTP ${r.status}`);
        return r.json();
      });
  }
  return cached;
}
