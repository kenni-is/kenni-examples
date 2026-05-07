// Minimal base64url JWT payload decoder. We only use it to display the
// id_token claims — token signature verification happens server-side at
// the token endpoint as part of the OIDC code exchange.
export const decodeJwtPayload = (token: string): Record<string, unknown> => {
  const segment = token.split(".")[1];
  if (!segment) throw new Error("Malformed JWT: missing payload segment");
  const padded = segment + "=".repeat((4 - (segment.length % 4)) % 4);
  const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const json =
    typeof atob === "function"
      ? atob(base64)
      : Buffer.from(base64, "base64").toString("utf8");
  return JSON.parse(json) as Record<string, unknown>;
};
