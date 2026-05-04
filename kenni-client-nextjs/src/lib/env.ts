function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required env var: ${name}`);
  return value;
}

export const env = {
  KENNI_ISSUER: required("KENNI_ISSUER"),
  KENNI_CLIENT_ID: required("KENNI_CLIENT_ID"),
  KENNI_CLIENT_SECRET: required("KENNI_CLIENT_SECRET"),

  // Optional: enables the "API call" feature.
  KENNI_API_SCOPE: process.env.KENNI_API_SCOPE || "",
  // Audience claim to validate against on incoming bearer tokens.
  // Defaults to "<client_id>-api" which is the Kenni convention.
  KENNI_API_AUDIENCE:
    process.env.KENNI_API_AUDIENCE ||
    `${required("KENNI_CLIENT_ID")}-api`,

  // Optional: enables the "Client credentials" feature.
  // Typically a separate M2M client registered in the Kenni portal.
  KENNI_M2M_CLIENT_ID: process.env.KENNI_M2M_CLIENT_ID || "",
  KENNI_M2M_CLIENT_SECRET: process.env.KENNI_M2M_CLIENT_SECRET || "",
  KENNI_M2M_SCOPE: process.env.KENNI_M2M_SCOPE || "",
};

export const features = {
  apiCall: Boolean(env.KENNI_API_SCOPE),
  clientCredentials: Boolean(
    env.KENNI_M2M_CLIENT_ID && env.KENNI_M2M_CLIENT_SECRET && env.KENNI_M2M_SCOPE,
  ),
};
