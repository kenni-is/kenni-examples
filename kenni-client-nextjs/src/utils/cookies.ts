const secure = process.env.NODE_ENV === "production";

const defaultCookieOptions = {
  httpOnly: true,
  sameSite: "lax" as const,
  path: "/",
  secure,
};

export const cookies = {
  sessionToken: {
    name: "kenni-example.session-token",
    options: defaultCookieOptions,
  },
  callbackUrl: {
    name: "kenni-example.callback-url",
    options: { ...defaultCookieOptions, httpOnly: false },
  },
  csrfToken: {
    name: "kenni-example.csrf-token",
    options: defaultCookieOptions,
  },
  pkceCodeVerifier: {
    name: "kenni-example.pkce.code_verifier",
    options: {
      ...defaultCookieOptions,
      maxAge: 30 * 60,
    },
  },
  state: {
    name: "kenni-example.state",
    options: {
      ...defaultCookieOptions,
      maxAge: 30 * 60,
    },
  },
  nonce: {
    name: "kenni-example.nonce",
    options: defaultCookieOptions,
  },
};
