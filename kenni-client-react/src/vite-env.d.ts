/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly KENNI_ISSUER: string;
  readonly KENNI_CLIENT_ID: string;
  readonly KENNI_REDIRECT_URI: string;
  readonly KENNI_POST_LOGOUT_REDIRECT_URI: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
