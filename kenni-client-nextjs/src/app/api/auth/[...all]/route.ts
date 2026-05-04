import { toNextJsHandler } from "better-auth/next-js";

import { auth } from "@kenni-example/lib/auth";

export const { GET, POST } = toNextJsHandler(auth);
