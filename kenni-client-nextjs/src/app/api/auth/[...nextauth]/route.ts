import NextAuth from "next-auth";

import { authOptions } from "@kenni-example/utils/auth";

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
