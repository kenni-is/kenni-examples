import { getServerSession } from "next-auth";

import { authOptions } from "@kenni-example/utils/auth";

export const getSession = async () => {
  return getServerSession(authOptions);
};
