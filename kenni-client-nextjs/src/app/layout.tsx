import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

import { RootProvider } from "@kenni-example/components/providers";

import { getSession } from "./session";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Create Next App",
  description: "Generated by create next app",
};

const RootLayout = async ({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) => {
  const session = await getSession();

  return (
    <html lang="en">
      <body className={inter.className}>
        <RootProvider session={session}>{children}</RootProvider>
      </body>
    </html>
  );
};

export default RootLayout;
