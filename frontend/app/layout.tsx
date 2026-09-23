import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "sentinel / workflow",
  description: "Action firewall trace viewer",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
