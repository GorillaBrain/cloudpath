import type { Metadata } from "next";
import "./globals.css";
import { CloudPathProvider } from "@/context/CloudPathContext";

export const metadata: Metadata = {
  title: "CloudPath — Cloud Attack Path Mapper & Identity Risk Intelligence",
  description:
    "Enterprise Cloud Security Posture Management (CSPM) & Attack Path Analysis Platform for AWS IAM, trust relationships, and exposed cloud assets.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
        <CloudPathProvider>{children}</CloudPathProvider>
      </body>
    </html>
  );
}
