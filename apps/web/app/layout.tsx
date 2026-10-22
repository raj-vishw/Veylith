import type { Metadata } from "next";
import { Fraunces, IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import "./globals.css";

// Self-hosted at build time by next/font (no runtime request to Google, compatible with the strict CSP).
const display = Fraunces({ subsets: ["latin"], variable: "--font-display", display: "swap", axes: ["opsz"] });
const body = IBM_Plex_Sans({ subsets: ["latin"], variable: "--font-body", weight: ["400", "500", "600"], display: "swap" });
const code = IBM_Plex_Mono({ subsets: ["latin"], variable: "--font-code", weight: ["400", "500"], display: "swap" });

export const metadata: Metadata = {
  title: "Veylith — third-party incident impact intelligence",
  description: "Trace external security events through vendor dependencies to the clients and assets that need investigation.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${display.variable} ${body.variable} ${code.variable}`}>
      <body>{children}</body>
    </html>
  );
}
