import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "ScamShield — Analyze suspicious messages before you act",
  description:
    "AI-assisted scam risk analysis for emails, SMS, WhatsApp messages and payment requests. Flags risk (HIGH/MEDIUM/LOW), explains why, and recommends safe next steps — without ever claiming certainty.",
  manifest: "/manifest.webmanifest",
  applicationName: "ScamShield",
  appleWebApp: {
    capable: true,
    statusBarStyle: "black-translucent",
    title: "ScamShield",
  },
  formatDetection: { telephone: false },
  openGraph: {
    title: "ScamShield — Analyze suspicious messages before you act",
    description:
      "Paste a suspicious message, link or screenshot. Get red flags, honest risk levels, and safe next steps — free, no sign-up.",
    type: "website",
    siteName: "ScamShield",
  },
  twitter: {
    card: "summary",
    title: "ScamShield — Analyze suspicious messages before you act",
    description: "Paste a suspicious message, link or screenshot. Get red flags and safe next steps.",
  },
  icons: {
    icon: [
      { url: "/icon.svg", type: "image/svg+xml" },
      { url: "/icon-192.png", sizes: "192x192", type: "image/png" },
      { url: "/icon-512.png", sizes: "512x512", type: "image/png" },
    ],
    apple: [{ url: "/apple-icon.png", sizes: "180x180", type: "image/png" }],
  },
};

export const viewport: Viewport = {
  themeColor: "#0a0a09",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
