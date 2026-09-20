import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /** Allow the Freebuff preview host to load Next.js dev resources (HMR, fonts). */
  allowedDevOrigins: ["*.e2b.app"],
};

export default nextConfig;
