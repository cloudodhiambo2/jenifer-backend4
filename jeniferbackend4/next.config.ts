import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  // Ensure Pages Router API routes are included
  experimental: {
    // This ensures both App Router and Pages Router work together
  },
};

export default nextConfig;
