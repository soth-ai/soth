import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Proxy API requests to the Rust backend during development
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://localhost:3001/api/:path*",
      },
    ];
  },
};

export default nextConfig;
