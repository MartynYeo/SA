import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: 'standalone',
  /* Expose shared env flag to the browser bundle */
  env: {
    NEXT_PUBLIC_LLM_DISABLED: process.env.LLM_DISABLED,
  },
};

export default nextConfig;
