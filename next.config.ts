import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  cacheComponents: true,
  // The triage route reads example cases and saved runs from disk at request time.
  outputFileTracingIncludes: {
    "/api/triage": ["./eval/cases/**/*", "./fixtures/**/*"],
  },
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
