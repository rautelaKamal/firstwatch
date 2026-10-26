import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  cacheComponents: true,
  // The triage route reads example cases and saved runs from disk at request time.
  outputFileTracingIncludes: {
    // Examples and saved runs for replay, plus the committed cache seed (digests, NVD, advisory pages).
    "/api/triage": ["./eval/cases/**/*", "./fixtures/**/*", "./data/cache/**/*"],
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
