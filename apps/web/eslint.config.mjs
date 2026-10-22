import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";

export default defineConfig([
  ...nextVitals,
  {
    rules: {
      // Sign-in, sign-out and org switching deliberately do a full page load so that all cached data and
      // the CSRF token belong to exactly one session.
      "@next/next/no-location-assign-relative-destination": "off",
    },
  },
  globalIgnores([".next/**", "node_modules/**", "e2e/**", "next-env.d.ts", "postcss.config.mjs"]),
]);
