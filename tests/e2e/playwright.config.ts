import { defineConfig, devices } from "@playwright/test";

// Runs against a live stack: `docker compose up -d` first. Set E2E_BASE_URL to target another host.
export default defineConfig({
  testDir: ".",
  timeout: 120_000,
  expect: { timeout: 15_000 },
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: { baseURL: process.env.E2E_BASE_URL || "http://localhost:3000", trace: "retain-on-failure", screenshot: "only-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
