import { defineConfig } from 'playwright';

/**
 * Base Playwright configuration for autonomous flow and attack execution.
 * Environment-specific logic remains in testRunner.ts.
 */
export default defineConfig({
  testDir: './',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: [['list']],
  use: {
    actionTimeout: 20_000,
    navigationTimeout: 45_000,
    ignoreHTTPSErrors: true,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    video: 'off'
  }
});
