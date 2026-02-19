import { Page } from 'playwright';
import { AppConfig } from '../config/schema';
import { EvidencePaths, captureFailureEvidence } from '../utils/evidence';
import { Logger, Severity } from '../utils/logger';
import { ConsoleWatcher } from '../watchers/console.watcher';
import { NetworkWatcher } from '../watchers/network.watcher';

export type RoleName = keyof AppConfig['credentials'];

export type AuthFlowResult = {
  role: RoleName;
  flow: 'auth';
  step: string;
  severity: Severity;
  details: string;
  screenshotPath?: string;
  htmlPath?: string;
};

export type AuthFlowOptions = {
  logger: Logger;
  evidenceDirs: EvidencePaths;
  consoleWatcher: ConsoleWatcher;
  networkWatcher: NetworkWatcher;
  dashboardSelector?: string;
  logoutButtonText?: RegExp;
};

/** Logs in a specific role account and validates dashboard access. */
export async function loginAsRole(
  page: Page,
  config: AppConfig,
  role: RoleName,
  options: AuthFlowOptions
): Promise<AuthFlowResult[]> {
  const results: AuthFlowResult[] = [];
  const creds = config.credentials[role];
  const c0 = options.consoleWatcher.getLogs().length;
  setContext(options, role);
  await runStep(page, role, 'open-login', options, results, async () => {
    await page.goto(`${config.baseURL}/login`, { waitUntil: 'domcontentloaded' });
  });
  await runStep(page, role, 'fill-credentials', options, results, async () => {
    await page.getByLabel('Email').fill(creds.email);
    await page.getByLabel('Password').fill(creds.password);
  });
  await runStep(page, role, 'submit-login', options, results, async () => {
    await page.getByRole('button', { name: /login|sign in/i }).click();
    await page.waitForLoadState('networkidle');
  });
  await runStep(page, role, 'validate-dashboard', options, results, async () => {
    await page.locator(options.dashboardSelector ?? '[data-testid="dashboard"]').first().waitFor({ state: 'visible', timeout: 12_000 });
    const errors = options.consoleWatcher.getLogs().slice(c0).filter((item) => item.level === 'error');
    if (errors.length) throw new Error(`Console errors after login: ${errors.length}`);
  });
  return results;
}

/** Logs out current role session and verifies return to anonymous state. */
export async function logoutRole(page: Page, role: RoleName, options: AuthFlowOptions): Promise<AuthFlowResult[]> {
  const results: AuthFlowResult[] = [];
  setContext(options, role);
  await runStep(page, role, 'open-user-menu', options, results, async () => {
    await page.getByRole('button', { name: /account|profile|menu/i }).first().click();
  });
  await runStep(page, role, 'submit-logout', options, results, async () => {
    await page.getByRole('button', { name: options.logoutButtonText ?? /logout|sign out/i }).first().click();
    await page.waitForLoadState('networkidle');
  });
  await runStep(page, role, 'validate-logout', options, results, async () => {
    await page.getByRole('button', { name: /login|sign in/i }).first().waitFor({ state: 'visible', timeout: 10_000 });
  });
  return results;
}

/** Executes one auth step, capturing evidence on FAIL outcomes. */
async function runStep(
  page: Page,
  role: RoleName,
  step: string,
  options: AuthFlowOptions,
  out: AuthFlowResult[],
  fn: () => Promise<void>
): Promise<void> {
  options.logger.info(role, 'auth', step, 'started');
  try {
    await fn();
    out.push({ role, flow: 'auth', step, severity: 'PASS', details: 'ok' });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    options.logger.fail(role, 'auth', step, message);
    const evidence = await captureFailureEvidence(page, options.evidenceDirs, `auth-${role}-${step}`);
    out.push({ role, flow: 'auth', step, severity: 'FAIL', details: message, screenshotPath: evidence.screenshotPath, htmlPath: evidence.htmlPath });
  }
}

/** Applies role/flow context to shared watchers before each auth phase. */
function setContext(options: AuthFlowOptions, role: RoleName): void {
  options.consoleWatcher.setContext(role, 'auth');
  options.networkWatcher.setContext(role, 'auth');
}
