import { Page } from 'playwright';
import { AppConfig } from '../config/schema';
import { AuthFlowResult, loginAsRole, logoutRole } from './auth.flow';
import { EvidencePaths, captureFailureEvidence } from '../utils/evidence';
import { Logger, Severity } from '../utils/logger';
import { ConsoleWatcher } from '../watchers/console.watcher';
import { NetworkWatcher } from '../watchers/network.watcher';

export type SuperAdminFlowResult = {
  role: 'superAdmin';
  flow: 'superAdmin';
  step: string;
  severity: Severity;
  details: string;
  screenshotPath?: string;
  htmlPath?: string;
};

export type SuperAdminFlowOptions = {
  logger: Logger;
  evidenceDirs: EvidencePaths;
  consoleWatcher: ConsoleWatcher;
  networkWatcher: NetworkWatcher;
};

/** Runs super-admin platform operations including account toggle workflow. */
export async function runSuperAdminFlow(
  page: Page,
  config: AppConfig,
  options: SuperAdminFlowOptions
): Promise<SuperAdminFlowResult[]> {
  const out: SuperAdminFlowResult[] = [];
  setContext(options);
  out.push(...mapAuthResults(await loginAsRole(page, config, 'superAdmin', authOptions(options))));
  await runStep(page, options, out, 'view-all-companies', (p) => viewAllCompanies(p, config.baseURL));
  await runStep(page, options, out, 'view-all-users', (p) => viewAllUsers(p, config.baseURL));
  await runStep(page, options, out, 'deactivate-test-account', deactivateTestAccount);
  await runStep(page, options, out, 'reactivate-test-account', reactivateTestAccount);
  out.push(...mapAuthResults(await logoutRole(page, 'superAdmin', authOptions(options))));
  return out;
}

/** Converts super-admin flow options to auth helper option format. */
function authOptions(options: SuperAdminFlowOptions) {
  return {
    logger: options.logger,
    evidenceDirs: options.evidenceDirs,
    consoleWatcher: options.consoleWatcher,
    networkWatcher: options.networkWatcher
  };
}

/** Opens platform companies page and asserts listing rows are visible. */
async function viewAllCompanies(page: Page, baseURL: string): Promise<void> {
  await page.goto(`${baseURL}/superadmin/companies`, { waitUntil: 'domcontentloaded' });
  await page.locator('[data-testid="company-row"], table tbody tr').first().waitFor({ state: 'visible', timeout: 12_000 });
}

/** Opens global users page and validates user rows are rendered. */
async function viewAllUsers(page: Page, baseURL: string): Promise<void> {
  await page.goto(`${baseURL}/superadmin/users`, { waitUntil: 'domcontentloaded' });
  await page.locator('[data-testid="user-row"], table tbody tr').first().waitFor({ state: 'visible', timeout: 12_000 });
}

/** Deactivates first eligible test account from platform users list. */
async function deactivateTestAccount(page: Page): Promise<void> {
  await page.goto('/superadmin/users', { waitUntil: 'domcontentloaded' });
  await page.getByRole('button', { name: /deactivate/i }).first().click();
  const confirm = page.getByRole('button', { name: /confirm|yes/i }).first();
  if (await confirm.isVisible().catch(() => false)) await confirm.click();
  await page.waitForLoadState('networkidle');
}

/** Reactivates first previously deactivated test account. */
async function reactivateTestAccount(page: Page): Promise<void> {
  await page.goto('/superadmin/users?filter=inactive', { waitUntil: 'domcontentloaded' });
  await page.getByRole('button', { name: /reactivate|activate/i }).first().click();
  const confirm = page.getByRole('button', { name: /confirm|yes/i }).first();
  if (await confirm.isVisible().catch(() => false)) await confirm.click();
  await page.waitForLoadState('networkidle');
}

/** Runs one super-admin step with fail evidence and typed result output. */
async function runStep(
  page: Page,
  options: SuperAdminFlowOptions,
  out: SuperAdminFlowResult[],
  step: string,
  fn: (page: Page) => Promise<void>
): Promise<void> {
  setContext(options);
  options.logger.info('superAdmin', 'superAdmin', step, 'started');
  try {
    await fn(page);
    out.push(result(step, 'PASS', 'ok'));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const ev = await captureFailureEvidence(page, options.evidenceDirs, `superAdmin-${step}`);
    options.logger.fail('superAdmin', 'superAdmin', step, message);
    out.push(result(step, 'FAIL', message, ev.screenshotPath, ev.htmlPath));
  }
}

/** Applies super-admin role context to all shared watcher streams. */
function setContext(options: SuperAdminFlowOptions): void {
  options.consoleWatcher.setContext('superAdmin', 'superAdmin');
  options.networkWatcher.setContext('superAdmin', 'superAdmin');
}

/** Creates a normalized super-admin result object. */
function result(
  step: string,
  severity: Severity,
  details: string,
  screenshotPath?: string,
  htmlPath?: string
): SuperAdminFlowResult {
  return { role: 'superAdmin', flow: 'superAdmin', step, severity, details, screenshotPath, htmlPath };
}

/** Converts shared auth results into super-admin flow result entries. */
function mapAuthResults(items: AuthFlowResult[]): SuperAdminFlowResult[] {
  return items.map((item) => ({
    role: 'superAdmin',
    flow: 'superAdmin',
    step: `auth:${item.step}`,
    severity: item.severity,
    details: item.details,
    screenshotPath: item.screenshotPath,
    htmlPath: item.htmlPath
  }));
}
