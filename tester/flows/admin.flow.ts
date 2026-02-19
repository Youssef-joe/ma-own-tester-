import { Page } from 'playwright';
import { AppConfig } from '../config/schema';
import { AuthFlowResult, loginAsRole, logoutRole } from './auth.flow';
import { EvidencePaths, captureFailureEvidence } from '../utils/evidence';
import { Logger, Severity } from '../utils/logger';
import { ConsoleWatcher } from '../watchers/console.watcher';
import { NetworkWatcher } from '../watchers/network.watcher';

export type CompanyAdminFlowResult = {
  role: 'companyAdmin';
  flow: 'companyAdmin';
  step: string;
  severity: Severity;
  details: string;
  screenshotPath?: string;
  htmlPath?: string;
};

export type CompanyAdminFlowOptions = {
  logger: Logger;
  evidenceDirs: EvidencePaths;
  consoleWatcher: ConsoleWatcher;
  networkWatcher: NetworkWatcher;
};

/** Runs company-admin workflow plus super-admin boundary validation. */
export async function runCompanyAdminFlow(
  page: Page,
  config: AppConfig,
  options: CompanyAdminFlowOptions
): Promise<CompanyAdminFlowResult[]> {
  const out: CompanyAdminFlowResult[] = [];
  setContext(options);
  out.push(...mapAuthResults(await loginAsRole(page, config, 'companyAdmin', authOptions(options))));
  await runStep(page, options, out, 'create-job-posting', (p) => createJobPosting(p, config.baseURL));
  await runStep(page, options, out, 'edit-job-posting', editJobPosting);
  await runStep(page, options, out, 'view-recruiter-activity', (p) => viewRecruiterActivity(p, config.baseURL));
  await assertForbiddenRoute(page, options, out, `${config.baseURL}/superadmin/dashboard`);
  out.push(...mapAuthResults(await logoutRole(page, 'companyAdmin', authOptions(options))));
  return out;
}

/** Adapts company-admin options for shared auth login/logout helpers. */
function authOptions(options: CompanyAdminFlowOptions) {
  return {
    logger: options.logger,
    evidenceDirs: options.evidenceDirs,
    consoleWatcher: options.consoleWatcher,
    networkWatcher: options.networkWatcher
  };
}

/** Creates a new job posting using required admin form fields. */
async function createJobPosting(page: Page, baseURL: string): Promise<void> {
  const title = `QA Auto Job ${Date.now()}`;
  await page.goto(`${baseURL}/admin/jobs/new`, { waitUntil: 'domcontentloaded' });
  await page.getByLabel('Job Title').fill(title);
  await page.getByLabel('Location').fill('Remote');
  await page.getByLabel('Description').fill('Automated test posting for company admin flow.');
  await page.getByRole('button', { name: /create|publish|save/i }).first().click();
  await page.waitForLoadState('networkidle');
}

/** Edits the latest job posting and validates update action path. */
async function editJobPosting(page: Page): Promise<void> {
  await page.goto('/admin/jobs', { waitUntil: 'domcontentloaded' });
  await page.getByRole('button', { name: /edit/i }).first().click();
  const summary = page.getByLabel('Summary').first();
  if (await summary.isVisible().catch(() => false)) await summary.fill(`updated-${Date.now()}`);
  await page.getByRole('button', { name: /update|save/i }).first().click();
  await page.waitForLoadState('networkidle');
}

/** Opens recruiter activity page and checks activity rows are rendered. */
async function viewRecruiterActivity(page: Page, baseURL: string): Promise<void> {
  await page.goto(`${baseURL}/admin/recruiters/activity`, { waitUntil: 'domcontentloaded' });
  await page.locator('[data-testid="activity-row"], table tbody tr').first().waitFor({ state: 'visible', timeout: 12_000 });
}

/** Confirms company-admin cannot access superadmin routes. */
async function assertForbiddenRoute(
  page: Page,
  options: CompanyAdminFlowOptions,
  out: CompanyAdminFlowResult[],
  url: string
): Promise<void> {
  const step = `forbidden-route:${new URL(url).pathname}`;
  setContext(options);
  options.logger.info('companyAdmin', 'companyAdmin', step, 'checking access boundary');
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  const blocked = page.url().includes('/403') || page.url().includes('/unauthorized') || page.url().includes('/login');
  if (blocked) {
    out.push(result(step, 'PASS', `Blocked as expected at ${page.url()}`));
    return;
  }
  const ev = await captureFailureEvidence(page, options.evidenceDirs, `companyAdmin-${step}`);
  options.logger.critical('companyAdmin', 'companyAdmin', step, `Unexpected superadmin access: ${page.url()}`);
  out.push(result(step, 'CRITICAL', `Unexpected superadmin access: ${page.url()}`, ev.screenshotPath, ev.htmlPath));
}

/** Executes one company-admin step and saves evidence on failures. */
async function runStep(
  page: Page,
  options: CompanyAdminFlowOptions,
  out: CompanyAdminFlowResult[],
  step: string,
  fn: (page: Page) => Promise<void>
): Promise<void> {
  setContext(options);
  options.logger.info('companyAdmin', 'companyAdmin', step, 'started');
  try {
    await fn(page);
    out.push(result(step, 'PASS', 'ok'));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const ev = await captureFailureEvidence(page, options.evidenceDirs, `companyAdmin-${step}`);
    options.logger.fail('companyAdmin', 'companyAdmin', step, message);
    out.push(result(step, 'FAIL', message, ev.screenshotPath, ev.htmlPath));
  }
}

/** Sets shared watcher context for company-admin flow execution. */
function setContext(options: CompanyAdminFlowOptions): void {
  options.consoleWatcher.setContext('companyAdmin', 'companyAdmin');
  options.networkWatcher.setContext('companyAdmin', 'companyAdmin');
}

/** Returns normalized company-admin flow result payload. */
function result(
  step: string,
  severity: Severity,
  details: string,
  screenshotPath?: string,
  htmlPath?: string
): CompanyAdminFlowResult {
  return { role: 'companyAdmin', flow: 'companyAdmin', step, severity, details, screenshotPath, htmlPath };
}

/** Converts shared auth flow results into company-admin flow entries. */
function mapAuthResults(items: AuthFlowResult[]): CompanyAdminFlowResult[] {
  return items.map((item) => ({
    role: 'companyAdmin',
    flow: 'companyAdmin',
    step: `auth:${item.step}`,
    severity: item.severity,
    details: item.details,
    screenshotPath: item.screenshotPath,
    htmlPath: item.htmlPath
  }));
}
