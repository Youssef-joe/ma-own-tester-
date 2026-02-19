import { Page } from 'playwright';
import { AppConfig } from '../config/schema';
import { AuthFlowResult, loginAsRole, logoutRole } from './auth.flow';
import { EvidencePaths, captureFailureEvidence } from '../utils/evidence';
import { Logger, Severity } from '../utils/logger';
import { ConsoleWatcher } from '../watchers/console.watcher';
import { NetworkWatcher } from '../watchers/network.watcher';

export type RecruiterFlowResult = {
  role: 'recruiter';
  flow: 'recruiter';
  step: string;
  severity: Severity;
  details: string;
  screenshotPath?: string;
  htmlPath?: string;
};

export type RecruiterFlowOptions = {
  logger: Logger;
  evidenceDirs: EvidencePaths;
  consoleWatcher: ConsoleWatcher;
  networkWatcher: NetworkWatcher;
  otherCompanyId: string;
};

/** Runs recruiter flow plus role-boundary and cross-company checks. */
export async function runRecruiterFlow(page: Page, config: AppConfig, options: RecruiterFlowOptions): Promise<RecruiterFlowResult[]> {
  const out: RecruiterFlowResult[] = [];
  setContext(options);
  out.push(...mapAuthResults(await loginAsRole(page, config, 'recruiter', authOptions(options))));
  await runStep(page, options, out, 'view-candidate-list', (p) => viewCandidateList(p, config.baseURL));
  await runStep(page, options, out, 'open-candidate-profile', openCandidateProfile);
  await runStep(page, options, out, 'change-application-status', changeApplicationStatus);
  await assertForbiddenRoute(page, options, out, `${config.baseURL}/admin/dashboard`);
  await assertCrossCompanyBlocked(page, options, out, `${config.baseURL}/recruiter/companies/${options.otherCompanyId}/candidates`);
  out.push(...mapAuthResults(await logoutRole(page, 'recruiter', authOptions(options))));
  return out;
}

/** Maps recruiter flow options to reusable auth flow options. */
function authOptions(options: RecruiterFlowOptions) {
  return {
    logger: options.logger,
    evidenceDirs: options.evidenceDirs,
    consoleWatcher: options.consoleWatcher,
    networkWatcher: options.networkWatcher
  };
}

/** Loads recruiter candidate listing page and waits for row visibility. */
async function viewCandidateList(page: Page, baseURL: string): Promise<void> {
  await page.goto(`${baseURL}/recruiter/candidates`, { waitUntil: 'domcontentloaded' });
  await page.locator('[data-testid="candidate-row"], table tbody tr').first().waitFor({ state: 'visible', timeout: 12_000 });
}

/** Opens first candidate profile from the recruiter candidate list. */
async function openCandidateProfile(page: Page): Promise<void> {
  await page.getByRole('button', { name: /view profile|open profile|details/i }).first().click();
  await page.waitForLoadState('networkidle');
  await page.locator('[data-testid="candidate-profile"], .candidate-profile').first().waitFor({ state: 'visible', timeout: 12_000 });
}

/** Updates candidate application status to shortlist/reject to validate workflow. */
async function changeApplicationStatus(page: Page): Promise<void> {
  await page.getByRole('button', { name: /shortlist|reject|change status/i }).first().click();
  const confirm = page.getByRole('button', { name: /confirm|save|update/i }).first();
  if (await confirm.isVisible().catch(() => false)) await confirm.click();
  await page.waitForLoadState('networkidle');
}

/** Verifies recruiter cannot access admin routes; success is CRITICAL. */
async function assertForbiddenRoute(
  page: Page,
  options: RecruiterFlowOptions,
  out: RecruiterFlowResult[],
  url: string
): Promise<void> {
  const step = `forbidden-route:${new URL(url).pathname}`;
  setContext(options);
  options.logger.info('recruiter', 'recruiter', step, 'checking access boundary');
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  const blocked = page.url().includes('/403') || page.url().includes('/unauthorized') || page.url().includes('/login');
  if (blocked) {
    out.push(result(step, 'PASS', `Blocked as expected at ${page.url()}`));
    return;
  }
  const ev = await captureFailureEvidence(page, options.evidenceDirs, `recruiter-${step}`);
  options.logger.critical('recruiter', 'recruiter', step, `Unexpected admin access: ${page.url()}`);
  out.push(result(step, 'CRITICAL', `Unexpected admin access: ${page.url()}`, ev.screenshotPath, ev.htmlPath));
}

/** Verifies recruiter cannot read other company candidates via URL manipulation. */
async function assertCrossCompanyBlocked(
  page: Page,
  options: RecruiterFlowOptions,
  out: RecruiterFlowResult[],
  url: string
): Promise<void> {
  const step = 'cross-company-candidate-access';
  setContext(options);
  options.logger.info('recruiter', 'recruiter', step, 'checking cross-company boundary');
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  const blocked = page.url().includes('/403') || page.url().includes('/unauthorized') || page.url().includes('/login');
  if (blocked) {
    out.push(result(step, 'PASS', `Cross-company access blocked at ${page.url()}`));
    return;
  }
  const ev = await captureFailureEvidence(page, options.evidenceDirs, `recruiter-${step}`);
  options.logger.critical('recruiter', 'recruiter', step, `Cross-company data exposed: ${page.url()}`);
  out.push(result(step, 'CRITICAL', `Cross-company data exposed: ${page.url()}`, ev.screenshotPath, ev.htmlPath));
}

/** Runs one recruiter action with fail evidence capture. */
async function runStep(
  page: Page,
  options: RecruiterFlowOptions,
  out: RecruiterFlowResult[],
  step: string,
  fn: (page: Page) => Promise<void>
): Promise<void> {
  setContext(options);
  options.logger.info('recruiter', 'recruiter', step, 'started');
  try {
    await fn(page);
    out.push(result(step, 'PASS', 'ok'));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const ev = await captureFailureEvidence(page, options.evidenceDirs, `recruiter-${step}`);
    options.logger.fail('recruiter', 'recruiter', step, message);
    out.push(result(step, 'FAIL', message, ev.screenshotPath, ev.htmlPath));
  }
}

/** Sets shared watcher context for recruiter flow execution. */
function setContext(options: RecruiterFlowOptions): void {
  options.consoleWatcher.setContext('recruiter', 'recruiter');
  options.networkWatcher.setContext('recruiter', 'recruiter');
}

/** Creates a normalized recruiter flow result object. */
function result(step: string, severity: Severity, details: string, screenshotPath?: string, htmlPath?: string): RecruiterFlowResult {
  return { role: 'recruiter', flow: 'recruiter', step, severity, details, screenshotPath, htmlPath };
}

/** Converts shared auth flow results into recruiter flow result entries. */
function mapAuthResults(items: AuthFlowResult[]): RecruiterFlowResult[] {
  return items.map((item) => ({
    role: 'recruiter',
    flow: 'recruiter',
    step: `auth:${item.step}`,
    severity: item.severity,
    details: item.details,
    screenshotPath: item.screenshotPath,
    htmlPath: item.htmlPath
  }));
}
