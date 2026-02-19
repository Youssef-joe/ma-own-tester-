import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Page } from 'playwright';
import { AppConfig } from '../config/schema';
import { AuthFlowResult, loginAsRole, logoutRole } from './auth.flow';
import { EvidencePaths, captureFailureEvidence } from '../utils/evidence';
import { Logger, Severity } from '../utils/logger';
import { ConsoleWatcher } from '../watchers/console.watcher';
import { NetworkWatcher } from '../watchers/network.watcher';

export type CandidateFlowResult = {
  role: 'candidate';
  flow: 'candidate';
  step: string;
  severity: Severity;
  details: string;
  screenshotPath?: string;
  htmlPath?: string;
};

export type CandidateFlowOptions = {
  logger: Logger;
  evidenceDirs: EvidencePaths;
  consoleWatcher: ConsoleWatcher;
  networkWatcher: NetworkWatcher;
};

/** Runs candidate business flow and role-boundary authorization checks. */
export async function runCandidateFlow(page: Page, config: AppConfig, options: CandidateFlowOptions): Promise<CandidateFlowResult[]> {
  const out: CandidateFlowResult[] = [];
  setContext(options);
  out.push(...mapAuthResults(await loginAsRole(page, config, 'candidate', withAuth(options))));
  await runStep(page, options, out, 'register-account', registerCandidate);
  await runStep(page, options, out, 'browse-jobs', async (p) => browseJobs(p, config.baseURL));
  await runStep(page, options, out, 'apply-to-job', applyToJob);
  await runStep(page, options, out, 'upload-valid-cv', uploadValidCv);
  await runStep(page, options, out, 'check-application-status', checkApplicationStatus);
  await assertForbiddenRoute(page, options, out, `${config.baseURL}/recruiter/dashboard`, '/login');
  await assertForbiddenRoute(page, options, out, `${config.baseURL}/admin/dashboard`, '/login');
  out.push(...mapAuthResults(await logoutRole(page, 'candidate', withAuth(options))));
  return out;
}

/** Adapts candidate options to shared auth flow option shape. */
function withAuth(options: CandidateFlowOptions) {
  return {
    logger: options.logger,
    evidenceDirs: options.evidenceDirs,
    consoleWatcher: options.consoleWatcher,
    networkWatcher: options.networkWatcher
  };
}

/** Creates a candidate account through registration form using valid values. */
async function registerCandidate(page: Page): Promise<void> {
  const email = `qa.candidate.${Date.now()}@example.test`;
  await page.goto('/register', { waitUntil: 'domcontentloaded' });
  await page.getByLabel('Full Name').fill('QA Candidate');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill('Candidate#12345');
  await page.getByRole('button', { name: /register|sign up/i }).click();
  await page.waitForLoadState('networkidle');
}

/** Opens jobs listing screen and validates listing cards are visible. */
async function browseJobs(page: Page, baseURL: string): Promise<void> {
  await page.goto(`${baseURL}/jobs`, { waitUntil: 'domcontentloaded' });
  await page.locator('[data-testid="job-card"]').first().waitFor({ state: 'visible', timeout: 12_000 });
}

/** Submits one job application using visible form inputs. */
async function applyToJob(page: Page): Promise<void> {
  await page.getByRole('button', { name: /apply/i }).first().click();
  await page.getByLabel('Phone').fill('+15555550100');
  await page.getByLabel('Cover Letter').fill('Automated QA application test submission.');
  await page.getByRole('button', { name: /submit application|apply now/i }).click();
  await page.waitForLoadState('networkidle');
}

/** Uploads a valid PDF CV fixture through candidate upload control. */
async function uploadValidCv(page: Page): Promise<void> {
  const filePath = createValidPdf();
  await page.setInputFiles('[name="cv"], input[type="file"]', filePath);
  await page.getByRole('button', { name: /upload|save cv/i }).first().click();
  await page.waitForLoadState('networkidle');
}

/** Opens application status page and verifies at least one status badge. */
async function checkApplicationStatus(page: Page): Promise<void> {
  await page.goto('/applications', { waitUntil: 'domcontentloaded' });
  await page.locator('[data-testid="application-status"], .status-badge').first().waitFor({ state: 'visible', timeout: 12_000 });
}

/** Validates restricted routes are denied or redirected, else marks CRITICAL. */
async function assertForbiddenRoute(
  page: Page,
  options: CandidateFlowOptions,
  out: CandidateFlowResult[],
  url: string,
  expectedRedirectPath: string
): Promise<void> {
  const step = `forbidden-route:${new URL(url).pathname}`;
  setContext(options);
  options.logger.info('candidate', 'candidate', step, 'checking access boundary');
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  const denied = page.url().includes(expectedRedirectPath) || page.url().includes('/403') || page.url().includes('/unauthorized');
  if (denied) {
    out.push(result(step, 'PASS', `Blocked as expected at ${page.url()}`));
    return;
  }
  const ev = await captureFailureEvidence(page, options.evidenceDirs, `candidate-${step}`);
  options.logger.critical('candidate', 'candidate', step, `Unexpected access granted: ${page.url()}`);
  out.push(result(step, 'CRITICAL', `Unexpected access granted: ${page.url()}`, ev.screenshotPath, ev.htmlPath));
}

/** Runs one candidate step with fail evidence capture and typed result output. */
async function runStep(
  page: Page,
  options: CandidateFlowOptions,
  out: CandidateFlowResult[],
  step: string,
  fn: (page: Page) => Promise<void>
): Promise<void> {
  setContext(options);
  options.logger.info('candidate', 'candidate', step, 'started');
  try {
    await fn(page);
    out.push(result(step, 'PASS', 'ok'));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const ev = await captureFailureEvidence(page, options.evidenceDirs, `candidate-${step}`);
    options.logger.fail('candidate', 'candidate', step, message);
    out.push(result(step, 'FAIL', message, ev.screenshotPath, ev.htmlPath));
  }
}

/** Applies candidate/flow context to shared watchers before each step. */
function setContext(options: CandidateFlowOptions): void {
  options.consoleWatcher.setContext('candidate', 'candidate');
  options.networkWatcher.setContext('candidate', 'candidate');
}

/** Builds normalized candidate flow result entries. */
function result(step: string, severity: Severity, details: string, screenshotPath?: string, htmlPath?: string): CandidateFlowResult {
  return { role: 'candidate', flow: 'candidate', step, severity, details, screenshotPath, htmlPath };
}

/** Converts shared auth flow result shape into candidate flow result shape. */
function mapAuthResults(items: AuthFlowResult[]): CandidateFlowResult[] {
  return items.map((item) => ({
    role: 'candidate',
    flow: 'candidate',
    step: `auth:${item.step}`,
    severity: item.severity,
    details: item.details,
    screenshotPath: item.screenshotPath,
    htmlPath: item.htmlPath
  }));
}

/** Generates a minimal valid PDF fixture file and returns path. */
function createValidPdf(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-candidate-cv-'));
  const filePath = path.join(dir, 'valid-cv.pdf');
  fs.writeFileSync(filePath, Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF', 'utf8'));
  return filePath;
}
