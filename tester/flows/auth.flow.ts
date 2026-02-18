import { Page } from 'playwright';
import { AppConfig } from '../config/schema';
import { Logger } from '../utils/logger';
import { EvidencePaths, captureFailureEvidence } from '../utils/evidence';
import { StepResult } from '../utils/report';
import { ConsoleWatcher } from '../watchers/console.watcher';
import { NetworkWatcher } from '../watchers/network.watcher';

export type AuthFlowOptions = {
  logger: Logger;
  evidenceDirs: EvidencePaths;
  consoleWatcher: ConsoleWatcher;
  networkWatcher: NetworkWatcher;
};

/** Executes login flow and validates dashboard reachability with clean console state. */
export async function runAuthFlow(page: Page, config: AppConfig, options: AuthFlowOptions): Promise<StepResult[]> {
  const flow = 'auth';
  options.consoleWatcher.setFlow(flow);
  options.networkWatcher.setFlow(flow);
  const results: StepResult[] = [];
  const c0 = options.consoleWatcher.getLogs().length;

  await step(results, flow, 'go-login', page, options, async () => {
    await page.goto(`${config.baseURL}/login`, { waitUntil: 'domcontentloaded' });
  });

  await step(results, flow, 'fill-credentials', page, options, async () => {
    await page.getByLabel('Email').fill(config.credentials.email);
    await page.getByLabel('Password').fill(config.credentials.password);
  });

  await step(results, flow, 'submit-login', page, options, async () => {
    await page.getByRole('button', { name: /login|sign in/i }).click();
    await page.waitForLoadState('networkidle');
  });

  await step(results, flow, 'validate-dashboard', page, options, async () => {
    await page.getByTestId('dashboard').waitFor({ state: 'visible', timeout: 10_000 });
    const errors = options.consoleWatcher.getLogs().slice(c0).filter((l) => l.level === 'error');
    if (errors.length) throw new Error(`Console errors found: ${errors.length}`);
  });

  return results;
}

/** Runs one flow step and records pass/fail evidence with diagnostics. */
async function step(
  results: StepResult[],
  flow: string,
  stepName: string,
  page: Page,
  options: AuthFlowOptions,
  fn: () => Promise<void>
): Promise<void> {
  options.logger.info(flow, stepName, 'started');
  try {
    await fn();
    results.push({ flow, step: stepName, status: 'PASS', details: 'ok' });
  } catch (error) {
    options.logger.error(flow, stepName, (error as Error).message);
    const ev = await captureFailureEvidence(page, options.evidenceDirs, `${flow}-${stepName}`);
    results.push({ flow, step: stepName, status: 'FAIL', details: (error as Error).message, screenshotPath: ev.screenshotPath });
  }
}
