import path from 'node:path';
import { Page } from 'playwright';
import { Logger } from '../utils/logger';
import { EvidencePaths } from '../utils/evidence';
import { StepResult } from '../utils/report';
import { ConsoleEvent } from '../watchers/console.watcher';
import { NetworkEvent } from '../watchers/network.watcher';

export type EdgeCaseOptions = {
  flow: string;
  submitSelector: string;
  errorSelector?: string;
  logger: Logger;
  evidenceDirs: EvidencePaths;
  getConsoleLogs: () => ConsoleEvent[];
  getNetworkIssues: () => NetworkEvent[];
};

const CASES = [
  { label: 'empty', value: '' },
  { label: 'long string', value: 'a'.repeat(1000) },
  { label: 'special chars', value: `!@#$%^&*()_+-=[]{}|;':",.<>?` },
  { label: 'xss attempt', value: '<script>alert(1)</script>' },
  { label: 'sql injection', value: `' OR 1=1 --` },
  { label: 'negative num', value: '-999' },
  { label: 'large num', value: '99999999999' },
  { label: 'invalid email', value: 'notanemail@@' }
] as const;

/** Runs deterministic edge-case inputs and records result/evidence per case. */
export async function runEdgeCases(page: Page, selector: string, options: EdgeCaseOptions): Promise<StepResult[]> {
  const results: StepResult[] = [];
  for (const testCase of CASES) {
    const step = `edge:${testCase.label}`;
    options.logger.info(options.flow, step, `Testing value length=${testCase.value.length}`);
    const c0 = options.getConsoleLogs().length;
    const n0 = options.getNetworkIssues().length;
    await page.locator(selector).fill(testCase.value);
    await page.locator(options.submitSelector).click();
    await page.waitForLoadState('networkidle');
    const uiError = await readVisibleError(page, options.errorSelector);
    const newConsole = options.getConsoleLogs().slice(c0);
    const newNetwork = options.getNetworkIssues().slice(n0);
    const screenshotPath = await saveCaseScreenshot(page, options.evidenceDirs, testCase.label);
    const status = classify(uiError, newConsole.length, newNetwork.length);
    const details = formatDetails(uiError, newConsole.length, newNetwork.length);
    results.push({ flow: options.flow, step, status, details, screenshotPath });
  }

  return results;
}

/** Reads first visible validation error if selector is provided and visible. */
async function readVisibleError(page: Page, errorSelector?: string): Promise<string> {
  if (!errorSelector) return '';
  const el = page.locator(errorSelector).first();
  if (!(await el.isVisible().catch(() => false))) return '';
  return (await el.textContent())?.trim() ?? '';
}

/** Saves a screenshot for each edge case under daily screenshot directory. */
async function saveCaseScreenshot(page: Page, dirs: EvidencePaths, label: string): Promise<string> {
  const name = `${label.replace(/\s+/g, '-')}-${new Date().toISOString().replace(/[.:]/g, '-')}.png`;
  const screenshotPath = path.join(dirs.screenshotsDir, name);
  await page.screenshot({ path: screenshotPath, fullPage: true });
  return screenshotPath;
}

/** Converts observed signals into PASS/WARN/FAIL outcome. */
function classify(uiError: string, consoleCount: number, networkCount: number): 'PASS' | 'WARN' | 'FAIL' {
  if (consoleCount > 0 || networkCount > 0) return 'FAIL';
  if (uiError) return 'PASS';
  return 'WARN';
}

/** Formats concise per-case diagnostics for the final report table. */
function formatDetails(uiError: string, consoleCount: number, networkCount: number): string {
  const bits = [`uiError=${uiError || 'none'}`, `console=${consoleCount}`, `network=${networkCount}`];
  return bits.join(', ');
}
