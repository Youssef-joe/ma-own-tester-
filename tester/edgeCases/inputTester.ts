import { Page } from 'playwright';
import { Logger, Severity } from '../utils/logger';
import { EvidencePaths, captureFailureEvidence, saveJsonEvidence } from '../utils/evidence';
import { ConsoleEvent } from '../watchers/console.watcher';
import { NetworkIssue } from '../watchers/network.watcher';

export type EdgeCaseResult = {
  role: string;
  flow: string;
  field: string;
  caseLabel: string;
  severity: Severity;
  details: string;
  screenshotPath?: string;
  htmlPath?: string;
};

export type InputEdgeOptions = {
  role: string;
  flow: string;
  submitSelector: string;
  errorSelector?: string;
  logger: Logger;
  evidenceDirs: EvidencePaths;
  getConsoleLogs: () => ConsoleEvent[];
  getNetworkIssues: () => NetworkIssue[];
};

const INPUT_CASES = [
  { label: 'empty', value: '' },
  { label: 'whitespace only', value: '   ' },
  { label: 'long string', value: 'a'.repeat(1000) },
  { label: 'special chars', value: `!@#$%^&*()<>?{}[]` },
  { label: 'xss basic', value: '<script>alert(1)</script>' },
  { label: 'xss img', value: '<img src=x onerror=alert(1)>' },
  { label: 'sql injection', value: `' OR '1'='1` },
  { label: 'sql drop', value: `'; DROP TABLE users; --` },
  { label: 'unicode overflow', value: '𝕳𝖊𝖑𝖑𝖔'.repeat(200) },
  { label: 'null byte', value: 'test\x00injection' },
  { label: 'negative number', value: '-99999' },
  { label: 'float overflow', value: '99999999999.999999' },
  { label: 'invalid email', value: 'a@@b..c' },
  { label: 'html entity', value: '&lt;script&gt;alert(1)&lt;/script&gt;' }
] as const;

/** Discovers visible inputs and runs the full edge-case matrix per field. */
export async function runInputEdgeCases(page: Page, options: InputEdgeOptions): Promise<EdgeCaseResult[]> {
  const results: EdgeCaseResult[] = [];
  const fields = await discoverFields(page);
  for (const field of fields) {
    for (const item of INPUT_CASES) {
      const result = await runSingleCase(page, field, item.label, item.value, options);
      results.push(result);
    }
  }

  return results;
}

/** Collects usable input selectors from visible form controls. */
async function discoverFields(page: Page): Promise<string[]> {
  const selectors = await page.locator('form input, form textarea').evaluateAll((nodes) => {
    return nodes
      .map((n) => {
        const el = n as HTMLInputElement | HTMLTextAreaElement;
        if (el.type === 'hidden' || el.disabled) return '';
        return el.id ? `#${el.id}` : el.name ? `[name="${el.name}"]` : '';
      })
      .filter(Boolean);
  });
  return Array.from(new Set(selectors));
}

/** Executes one edge case on one input and captures evidence on failure levels. */
async function runSingleCase(
  page: Page,
  field: string,
  caseLabel: string,
  value: string,
  options: InputEdgeOptions
): Promise<EdgeCaseResult> {
  const step = `edge:${field}:${caseLabel}`;
  options.logger.info(options.role, options.flow, step, `Running value length=${value.length}`);
  const c0 = options.getConsoleLogs().length;
  const n0 = options.getNetworkIssues().length;
  await page.locator(field).fill(value);
  await page.locator(options.submitSelector).click();
  await page.waitForLoadState('networkidle');
  const uiError = await readVisibleError(page, options.errorSelector);
  const consoleCount = options.getConsoleLogs().slice(c0).length;
  const networkCount = options.getNetworkIssues().slice(n0).length;
  const severity = classify(uiError, consoleCount, networkCount);
  const details = `uiError=${uiError || 'none'}, console=${consoleCount}, network=${networkCount}`;
  if (severity === 'PASS' || severity === 'INFO') return { role: options.role, flow: options.flow, field, caseLabel, severity, details };
  const evidence = await captureFailureEvidence(page, options.evidenceDirs, `${options.flow}-${caseLabel}`);
  saveJsonEvidence(options.evidenceDirs, `${options.flow}-${caseLabel}-context`, { field, caseLabel, value: value.slice(0, 250), details });
  return { role: options.role, flow: options.flow, field, caseLabel, severity, details, screenshotPath: evidence.screenshotPath, htmlPath: evidence.htmlPath };
}

/** Reads the first visible validation message for the submitted form. */
async function readVisibleError(page: Page, errorSelector?: string): Promise<string> {
  if (!errorSelector) return '';
  const alert = page.locator(errorSelector).first();
  const visible = await alert.isVisible().catch(() => false);
  if (!visible) return '';
  return (await alert.textContent())?.trim() ?? '';
}

/** Maps observed behavior into severity levels for reporting. */
function classify(uiError: string, consoleCount: number, networkCount: number): Severity {
  if (consoleCount > 0 || networkCount > 0) return 'FAIL';
  if (uiError) return 'PASS';
  return 'WARN';
}
