import { chromium, Page } from 'playwright';
import { loadConfig, parseEnvArg } from './tester/config/env';
import { EnvName } from './tester/config/schema';
import { runAuthFlow } from './tester/flows/auth.flow';
import { runCrudFlow } from './tester/flows/crud.flow';
import { runEdgeCases } from './tester/edgeCases/inputTester';
import { attachConsoleWatcher } from './tester/watchers/console.watcher';
import { attachNetworkWatcher } from './tester/watchers/network.watcher';
import { ensureEvidenceDirs, saveWatcherLogs, captureFailureEvidence } from './tester/utils/evidence';
import { generateHtmlReport, StepResult } from './tester/utils/report';
import { Logger } from './tester/utils/logger';

const DEFAULT_INPUT_SELECTOR = process.env.MAIN_FORM_INPUT_SELECTOR ?? '[name="email"]';
const DEFAULT_SUBMIT_SELECTOR = process.env.MAIN_FORM_SUBMIT_SELECTOR ?? 'button[type="submit"]';
const DEFAULT_ERROR_SELECTOR = process.env.MAIN_FORM_ERROR_SELECTOR ?? '[role="alert"]';

/** Entrypoint for CLI execution. */
async function main(): Promise<void> {
  const envName = parseEnvArg(process.argv.slice(2));
  const config = loadConfig(envName);
  const runDate = new Date().toISOString().slice(0, 10);
  const evidenceDirs = ensureEvidenceDirs(runDate);
  const logger = new Logger();
  const browser = await chromium.launch({ headless: envName !== 'local' });

  let page: Page | null = null;
  try {
    const context = await browser.newContext({ baseURL: config.baseURL });
    page = await context.newPage();
    const consoleWatcher = attachConsoleWatcher(page);
    const networkWatcher = attachNetworkWatcher(page, config.slowThresholdMs);
    const steps = await runFlows(page, config, logger, evidenceDirs, consoleWatcher, networkWatcher);
    const edgeCases = await runEdgeSuite(page, logger, evidenceDirs, consoleWatcher, networkWatcher);
    const reportPath = finalize(runDate, envName, steps, edgeCases, evidenceDirs, consoleWatcher.getLogs(), networkWatcher.getIssues());
    await context.close();
    await browser.close();
    logger.info('runner', 'report', `Report saved to ${reportPath}`);
    process.exit(hasFailure(steps, edgeCases) ? 1 : 0);
  } catch (error) {
    await handleFatal(error, page, evidenceDirs, logger);
    await browser.close();
    process.exit(1);
  }
}

/** Runs authentication and CRUD flows in order. */
async function runFlows(
  page: Page,
  config: ReturnType<typeof loadConfig>,
  logger: Logger,
  evidenceDirs: ReturnType<typeof ensureEvidenceDirs>,
  consoleWatcher: ReturnType<typeof attachConsoleWatcher>,
  networkWatcher: ReturnType<typeof attachNetworkWatcher>
): Promise<StepResult[]> {
  const auth = await runAuthFlow(page, config, { logger, evidenceDirs, consoleWatcher, networkWatcher });
  const crud = await runCrudFlow(page, config, { logger, evidenceDirs, consoleWatcher, networkWatcher });
  return [...auth, ...crud];
}

/** Executes edge-case injection suite against configured main form selectors. */
async function runEdgeSuite(
  page: Page,
  logger: Logger,
  evidenceDirs: ReturnType<typeof ensureEvidenceDirs>,
  consoleWatcher: ReturnType<typeof attachConsoleWatcher>,
  networkWatcher: ReturnType<typeof attachNetworkWatcher>
): Promise<StepResult[]> {
  consoleWatcher.setFlow('edgeCases');
  networkWatcher.setFlow('edgeCases');
  return runEdgeCases(page, DEFAULT_INPUT_SELECTOR, {
    flow: 'edgeCases',
    submitSelector: DEFAULT_SUBMIT_SELECTOR,
    errorSelector: DEFAULT_ERROR_SELECTOR,
    logger,
    evidenceDirs,
    getConsoleLogs: () => consoleWatcher.getLogs(),
    getNetworkIssues: () => networkWatcher.getIssues()
  });
}

/** Writes watcher logs + HTML report and prints run summary. */
function finalize(
  runDate: string,
  envName: EnvName,
  steps: StepResult[],
  edgeCases: StepResult[],
  evidenceDirs: ReturnType<typeof ensureEvidenceDirs>,
  consoleLogs: ReturnType<ReturnType<typeof attachConsoleWatcher>['getLogs']>,
  networkIssues: ReturnType<ReturnType<typeof attachNetworkWatcher>['getIssues']>
): string {
  saveWatcherLogs(evidenceDirs, consoleLogs, networkIssues, 'run');
  const reportPath = generateHtmlReport(evidenceDirs.rootDir, {
    runDate,
    environment: envName,
    steps,
    edgeCases,
    consoleLogs,
    networkIssues
  });
  printSummary(steps, edgeCases, reportPath);
  return reportPath;
}

/** Handles fatal runner-level failures with evidence capture. */
async function handleFatal(
  error: unknown,
  page: Page | null,
  evidenceDirs: ReturnType<typeof ensureEvidenceDirs>,
  logger: Logger
): Promise<void> {
  const message = error instanceof Error ? error.message : String(error);
  logger.error('runner', 'fatal', message);
  if (page) {
    await captureFailureEvidence(page, evidenceDirs, 'fatal-runner');
  }
}

/** Prints execution totals to console. */
function printSummary(steps: StepResult[], edgeCases: StepResult[], reportPath: string): void {
  const all = [...steps, ...edgeCases];
  const pass = all.filter((s) => s.status === 'PASS').length;
  const warn = all.filter((s) => s.status === 'WARN').length;
  const fail = all.filter((s) => s.status === 'FAIL').length;
  console.log(`Summary -> PASS:${pass} WARN:${warn} FAIL:${fail}`);
  console.log(`Report -> ${reportPath}`);
}

/** Returns true when any step or edge case failed. */
function hasFailure(steps: StepResult[], edgeCases: StepResult[]): boolean {
  return [...steps, ...edgeCases].some((item) => item.status === 'FAIL');
}

main();
