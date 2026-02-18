import { Page } from 'playwright';
import { AppConfig } from '../config/schema';
import { Logger } from '../utils/logger';
import { EvidencePaths, captureFailureEvidence } from '../utils/evidence';
import { StepResult } from '../utils/report';
import { ConsoleWatcher } from '../watchers/console.watcher';
import { NetworkWatcher } from '../watchers/network.watcher';

export type CrudFlowOptions = {
  logger: Logger;
  evidenceDirs: EvidencePaths;
  consoleWatcher: ConsoleWatcher;
  networkWatcher: NetworkWatcher;
};

/** Executes create/update/delete flow on the main resource page. */
export async function runCrudFlow(page: Page, config: AppConfig, options: CrudFlowOptions): Promise<StepResult[]> {
  const flow = 'crud';
  options.consoleWatcher.setFlow(flow);
  options.networkWatcher.setFlow(flow);
  const results: StepResult[] = [];
  const itemName = `qa-item-${Date.now()}`;
  const updatedName = `${itemName}-updated`;

  await step(results, flow, 'open-resource-page', page, options, async () => {
    await page.goto(`${config.baseURL}${config.resourcePath}`, { waitUntil: 'domcontentloaded' });
  });

  await step(results, flow, 'create-item', page, options, async () => {
    await page.getByLabel('Name').fill(itemName);
    await page.getByRole('button', { name: /create|save/i }).click();
    await page.waitForLoadState('networkidle');
  });

  await step(results, flow, 'validate-created', page, options, async () => {
    await page.getByText(itemName, { exact: true }).waitFor({ state: 'visible', timeout: 10_000 });
  });

  await step(results, flow, 'update-item', page, options, async () => {
    await page.getByRole('row', { name: itemName }).getByRole('button', { name: /edit/i }).click();
    await page.getByLabel('Name').fill(updatedName);
    await page.getByRole('button', { name: /update|save/i }).click();
    await page.waitForLoadState('networkidle');
  });

  await step(results, flow, 'delete-item', page, options, async () => {
    await page.getByRole('row', { name: updatedName }).getByRole('button', { name: /delete/i }).click();
    await page.getByRole('button', { name: /confirm|yes/i }).click();
    await page.waitForLoadState('networkidle');
  });

  await step(results, flow, 'validate-deleted', page, options, async () => {
    await page.getByText(updatedName, { exact: true }).waitFor({ state: 'hidden', timeout: 10_000 });
  });

  return results;
}

/** Runs one CRUD step and captures evidence when the action fails. */
async function step(
  results: StepResult[],
  flow: string,
  stepName: string,
  page: Page,
  options: CrudFlowOptions,
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
