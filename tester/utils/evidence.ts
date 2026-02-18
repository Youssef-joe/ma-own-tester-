import fs from 'node:fs';
import path from 'node:path';
import { Page } from 'playwright';
import { redactToken } from './jwt.utils';

export type EvidencePaths = {
  rootDir: string;
  dayDir: string;
  roleDir: string;
  scopeDir: string;
  screenshotsDir: string;
  snapshotsDir: string;
  logsDir: string;
};

export type FailureEvidence = {
  screenshotPath: string;
  htmlPath: string;
  requestResponsePath?: string;
  consolePath?: string;
  networkPath?: string;
};

export type RequestResponseEvidence = {
  request: { method: string; url: string; headers?: Record<string, string>; body?: unknown };
  response: { status: number; headers?: Record<string, string>; body?: unknown };
  tokenUsed?: string;
};

/** Creates evidence directories under reports/date/role/attack-type. */
export function ensureEvidenceDirs(dateStr: string, role = 'global', scope = 'general'): EvidencePaths {
  const rootDir = path.resolve(process.cwd(), 'reports');
  const dayDir = path.join(rootDir, dateStr);
  const roleDir = path.join(dayDir, safeName(role));
  const scopeDir = path.join(roleDir, safeName(scope));
  const screenshotsDir = path.join(scopeDir, 'screenshots');
  const snapshotsDir = path.join(scopeDir, 'snapshots');
  const logsDir = path.join(scopeDir, 'logs');
  [rootDir, dayDir, roleDir, scopeDir, screenshotsDir, snapshotsDir, logsDir].forEach(createDir);
  return { rootDir, dayDir, roleDir, scopeDir, screenshotsDir, snapshotsDir, logsDir };
}

/** Captures screenshot and HTML snapshot for a failing or critical step. */
export async function captureFailureEvidence(page: Page, dirs: EvidencePaths, label: string): Promise<FailureEvidence> {
  const stamp = safeStamp();
  const screenshotPath = path.join(dirs.screenshotsDir, `${safeName(label)}-${stamp}.png`);
  const htmlPath = path.join(dirs.snapshotsDir, `${safeName(label)}-${stamp}.html`);
  await page.screenshot({ path: screenshotPath, fullPage: true });
  fs.writeFileSync(htmlPath, await page.content(), 'utf8');
  return { screenshotPath, htmlPath };
}

/** Saves request/response payloads and redacted token for attack evidence. */
export function saveRequestResponseEvidence(
  dirs: EvidencePaths,
  label: string,
  data: RequestResponseEvidence
): string {
  const stamp = safeStamp();
  const outPath = path.join(dirs.logsDir, `${safeName(label)}-http-${stamp}.json`);
  const payload = { ...data, tokenUsed: data.tokenUsed ? redactToken(data.tokenUsed) : undefined };
  fs.writeFileSync(outPath, JSON.stringify(payload, null, 2), 'utf8');
  return outPath;
}

/** Saves console and network watcher data in timestamped JSON files. */
export function saveWatcherLogs(dirs: EvidencePaths, consoleLogs: unknown, networkLogs: unknown, label = 'watchers'): {
  consolePath: string;
  networkPath: string;
} {
  const stamp = safeStamp();
  const consolePath = path.join(dirs.logsDir, `${safeName(label)}-console-${stamp}.json`);
  const networkPath = path.join(dirs.logsDir, `${safeName(label)}-network-${stamp}.json`);
  fs.writeFileSync(consolePath, JSON.stringify(consoleLogs, null, 2), 'utf8');
  fs.writeFileSync(networkPath, JSON.stringify(networkLogs, null, 2), 'utf8');
  return { consolePath, networkPath };
}

/** Writes any JSON-serializable object as evidence with timestamped name. */
export function saveJsonEvidence(dirs: EvidencePaths, label: string, data: unknown): string {
  const outPath = path.join(dirs.logsDir, `${safeName(label)}-${safeStamp()}.json`);
  fs.writeFileSync(outPath, JSON.stringify(data, null, 2), 'utf8');
  return outPath;
}

/** Creates a directory recursively when it does not already exist. */
function createDir(dirPath: string): void {
  fs.mkdirSync(dirPath, { recursive: true });
}

/** Sanitizes a string for safe filesystem naming. */
function safeName(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]/g, '_');
}

/** Returns a filesystem-safe timestamp string. */
function safeStamp(): string {
  return new Date().toISOString().replace(/[.:]/g, '-');
}
