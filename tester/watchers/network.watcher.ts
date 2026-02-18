import { Page, Response } from 'playwright';

export type NetworkIssueType =
  | 'http_error'
  | 'slow_response'
  | 'missing_security_headers'
  | 'sensitive_data_exposed';

export type NetworkIssue = {
  timestamp: string;
  role: string;
  flow: string;
  type: NetworkIssueType;
  url: string;
  status: number;
  durationMs: number;
  details: string;
};

export type NetworkWatcher = {
  setContext: (role: string, flow: string) => void;
  getIssues: () => NetworkIssue[];
  getLargestApiDurationMs: () => number;
};

const REQUIRED_HEADERS = ['x-frame-options', 'content-security-policy', 'x-content-type-options'] as const;
const SENSITIVE_KEYS = ['password', 'token', 'secret', 'ssn'] as const;

/** Attaches response watcher and flags failures, slowness, and data/header risks. */
export function attachNetworkWatcher(page: Page, slowThresholdMs: number): NetworkWatcher {
  let role = 'global';
  let flow = 'bootstrap';
  let largestApiDurationMs = 0;
  const issues: NetworkIssue[] = [];

  page.on('response', async (response) => {
    const status = response.status();
    const url = response.url();
    const durationMs = getDurationMs(response);
    largestApiDurationMs = Math.max(largestApiDurationMs, durationMs);
    if (status >= 400) pushIssue(issues, role, flow, 'http_error', response, durationMs, `Status ${status}`);
    if (durationMs > slowThresholdMs) pushIssue(issues, role, flow, 'slow_response', response, durationMs, `>${slowThresholdMs}ms`);
    flagMissingHeaders(issues, role, flow, response, durationMs);
    await flagSensitiveData(issues, role, flow, response, durationMs);
  });

  return {
    setContext: (nextRole: string, nextFlow: string) => {
      role = nextRole;
      flow = nextFlow;
    },
    getIssues: () => [...issues],
    getLargestApiDurationMs: () => largestApiDurationMs
  };
}

/** Appends an issue entry in a single normalized format. */
function pushIssue(
  issues: NetworkIssue[],
  role: string,
  flow: string,
  type: NetworkIssueType,
  response: Response,
  durationMs: number,
  details: string
): void {
  issues.push({
    timestamp: new Date().toISOString(),
    role,
    flow,
    type,
    url: response.url(),
    status: response.status(),
    durationMs,
    details
  });
}

/** Calculates request duration from Playwright timing data. */
function getDurationMs(response: Response): number {
  const timing = response.request().timing();
  if (!Number.isFinite(timing.responseEnd) || timing.responseEnd < 0) return 0;
  return Math.max(0, Math.round(timing.responseEnd));
}

/** Flags responses missing required browser security headers. */
function flagMissingHeaders(
  issues: NetworkIssue[],
  role: string,
  flow: string,
  response: Response,
  durationMs: number
): void {
  const headers = response.headers();
  const missing = REQUIRED_HEADERS.filter((name) => !headers[name]);
  if (!missing.length) return;
  pushIssue(issues, role, flow, 'missing_security_headers', response, durationMs, missing.join(', '));
}

/** Scans JSON-like responses for sensitive keys to detect leakage risks. */
async function flagSensitiveData(
  issues: NetworkIssue[],
  role: string,
  flow: string,
  response: Response,
  durationMs: number
): Promise<void> {
  const text = await safeText(response);
  if (!text) return;
  const lower = text.toLowerCase();
  const hit = SENSITIVE_KEYS.find((key) => lower.includes(`\"${key}\"`) || lower.includes(`${key}:`));
  if (!hit) return;
  pushIssue(issues, role, flow, 'sensitive_data_exposed', response, durationMs, `Found field: ${hit}`);
}

/** Reads response text safely, ignoring non-readable payloads. */
async function safeText(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return '';
  }
}
