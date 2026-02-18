import { Page } from 'playwright';

export type PerformanceIssueType = 'slow_page_load' | 'slow_tti' | 'slow_api';

export type PerformanceIssue = {
  timestamp: string;
  role: string;
  flow: string;
  type: PerformanceIssueType;
  target: string;
  durationMs: number;
  thresholdMs: number;
};

export type PerformanceStats = {
  role: string;
  flow: string;
  pageLoadMs: number;
  timeToInteractiveMs: number;
  largestApiMs: number;
};

export type PerformanceWatcher = {
  setContext: (role: string, flow: string) => void;
  capturePageMetrics: (page: Page, largestApiMs: number) => Promise<void>;
  getIssues: () => PerformanceIssue[];
  getStats: () => PerformanceStats[];
};

/** Tracks page metrics and records threshold violations per role/flow. */
export function createPerformanceWatcher(pageThresholdMs = 3000, apiThresholdMs = 2000): PerformanceWatcher {
  let role = 'global';
  let flow = 'bootstrap';
  const issues: PerformanceIssue[] = [];
  const stats: PerformanceStats[] = [];

  return {
    setContext: (nextRole: string, nextFlow: string) => {
      role = nextRole;
      flow = nextFlow;
    },
    capturePageMetrics: async (page: Page, largestApiMs: number) => {
      const pageLoadMs = await readNavigationMetric(page, 'loadEventEnd');
      const timeToInteractiveMs = await readNavigationMetric(page, 'domInteractive');
      stats.push({ role, flow, pageLoadMs, timeToInteractiveMs, largestApiMs });
      if (pageLoadMs > pageThresholdMs) pushIssue(issues, role, flow, 'slow_page_load', page.url(), pageLoadMs, pageThresholdMs);
      if (timeToInteractiveMs > pageThresholdMs) pushIssue(issues, role, flow, 'slow_tti', page.url(), timeToInteractiveMs, pageThresholdMs);
      if (largestApiMs > apiThresholdMs) pushIssue(issues, role, flow, 'slow_api', page.url(), largestApiMs, apiThresholdMs);
    },
    getIssues: () => [...issues],
    getStats: () => [...stats]
  };
}

/** Reads a navigation timing metric and converts it to elapsed milliseconds. */
async function readNavigationMetric(page: Page, key: 'loadEventEnd' | 'domInteractive'): Promise<number> {
  return page.evaluate((metric) => {
    const nav = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
    if (!nav) return 0;
    const value = nav[metric] as number;
    return Number.isFinite(value) && value > 0 ? Math.round(value) : 0;
  }, key);
}

/** Adds a single performance issue record with standard shape. */
function pushIssue(
  issues: PerformanceIssue[],
  role: string,
  flow: string,
  type: PerformanceIssueType,
  target: string,
  durationMs: number,
  thresholdMs: number
): void {
  issues.push({
    timestamp: new Date().toISOString(),
    role,
    flow,
    type,
    target,
    durationMs,
    thresholdMs
  });
}
