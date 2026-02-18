import fs from 'node:fs';
import path from 'node:path';
import { ConsoleEvent } from '../watchers/console.watcher';
import { NetworkEvent } from '../watchers/network.watcher';

export type StepStatus = 'PASS' | 'WARN' | 'FAIL';

export type StepResult = {
  flow: string;
  step: string;
  status: StepStatus;
  details: string;
  screenshotPath?: string;
};

export type ReportPayload = {
  runDate: string;
  environment: string;
  steps: StepResult[];
  edgeCases: StepResult[];
  consoleLogs: ConsoleEvent[];
  networkIssues: NetworkEvent[];
};

/** Writes an HTML report with summary, flows, edge cases, and diagnostics. */
export function generateHtmlReport(outDir: string, payload: ReportPayload): string {
  const reportPath = path.join(outDir, 'report.html');
  const totals = summarize(payload.steps, payload.edgeCases);
  const html = `<!doctype html>
<html><head><meta charset="utf-8" /><title>QA Report</title><style>${css()}</style></head>
<body>
  <h1>Autonomous QA Report</h1>
  <p><strong>Date:</strong> ${escape(payload.runDate)} | <strong>Environment:</strong> ${escape(payload.environment)}</p>
  <div class="summary">
    <div>Passed: ${totals.pass}</div><div>Warned: ${totals.warn}</div><div>Failed: ${totals.fail}</div>
  </div>
  <h2>Flow Steps</h2>${renderSteps(payload.steps, outDir)}
  <h2>Edge Cases</h2>${renderSteps(payload.edgeCases, outDir)}
  <h2>Network Issues</h2>${renderNetwork(payload.networkIssues)}
  <h2>Console Warnings/Errors</h2>${renderConsole(payload.consoleLogs)}
</body></html>`;

  fs.writeFileSync(reportPath, html, 'utf8');
  return reportPath;
}

function summarize(steps: StepResult[], edgeCases: StepResult[]): { pass: number; warn: number; fail: number } {
  return [...steps, ...edgeCases].reduce(
    (acc, item) => ({ ...acc, [item.status.toLowerCase()]: acc[item.status.toLowerCase() as 'pass' | 'warn' | 'fail'] + 1 }),
    { pass: 0, warn: 0, fail: 0 }
  );
}

function renderSteps(steps: StepResult[], outDir: string): string {
  if (!steps.length) return '<p>No step data.</p>';
  const rows = steps
    .map((s) => `<tr><td>${escape(s.flow)}</td><td>${escape(s.step)}</td><td class="${s.status}">${s.status}</td><td>${escape(s.details)}</td><td>${renderShot(s.screenshotPath, outDir)}</td></tr>`)
    .join('');
  return `<table><thead><tr><th>Flow</th><th>Step</th><th>Status</th><th>Details</th><th>Evidence</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderNetwork(issues: NetworkEvent[]): string {
  if (!issues.length) return '<p>No network issues detected.</p>';
  const rows = issues
    .map((n) => `<tr><td>${escape(n.flow)}</td><td>${escape(n.type)}</td><td>${escape(n.url)}</td><td>${n.status}</td><td>${n.durationMs}</td></tr>`)
    .join('');
  return `<table><thead><tr><th>Flow</th><th>Type</th><th>URL</th><th>Status</th><th>Duration(ms)</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderConsole(logs: ConsoleEvent[]): string {
  if (!logs.length) return '<p>No console warnings or errors.</p>';
  const rows = logs
    .map((c) => `<tr><td>${escape(c.timestamp)}</td><td>${escape(c.flow)}</td><td>${escape(c.level)}</td><td>${escape(c.message)}</td></tr>`)
    .join('');
  return `<table><thead><tr><th>Timestamp</th><th>Flow</th><th>Level</th><th>Message</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderShot(absPath: string | undefined, outDir: string): string {
  if (!absPath) return 'N/A';
  const rel = toPosix(path.relative(outDir, absPath));
  return `<a href="${escape(rel)}"><img src="${escape(rel)}" alt="evidence" class="thumb" /></a>`;
}

function toPosix(value: string): string {
  return value.split(path.sep).join('/');
}

function escape(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
}

function css(): string {
  return `body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f7f9fc;color:#1f2937}
h1,h2{margin:0 0 12px}table{width:100%;border-collapse:collapse;margin:12px 0 20px;background:#fff}
th,td{border:1px solid #d1d5db;padding:8px;vertical-align:top}th{background:#eef2ff;text-align:left}
.summary{display:flex;gap:12px;margin:12px 0}.summary div{background:#fff;border:1px solid #d1d5db;padding:10px 14px}
.PASS{color:#166534;font-weight:700}.WARN{color:#92400e;font-weight:700}.FAIL{color:#991b1b;font-weight:700}
.thumb{max-width:180px;max-height:100px;object-fit:cover;border:1px solid #d1d5db}`;
}
