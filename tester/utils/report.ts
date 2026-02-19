import fs from 'node:fs';
import path from 'node:path';
import { diff } from 'jsondiffpatch';
import { Severity } from './logger';
import { ConsoleEvent } from '../watchers/console.watcher';
import { NetworkIssue } from '../watchers/network.watcher';
import { PerformanceIssue, PerformanceStats } from '../watchers/performance.watcher';

export type ReportFinding = {
  role: string;
  flow: string;
  step: string;
  severity: Severity;
  details: string;
  screenshotPath?: string;
  htmlPath?: string;
  evidencePath?: string;
};

export type ReportPayload = {
  environment: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  flowResults: ReportFinding[];
  securityResults: ReportFinding[];
  businessResults: ReportFinding[];
  edgeResults: ReportFinding[];
  consoleLogs: ConsoleEvent[];
  networkIssues: NetworkIssue[];
  performanceIssues: PerformanceIssue[];
  performanceStats: PerformanceStats[];
};

/** Builds and writes the final HTML report in a single standalone file. */
export function generateHtmlReport(outDir: string, payload: ReportPayload): string {
  const reportPath = path.join(outDir, 'report.html');
  const all = collectAllFindings(payload);
  const totals = summarize(all);
  const summaryDelta = diff({ pass: 0, warn: 0, fail: 0, critical: 0 }, totals);
  const html = renderDocument(outDir, payload, all, totals, summaryDelta);
  fs.writeFileSync(reportPath, html, 'utf8');
  return reportPath;
}

/** Returns all report findings merged across execution domains. */
function collectAllFindings(payload: ReportPayload): ReportFinding[] {
  return [...payload.flowResults, ...payload.securityResults, ...payload.businessResults, ...payload.edgeResults];
}

/** Computes total findings by severity for executive summary. */
function summarize(findings: ReportFinding[]): Record<'pass' | 'warn' | 'fail' | 'critical', number> {
  return findings.reduce(
    (acc, item) => {
      const key = item.severity.toLowerCase() as keyof typeof acc;
      acc[key] = (acc[key] ?? 0) + 1;
      return acc;
    },
    { pass: 0, warn: 0, fail: 0, critical: 0 }
  );
}

/** Renders the full HTML document with all required sections. */
function renderDocument(
  outDir: string,
  payload: ReportPayload,
  all: ReportFinding[],
  totals: Record<'pass' | 'warn' | 'fail' | 'critical', number>,
  summaryDelta: unknown
): string {
  return `<!doctype html>
<html><head><meta charset="utf-8" /><title>Wazifame QA Security Report</title><style>${css()}</style></head>
<body>
  <h1>Wazifame Aggressive QA Report</h1>
  ${renderExecutive(payload, totals, summaryDelta)}
  <h2>Security Section</h2>${renderFindingsTable(payload.securityResults, outDir)}
  <h2>Business Logic Section</h2>${renderFindingsTable(payload.businessResults, outDir)}
  <h2>Performance Section</h2>${renderPerformance(payload.performanceIssues, payload.performanceStats)}
  <h2>Edge Case Section</h2>${renderFindingsTable(payload.edgeResults, outDir)}
  <h2>Failure Evidence</h2>${renderEvidenceGallery(all, outDir)}
  <h2>Console Warnings/Errors</h2>${renderConsole(payload.consoleLogs)}
  <h2>Network Issues</h2>${renderNetwork(payload.networkIssues)}
</body></html>`;
}

/** Renders executive summary card set with environment and duration context. */
function renderExecutive(
  payload: ReportPayload,
  totals: Record<'pass' | 'warn' | 'fail' | 'critical', number>,
  summaryDelta: unknown
): string {
  return `<section class="cards">
    <div class="card critical">🔴 CRITICAL: ${totals.critical}</div>
    <div class="card fail">🟠 FAIL: ${totals.fail}</div>
    <div class="card warn">🟡 WARN: ${totals.warn}</div>
    <div class="card pass">🟢 PASS: ${totals.pass}</div>
  </section>
  <p><strong>Environment:</strong> ${escape(payload.environment)} | <strong>Duration:</strong> ${payload.durationMs}ms</p>
  <p><strong>Started:</strong> ${escape(payload.startedAt)} | <strong>Finished:</strong> ${escape(payload.finishedAt)}</p>
  <details><summary>Summary Diff (jsondiffpatch)</summary><pre>${escape(JSON.stringify(summaryDelta ?? {}, null, 2))}</pre></details>`;
}

/** Renders generic findings table for flow/security/business/edge sections. */
function renderFindingsTable(findings: ReportFinding[], outDir: string): string {
  if (!findings.length) return '<p>No findings recorded.</p>';
  const rows = findings
    .map((f) => `<tr><td>${escape(f.role)}</td><td>${escape(f.flow)}</td><td>${escape(f.step)}</td><td class="${f.severity}">${badge(f.severity)}</td><td>${escape(f.details)}</td><td>${linkCell(f.evidencePath, outDir)}</td></tr>`)
    .join('');
  return `<table><thead><tr><th>Role</th><th>Flow</th><th>Step/Attack</th><th>Severity</th><th>Details</th><th>Evidence</th></tr></thead><tbody>${rows}</tbody></table>`;
}

/** Renders performance issue + stats tables with threshold exceedance focus. */
function renderPerformance(issues: PerformanceIssue[], stats: PerformanceStats[]): string {
  const issueHtml = issues.length
    ? `<table><thead><tr><th>Role</th><th>Flow</th><th>Type</th><th>Target</th><th>Duration(ms)</th><th>Threshold(ms)</th></tr></thead><tbody>${issues
        .map((i) => `<tr><td>${escape(i.role)}</td><td>${escape(i.flow)}</td><td>${escape(i.type)}</td><td>${escape(i.target)}</td><td>${i.durationMs}</td><td>${i.thresholdMs}</td></tr>`)
        .join('')}</tbody></table>`
    : '<p>No performance issues detected.</p>';
  const statsHtml = stats.length
    ? `<table><thead><tr><th>Role</th><th>Flow</th><th>Page Load</th><th>TTI</th><th>Largest API</th></tr></thead><tbody>${stats
        .map((s) => `<tr><td>${escape(s.role)}</td><td>${escape(s.flow)}</td><td>${s.pageLoadMs}</td><td>${s.timeToInteractiveMs}</td><td>${s.largestApiMs}</td></tr>`)
        .join('')}</tbody></table>`
    : '<p>No performance stats captured.</p>';
  return `${issueHtml}${statsHtml}`;
}

/** Renders thumbnails and links for fail/critical evidence artifacts. */
function renderEvidenceGallery(all: ReportFinding[], outDir: string): string {
  const items = all.filter((f) => f.severity === 'FAIL' || f.severity === 'CRITICAL');
  if (!items.length) return '<p>No failure evidence.</p>';
  return `<div class="gallery">${items
    .map((f) => `<article><h4>${escape(f.role)} :: ${escape(f.step)}</h4>${thumb(f.screenshotPath, outDir)}<p>${linkCell(f.htmlPath, outDir)} | ${linkCell(f.evidencePath, outDir)}</p></article>`)
    .join('')}</div>`;
}

/** Renders console warning/error events table by role and flow. */
function renderConsole(logs: ConsoleEvent[]): string {
  if (!logs.length) return '<p>No console warnings/errors captured.</p>';
  const rows = logs
    .map((c) => `<tr><td>${escape(c.timestamp)}</td><td>${escape(c.role)}</td><td>${escape(c.flow)}</td><td>${escape(c.level)}</td><td>${escape(c.message)}</td></tr>`)
    .join('');
  return `<table><thead><tr><th>Timestamp</th><th>Role</th><th>Flow</th><th>Level</th><th>Message</th></tr></thead><tbody>${rows}</tbody></table>`;
}

/** Renders network issue table including security header and leak signals. */
function renderNetwork(issues: NetworkIssue[]): string {
  if (!issues.length) return '<p>No network issues detected.</p>';
  const rows = issues
    .map((n) => `<tr><td>${escape(n.role)}</td><td>${escape(n.flow)}</td><td>${escape(n.type)}</td><td>${escape(n.url)}</td><td>${n.status}</td><td>${n.durationMs}</td><td>${escape(n.details)}</td></tr>`)
    .join('');
  return `<table><thead><tr><th>Role</th><th>Flow</th><th>Type</th><th>URL</th><th>Status</th><th>Duration</th><th>Details</th></tr></thead><tbody>${rows}</tbody></table>`;
}

/** Renders severity badge text with explicit color-keyed icon prefixes. */
function badge(severity: Severity): string {
  const map: Record<Severity, string> = { CRITICAL: '🔴 CRITICAL', FAIL: '🟠 FAIL', WARN: '🟡 WARN', PASS: '🟢 PASS', INFO: 'ℹ️ INFO' };
  return map[severity] ?? severity;
}

/** Renders link cell to evidence file using relative report path conversion. */
function linkCell(absPath: string | undefined, outDir: string): string {
  if (!absPath) return 'N/A';
  const rel = toPosix(path.relative(outDir, absPath));
  return `<a href="${escape(rel)}">${escape(path.basename(absPath))}</a>`;
}

/** Renders screenshot thumbnail with click-through link when available. */
function thumb(absPath: string | undefined, outDir: string): string {
  if (!absPath) return '<span>N/A</span>';
  const rel = toPosix(path.relative(outDir, absPath));
  return `<a href="${escape(rel)}"><img src="${escape(rel)}" alt="evidence" class="thumb" /></a>`;
}

/** Escapes HTML entities to keep report output safe and readable. */
function escape(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** Converts platform path separators to web-compatible forward slashes. */
function toPosix(value: string): string {
  return value.split(path.sep).join('/');
}

/** Provides inline stylesheet required by standalone report rendering. */
function css(): string {
  return `body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f4f6fb;color:#111827}
.cards{display:grid;grid-template-columns:repeat(4,minmax(120px,1fr));gap:10px;margin:8px 0 14px}
.card{padding:10px 12px;border:1px solid #d1d5db;background:#fff;border-radius:8px;font-weight:700}
.card.critical{border-color:#dc2626}.card.fail{border-color:#f97316}.card.warn{border-color:#eab308}.card.pass{border-color:#16a34a}
h1,h2{margin:0 0 10px}table{width:100%;border-collapse:collapse;background:#fff;margin:10px 0 18px}
th,td{border:1px solid #d1d5db;padding:8px;vertical-align:top}th{text-align:left;background:#e5edff}
.CRITICAL{color:#b91c1c;font-weight:700}.FAIL{color:#c2410c;font-weight:700}.WARN{color:#a16207;font-weight:700}.PASS{color:#166534;font-weight:700}.INFO{color:#1d4ed8;font-weight:700}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}.gallery article{background:#fff;border:1px solid #d1d5db;padding:10px;border-radius:8px}
.thumb{width:100%;max-height:140px;object-fit:cover;border:1px solid #d1d5db}`;
}
