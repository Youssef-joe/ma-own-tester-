import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { Page } from 'playwright';
import { Logger, Severity } from '../utils/logger';
import { EvidencePaths, captureFailureEvidence, saveJsonEvidence } from '../utils/evidence';

export type FileCaseResult = {
  role: string;
  flow: string;
  caseLabel: string;
  severity: Severity;
  details: string;
  screenshotPath?: string;
  htmlPath?: string;
};

export type FileEdgeOptions = {
  role: string;
  flow: string;
  inputSelector: string;
  submitSelector: string;
  errorSelector?: string;
  logger: Logger;
  evidenceDirs: EvidencePaths;
};

const FILE_CASES = [
  { label: '0 byte file', kind: 'zero_pdf' },
  { label: '50MB PDF', kind: 'big_pdf' },
  { label: 'password-protected PDF', kind: 'password_pdf' },
  { label: 'corrupted PDF header', kind: 'corrupt_pdf' },
  { label: 'PDF with embedded JavaScript', kind: 'js_pdf' },
  { label: 'image renamed as PDF', kind: 'image_as_pdf' },
  { label: 'HTML file renamed as PDF', kind: 'html_as_pdf' }
] as const;

/** Runs CV upload edge cases and verifies backend rejection behavior. */
export async function runFileEdgeCases(page: Page, options: FileEdgeOptions): Promise<FileCaseResult[]> {
  const results: FileCaseResult[] = [];
  for (const item of FILE_CASES) {
    const filePath = createFixture(item.kind);
    const step = `file-edge:${item.label}`;
    options.logger.info(options.role, options.flow, step, `Uploading ${path.basename(filePath)}`);
    await page.setInputFiles(options.inputSelector, filePath);
    await page.locator(options.submitSelector).click();
    await page.waitForLoadState('networkidle');
    const uiError = await readVisibleError(page, options.errorSelector);
    const severity = uiError ? 'PASS' : 'WARN';
    const details = uiError || 'No clear rejection message found';
    const result = await withEvidenceOnWarnFail(page, options, item.label, severity, details, filePath);
    results.push(result);
  }

  return results;
}

/** Captures evidence for non-pass outcomes and stores case metadata. */
async function withEvidenceOnWarnFail(
  page: Page,
  options: FileEdgeOptions,
  caseLabel: string,
  severity: Severity,
  details: string,
  filePath: string
): Promise<FileCaseResult> {
  if (severity === 'PASS' || severity === 'INFO') {
    return { role: options.role, flow: options.flow, caseLabel, severity, details };
  }

  const ev = await captureFailureEvidence(page, options.evidenceDirs, `${options.flow}-${caseLabel}`);
  saveJsonEvidence(options.evidenceDirs, `${options.flow}-${caseLabel}-file`, { caseLabel, filePath, details });
  return { role: options.role, flow: options.flow, caseLabel, severity, details, screenshotPath: ev.screenshotPath, htmlPath: ev.htmlPath };
}

/** Reads the first visible upload validation message when available. */
async function readVisibleError(page: Page, errorSelector?: string): Promise<string> {
  if (!errorSelector) return '';
  const node = page.locator(errorSelector).first();
  const visible = await node.isVisible().catch(() => false);
  if (!visible) return '';
  return (await node.textContent())?.trim() ?? '';
}

/** Creates a temporary fixture file matching the attack case profile. */
function createFixture(kind: (typeof FILE_CASES)[number]['kind']): string {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-upload-'));
  const out = path.join(tempDir, fileName(kind));
  fs.writeFileSync(out, fileContent(kind));
  return out;
}

/** Maps fixture kind to realistic file names used in upload edge tests. */
function fileName(kind: (typeof FILE_CASES)[number]['kind']): string {
  const map = {
    zero_pdf: '0kb.pdf',
    big_pdf: '50MB.pdf',
    password_pdf: 'password-protected.pdf',
    corrupt_pdf: 'corrupted.pdf',
    js_pdf: 'embedded-js.pdf',
    image_as_pdf: 'image-as-pdf.pdf',
    html_as_pdf: 'html-as-pdf.pdf'
  } as const;
  return map[kind];
}

/** Builds binary content that approximates each malicious file class. */
function fileContent(kind: (typeof FILE_CASES)[number]['kind']): Buffer {
  if (kind === 'zero_pdf') return Buffer.alloc(0);
  if (kind === 'big_pdf') return Buffer.alloc(50 * 1024 * 1024, 'A');
  if (kind === 'password_pdf') return Buffer.from('%PDF-1.4\n%encrypted-placeholder\n', 'utf8');
  if (kind === 'corrupt_pdf') return Buffer.from('NOT_A_PDF_HEADER', 'utf8');
  if (kind === 'js_pdf') return Buffer.from('%PDF-1.4\n1 0 obj\n<< /JS (app.alert(1)) >>\n', 'utf8');
  if (kind === 'image_as_pdf') return Buffer.from([0x89, 0x50, 0x4e, 0x47]);
  return Buffer.from('<html><script>alert(1)</script></html>', 'utf8');
}
