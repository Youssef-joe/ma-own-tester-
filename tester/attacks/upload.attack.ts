import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { APIRequestContext } from 'playwright';
import { EvidencePaths, saveRequestResponseEvidence } from '../utils/evidence';
import { Logger, Severity } from '../utils/logger';

export type UploadAttackLabel =
  | 'oversized file'
  | 'wrong MIME type'
  | 'double extension'
  | 'null byte injection'
  | 'empty file'
  | 'svg with script'
  | 'zip bomb renamed'
  | 'path traversal name';

export type UploadAttackResult = {
  role: string;
  flow: string;
  attack: UploadAttackLabel;
  severity: Severity;
  status: number;
  details: string;
  evidencePath: string;
};

export type UploadAttackOptions = {
  role: string;
  flow: string;
  logger: Logger;
  request: APIRequestContext;
  evidenceDirs: EvidencePaths;
  token: string;
  uploadEndpoint: string;
};

type UploadCase = {
  label: UploadAttackLabel;
  fileName: string;
  mimeType: string;
  content: Buffer;
};

/** Runs malicious CV upload scenarios against the upload API endpoint. */
export async function runUploadAttacks(options: UploadAttackOptions): Promise<UploadAttackResult[]> {
  const results: UploadAttackResult[] = [];
  for (const item of buildUploadCases()) {
    const response = await postMultipart(options, item);
    const status = response.status();
    const severity = classify(status);
    const details = severity === 'CRITICAL' ? 'CRITICAL: malicious upload accepted' : 'Rejected or blocked as expected';
    const evidencePath = saveRequestResponseEvidence(options.evidenceDirs, `upload-${item.label}`, {
      request: {
        method: 'POST',
        url: options.uploadEndpoint,
        headers: authHeaders(options.token),
        body: { fileName: item.fileName, mimeType: item.mimeType, bytes: item.content.length }
      },
      response: { status, headers: response.headers(), body: await safeBody(response) },
      tokenUsed: options.token
    });

    logResult(options, item.label, severity, status);
    results.push({ role: options.role, flow: options.flow, attack: item.label, severity, status, details, evidencePath });
  }

  return results;
}

/** Posts multipart form-data upload with crafted payload and filename. */
async function postMultipart(options: UploadAttackOptions, item: UploadCase) {
  const temp = createTempFile(item.fileName, item.content);
  const multipart = {
    cv: {
      name: item.fileName,
      mimeType: item.mimeType,
      buffer: fs.readFileSync(temp)
    }
  };
  return options.request.post(options.uploadEndpoint, { headers: authHeaders(options.token), multipart });
}

/** Builds the full malicious upload test matrix from the specification. */
function buildUploadCases(): UploadCase[] {
  return [
    { label: 'oversized file', fileName: '50MB.pdf', mimeType: 'application/pdf', content: Buffer.alloc(50 * 1024 * 1024, 'A') },
    { label: 'wrong MIME type', fileName: 'malware.pdf', mimeType: 'application/x-msdownload', content: Buffer.from('MZ-fake-exe', 'utf8') },
    { label: 'double extension', fileName: 'cv.pdf.exe', mimeType: 'application/octet-stream', content: Buffer.from('double-ext', 'utf8') },
    { label: 'null byte injection', fileName: 'cv.pdf\u0000.exe', mimeType: 'application/octet-stream', content: Buffer.from('null-byte', 'utf8') },
    { label: 'empty file', fileName: '0kb.pdf', mimeType: 'application/pdf', content: Buffer.alloc(0) },
    { label: 'svg with script', fileName: 'xss.svg', mimeType: 'image/svg+xml', content: Buffer.from('<svg onload=alert(1)>', 'utf8') },
    { label: 'zip bomb renamed', fileName: 'bomb.pdf', mimeType: 'application/pdf', content: Buffer.from('PK\u0003\u0004-fake-zip', 'utf8') },
    { label: 'path traversal name', fileName: '../../etc/passwd.pdf', mimeType: 'application/pdf', content: Buffer.from('%PDF-1.4\n', 'utf8') }
  ];
}

/** Classifies upload result: accepted malicious file means CRITICAL. */
function classify(status: number): Severity {
  if (status >= 200 && status < 300) return 'CRITICAL';
  if (status >= 400) return 'PASS';
  return 'WARN';
}

/** Writes severity-aware logs for each upload attack execution. */
function logResult(options: UploadAttackOptions, label: UploadAttackLabel, severity: Severity, status: number): void {
  const message = `status=${status} attack=${label}`;
  if (severity === 'CRITICAL') options.logger.critical(options.role, options.flow, label, message);
  else if (severity === 'WARN') options.logger.warn(options.role, options.flow, label, message);
  else options.logger.log('PASS', options.role, options.flow, label, message);
}

/** Creates temporary file used by API multipart upload helper. */
function createTempFile(fileName: string, content: Buffer): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-upload-attack-'));
  const filePath = path.join(dir, fileName.replace(/[\\/]/g, '_'));
  fs.writeFileSync(filePath, content);
  return filePath;
}

/** Builds bearer-auth JSON headers for upload attack requests. */
function authHeaders(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

/** Reads response body safely as JSON or text for evidence capture. */
async function safeBody(response: Awaited<ReturnType<APIRequestContext['post']>>): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return await response.text();
  }
}
