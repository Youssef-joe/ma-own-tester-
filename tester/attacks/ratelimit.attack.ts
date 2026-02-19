import { APIRequestContext } from 'playwright';
import { EvidencePaths, saveRequestResponseEvidence } from '../utils/evidence';
import { Logger, Severity } from '../utils/logger';

export type RateLimitAttackName =
  | 'login_flood_50'
  | 'application_flood_20'
  | 'concurrent_cv_upload_10'
  | 'rapid_status_change_15';

export type RateLimitAttackResult = {
  role: string;
  flow: string;
  attack: RateLimitAttackName;
  severity: Severity;
  details: string;
  evidencePath: string;
  statusHistogram: Record<string, number>;
};

export type RateLimitAttackOptions = {
  role: string;
  flow: string;
  logger: Logger;
  request: APIRequestContext;
  evidenceDirs: EvidencePaths;
  apiBasePath?: string;
  candidateToken: string;
  recruiterToken: string;
  loginPayload: { email: string; password: string };
  applicationPayload: Record<string, unknown>;
  applicationId: string;
};

/** Runs flood and concurrency attacks to validate effective rate-limiting controls. */
export async function runRateLimitAttacks(options: RateLimitAttackOptions): Promise<RateLimitAttackResult[]> {
  const cases = buildCases(options);
  const results: RateLimitAttackResult[] = [];
  for (const testCase of cases) {
    const statuses = await testCase.run();
    const histogram = makeHistogram(statuses);
    const saw429 = statuses.some((code) => code === 429);
    const severity = saw429 ? 'PASS' : statuses.length >= 20 ? 'FAIL' : 'WARN';
    const details = saw429 ? 'Rate limiting observed (429 received)' : 'No 429 seen under aggressive repeated load';
    const evidencePath = saveRequestResponseEvidence(options.evidenceDirs, `ratelimit-${testCase.name}`, {
      request: { method: testCase.method, url: testCase.endpoint, body: testCase.body, headers: testCase.headers },
      response: { status: statuses[0] ?? 0, body: { statuses, histogram } },
      tokenUsed: testCase.token ?? ''
    });

    logResult(options.logger, options.role, options.flow, testCase.name, severity, histogram);
    results.push({ role: options.role, flow: options.flow, attack: testCase.name, severity, details, evidencePath, statusHistogram: histogram });
  }

  return results;
}

type CaseDef = {
  name: RateLimitAttackName;
  method: 'POST' | 'PATCH';
  endpoint: string;
  body: unknown;
  headers: Record<string, string>;
  token?: string;
  run: () => Promise<number[]>;
};

/** Constructs all rate-limit scenarios defined in the aggressive spec. */
function buildCases(options: RateLimitAttackOptions): CaseDef[] {
  const api = options.apiBasePath ?? '/api';
  return [
    {
      name: 'login_flood_50',
      method: 'POST',
      endpoint: `${api}/auth/login`,
      body: options.loginPayload,
      headers: jsonHeaders(),
      run: async () => burst(options.request, 50, () => options.request.post(`${api}/auth/login`, { data: options.loginPayload }))
    },
    {
      name: 'application_flood_20',
      method: 'POST',
      endpoint: `${api}/applications`,
      body: options.applicationPayload,
      headers: authHeaders(options.candidateToken),
      token: options.candidateToken,
      run: async () => burst(options.request, 20, () => options.request.post(`${api}/applications`, {
        headers: authHeaders(options.candidateToken),
        data: options.applicationPayload
      }))
    },
    {
      name: 'concurrent_cv_upload_10',
      method: 'POST',
      endpoint: `${api}/cv/upload`,
      body: { fileName: 'same-cv.pdf', size: 1024 },
      headers: authHeaders(options.candidateToken),
      token: options.candidateToken,
      run: async () => burst(options.request, 10, () => options.request.post(`${api}/cv/upload`, {
        headers: authHeaders(options.candidateToken),
        multipart: {
          cv: {
            name: 'same-cv.pdf',
            mimeType: 'application/pdf',
            buffer: Buffer.from('%PDF-1.4\nqa-test\n', 'utf8')
          }
        }
      }), true)
    },
    {
      name: 'rapid_status_change_15',
      method: 'PATCH',
      endpoint: `${api}/applications/${options.applicationId}/status`,
      body: { status: 'shortlisted' },
      headers: authHeaders(options.recruiterToken),
      token: options.recruiterToken,
      run: async () => burst(options.request, 15, (index) => options.request.patch(`${api}/applications/${options.applicationId}/status`, {
        headers: authHeaders(options.recruiterToken),
        data: { status: index % 2 === 0 ? 'shortlisted' : 'rejected' }
      }))
    }
  ];
}

/** Executes repeated HTTP requests either sequentially or concurrently. */
async function burst(
  _request: APIRequestContext,
  count: number,
  sender: (index: number) => Promise<Awaited<ReturnType<APIRequestContext['post']>>>,
  concurrent = false
): Promise<number[]> {
  if (concurrent) {
    const responses = await Promise.all(Array.from({ length: count }, (_, i) => sender(i)));
    return responses.map((res) => res.status());
  }

  const out: number[] = [];
  for (let i = 0; i < count; i += 1) {
    out.push((await sender(i)).status());
  }

  return out;
}

/** Converts status code list into summary histogram for reporting and evidence. */
function makeHistogram(statuses: number[]): Record<string, number> {
  return statuses.reduce<Record<string, number>>((acc, status) => {
    const key = String(status);
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});
}

/** Writes per-attack log lines with severity and status breakdown. */
function logResult(
  logger: Logger,
  role: string,
  flow: string,
  attack: RateLimitAttackName,
  severity: Severity,
  histogram: Record<string, number>
): void {
  const message = `statuses=${JSON.stringify(histogram)}`;
  if (severity === 'FAIL') logger.fail(role, flow, attack, message);
  else if (severity === 'WARN') logger.warn(role, flow, attack, message);
  else logger.log('PASS', role, flow, attack, message);
}

/** Builds JSON content-type header map for unauthenticated login flood tests. */
function jsonHeaders(): Record<string, string> {
  return { 'content-type': 'application/json' };
}

/** Builds bearer authorization headers used in authenticated flood tests. */
function authHeaders(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
}
