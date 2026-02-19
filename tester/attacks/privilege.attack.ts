import { APIRequestContext } from 'playwright';
import { EvidencePaths, saveRequestResponseEvidence } from '../utils/evidence';
import { Logger, Severity } from '../utils/logger';

export type PrivilegeAttackName =
  | 'candidate_changes_application_status'
  | 'recruiter_creates_job'
  | 'company_admin_access_platform_companies'
  | 'self_role_escalation_patch_me';

export type PrivilegeAttackResult = {
  role: string;
  flow: string;
  attack: PrivilegeAttackName;
  severity: Severity;
  status: number;
  details: string;
  evidencePath: string;
};

export type PrivilegeAttackOptions = {
  logger: Logger;
  request: APIRequestContext;
  evidenceDirs: EvidencePaths;
  apiBasePath?: string;
  candidateToken: string;
  recruiterToken: string;
  companyAdminToken: string;
  applicationId: string;
};

type AttackCase = {
  role: string;
  flow: string;
  name: PrivilegeAttackName;
  method: 'GET' | 'POST' | 'PATCH';
  endpoint: string;
  token: string;
  body?: Record<string, unknown>;
};

/** Runs direct privilege escalation attempts across platform role boundaries. */
export async function runPrivilegeAttacks(options: PrivilegeAttackOptions): Promise<PrivilegeAttackResult[]> {
  const results: PrivilegeAttackResult[] = [];
  for (const testCase of buildCases(options)) {
    const response = await send(options.request, testCase);
    const status = response.status();
    const severity = classify(status);
    const details = severity === 'CRITICAL' ? 'CRITICAL: forbidden action succeeded' : 'Blocked as expected';
    const evidencePath = saveRequestResponseEvidence(options.evidenceDirs, `priv-${testCase.name}`, {
      request: { method: testCase.method, url: testCase.endpoint, headers: authHeaders(testCase.token), body: testCase.body },
      response: { status, headers: response.headers(), body: await safeBody(response) },
      tokenUsed: testCase.token
    });

    logResult(options.logger, testCase, severity, status);
    results.push({ role: testCase.role, flow: testCase.flow, attack: testCase.name, severity, status, details, evidencePath });
  }

  return results;
}

/** Builds privilege abuse scenarios from candidate, recruiter, and admin roles. */
function buildCases(options: PrivilegeAttackOptions): AttackCase[] {
  const api = options.apiBasePath ?? '/api';
  return [
    {
      role: 'candidate',
      flow: 'privilege',
      name: 'candidate_changes_application_status',
      method: 'POST',
      endpoint: `${api}/applications/${options.applicationId}/status`,
      token: options.candidateToken,
      body: { status: 'shortlisted' }
    },
    {
      role: 'recruiter',
      flow: 'privilege',
      name: 'recruiter_creates_job',
      method: 'POST',
      endpoint: `${api}/jobs`,
      token: options.recruiterToken,
      body: { title: `unauthorized-job-${Date.now()}`, description: 'blocked expected' }
    },
    {
      role: 'companyAdmin',
      flow: 'privilege',
      name: 'company_admin_access_platform_companies',
      method: 'GET',
      endpoint: `${api}/platform/companies`,
      token: options.companyAdminToken
    },
    {
      role: 'candidate',
      flow: 'privilege',
      name: 'self_role_escalation_patch_me',
      method: 'PATCH',
      endpoint: `${api}/users/me`,
      token: options.candidateToken,
      body: { role: 'superAdmin' }
    }
  ];
}

/** Sends one HTTP call for a privilege attack case. */
async function send(request: APIRequestContext, testCase: AttackCase) {
  const payload = { headers: authHeaders(testCase.token), data: testCase.body };
  if (testCase.method === 'POST') return request.post(testCase.endpoint, payload);
  if (testCase.method === 'PATCH') return request.patch(testCase.endpoint, payload);
  return request.get(testCase.endpoint, payload);
}

/** Marks forbidden-success outcomes as CRITICAL security failures. */
function classify(status: number): Severity {
  if (status >= 200 && status < 300) return 'CRITICAL';
  if (status === 401 || status === 403) return 'PASS';
  return 'WARN';
}

/** Logs the final severity for each privilege escalation attempt. */
function logResult(logger: Logger, testCase: AttackCase, severity: Severity, status: number): void {
  const msg = `status=${status} endpoint=${testCase.endpoint}`;
  if (severity === 'CRITICAL') logger.critical(testCase.role, testCase.flow, testCase.name, msg);
  else if (severity === 'WARN') logger.warn(testCase.role, testCase.flow, testCase.name, msg);
  else logger.log('PASS', testCase.role, testCase.flow, testCase.name, msg);
}

/** Builds common bearer authorization headers for attack calls. */
function authHeaders(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
}

/** Reads response body for evidence storage using JSON fallback logic. */
async function safeBody(response: Awaited<ReturnType<APIRequestContext['get']>>): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return await response.text();
  }
}
