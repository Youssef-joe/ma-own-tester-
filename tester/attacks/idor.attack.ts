import { APIRequestContext } from 'playwright';
import { EvidencePaths, saveRequestResponseEvidence } from '../utils/evidence';
import { Logger, Severity } from '../utils/logger';

export type IdorAttackName =
  | 'candidate_application_cross_access'
  | 'candidate_cv_cross_access'
  | 'recruiter_other_company_candidates'
  | 'company_admin_modify_other_company_job';

export type IdorAttackResult = {
  role: string;
  flow: string;
  attack: IdorAttackName;
  severity: Severity;
  status: number;
  endpoint: string;
  details: string;
  evidencePath: string;
};

export type IdorAttackOptions = {
  logger: Logger;
  request: APIRequestContext;
  evidenceDirs: EvidencePaths;
  apiBasePath?: string;
  candidateAToken: string;
  recruiterToken: string;
  companyAdminToken: string;
  candidateAApplicationId: string;
  candidateBApplicationId: string;
  otherCandidateId: string;
  otherCompanyId: string;
  otherCompanyJobId: string;
};

type IdorCase = {
  role: string;
  flow: string;
  attack: IdorAttackName;
  method: 'GET' | 'PUT';
  endpoint: string;
  token: string;
  body?: Record<string, unknown>;
};

/** Runs IDOR cross-resource attacks with real authenticated role tokens. */
export async function runIdorAttacks(options: IdorAttackOptions): Promise<IdorAttackResult[]> {
  const cases = buildCases(options);
  const results: IdorAttackResult[] = [];
  for (const testCase of cases) {
    const response = await send(testCase, options.request);
    const status = response.status();
    const severity = classify(status);
    const details = severity === 'CRITICAL' ? 'CRITICAL: unauthorized cross-resource access succeeded' : 'Rejected as expected';
    const evidencePath = saveRequestResponseEvidence(options.evidenceDirs, `idor-${testCase.attack}`, {
      request: { method: testCase.method, url: testCase.endpoint, headers: authHeaders(testCase.token), body: testCase.body },
      response: { status, headers: response.headers(), body: await safeBody(response) },
      tokenUsed: testCase.token
    });

    logResult(options.logger, testCase, severity, status);
    results.push({ role: testCase.role, flow: testCase.flow, attack: testCase.attack, severity, status, endpoint: testCase.endpoint, details, evidencePath });
  }

  return results;
}

/** Builds canonical IDOR test matrix across candidate/recruiter/admin contexts. */
function buildCases(options: IdorAttackOptions): IdorCase[] {
  const api = options.apiBasePath ?? '/api';
  return [
    {
      role: 'candidate',
      flow: 'idor',
      attack: 'candidate_application_cross_access',
      method: 'GET',
      endpoint: `${api}/applications/${options.candidateBApplicationId}`,
      token: options.candidateAToken
    },
    {
      role: 'candidate',
      flow: 'idor',
      attack: 'candidate_cv_cross_access',
      method: 'GET',
      endpoint: `${api}/candidates/${options.otherCandidateId}/cv`,
      token: options.candidateAToken
    },
    {
      role: 'recruiter',
      flow: 'idor',
      attack: 'recruiter_other_company_candidates',
      method: 'GET',
      endpoint: `${api}/companies/${options.otherCompanyId}/candidates`,
      token: options.recruiterToken
    },
    {
      role: 'companyAdmin',
      flow: 'idor',
      attack: 'company_admin_modify_other_company_job',
      method: 'PUT',
      endpoint: `${api}/jobs/${options.otherCompanyJobId}`,
      token: options.companyAdminToken,
      body: { title: `unauthorized-update-${Date.now()}` }
    }
  ];
}

/** Sends one HTTP request for a given IDOR case with auth context. */
async function send(testCase: IdorCase, request: APIRequestContext) {
  const payload = { headers: authHeaders(testCase.token), data: testCase.body };
  if (testCase.method === 'PUT') return request.put(testCase.endpoint, payload);
  return request.get(testCase.endpoint, payload);
}

/** Returns CRITICAL when unauthorized object access is accepted by server. */
function classify(status: number): Severity {
  if (status >= 200 && status < 300) return 'CRITICAL';
  if (status === 401 || status === 403) return 'PASS';
  return 'WARN';
}

/** Writes severity-aware logs for each IDOR case outcome. */
function logResult(logger: Logger, testCase: IdorCase, severity: Severity, status: number): void {
  const msg = `status=${status} endpoint=${testCase.endpoint}`;
  if (severity === 'CRITICAL') logger.critical(testCase.role, testCase.flow, testCase.attack, msg);
  else if (severity === 'WARN') logger.warn(testCase.role, testCase.flow, testCase.attack, msg);
  else logger.log('PASS', testCase.role, testCase.flow, testCase.attack, msg);
}

/** Builds standard JSON API headers with bearer authorization token. */
function authHeaders(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
}

/** Parses HTTP response body safely for evidence persistence. */
async function safeBody(response: Awaited<ReturnType<APIRequestContext['get']>>): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return await response.text();
  }
}
