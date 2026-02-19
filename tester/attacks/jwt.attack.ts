import { APIRequestContext } from 'playwright';
import { EvidencePaths, saveRequestResponseEvidence } from '../utils/evidence';
import { Logger, Severity } from '../utils/logger';
import {
  createExpiredToken,
  createNoneAlgorithmToken,
  forgeRoleToken,
  redactToken,
  tamperPayloadKeepSignature
} from '../utils/jwt.utils';

export type JwtAttackName =
  | 'expired_token'
  | 'invalid_signature'
  | 'none_algorithm'
  | 'role_escalation'
  | 'missing_token'
  | 'malformed_token'
  | 'reused_after_logout';

export type JwtAttackResult = {
  role: string;
  flow: string;
  attack: JwtAttackName;
  severity: Severity;
  status: number;
  details: string;
  evidencePath: string;
};

export type JwtAttackOptions = {
  role: string;
  flow: string;
  logger: Logger;
  evidenceDirs: EvidencePaths;
  request: APIRequestContext;
  validToken: string;
  protectedEndpoint: string;
  logoutEndpoint: string;
  jwtSecret?: string;
  method?: 'GET' | 'POST';
  body?: Record<string, unknown>;
};

const JWT_ATTACKS: readonly JwtAttackName[] = [
  'expired_token',
  'invalid_signature',
  'none_algorithm',
  'role_escalation',
  'missing_token',
  'malformed_token',
  'reused_after_logout'
] as const;

/** Runs all JWT manipulation attacks against one protected API endpoint. */
export async function runJwtAttacks(options: JwtAttackOptions): Promise<JwtAttackResult[]> {
  const results: JwtAttackResult[] = [];
  for (const attack of JWT_ATTACKS) {
    const result = await runSingleJwtAttack(attack, options);
    results.push(result);
  }

  return results;
}

/** Executes one JWT attack vector and records normalized result + evidence. */
async function runSingleJwtAttack(attack: JwtAttackName, options: JwtAttackOptions): Promise<JwtAttackResult> {
  const forged = await buildAttackToken(attack, options);
  const requestMeta = { method: options.method ?? 'GET', url: options.protectedEndpoint, body: options.body };
  const response = await callProtectedEndpoint(options, forged);
  const severity = classifyJwtStatus(response.status());
  const details = severity === 'CRITICAL' ? 'CRITICAL SECURITY FAILURE: endpoint accepted invalid JWT' : 'Rejected as expected';
  const evidencePath = saveRequestResponseEvidence(options.evidenceDirs, `jwt-${attack}`, {
    request: { ...requestMeta, headers: authHeaders(forged) },
    response: { status: response.status(), headers: response.headers(), body: await safeJson(response) },
    tokenUsed: forged ?? 'NO_TOKEN'
  });

  logJwtResult(options, attack, severity, response.status(), forged);
  return { role: options.role, flow: options.flow, attack, severity, status: response.status(), details, evidencePath };
}

/** Creates manipulated token variant per attack type using a real source token. */
async function buildAttackToken(attack: JwtAttackName, options: JwtAttackOptions): Promise<string | null> {
  if (attack === 'expired_token') return createExpiredToken(options.validToken, options.jwtSecret ?? '');
  if (attack === 'invalid_signature') return tamperPayloadKeepSignature(options.validToken, { nonce: Date.now() });
  if (attack === 'none_algorithm') return createNoneAlgorithmToken(options.validToken, { role: options.role });
  if (attack === 'role_escalation') return forgeRoleToken(options.validToken, 'superAdmin', options.jwtSecret ?? '');
  if (attack === 'missing_token') return null;
  if (attack === 'malformed_token') return 'not.a.valid.jwt-token';
  await options.request.post(options.logoutEndpoint, { headers: authHeaders(options.validToken) });
  return options.validToken;
}

/** Performs protected endpoint call with attack token and optional request body. */
async function callProtectedEndpoint(options: JwtAttackOptions, token: string | null) {
  const method = options.method ?? 'GET';
  const payload = { headers: authHeaders(token), data: options.body };
  if (method === 'POST') return options.request.post(options.protectedEndpoint, payload);
  return options.request.get(options.protectedEndpoint, payload);
}

/** Converts status code to severity, escalating 200-class responses to CRITICAL. */
function classifyJwtStatus(status: number): Severity {
  if (status >= 200 && status < 300) return 'CRITICAL';
  if (status === 401 || status === 403) return 'PASS';
  return 'WARN';
}

/** Builds Authorization header set for Bearer-token based API requests. */
function authHeaders(token: string | null): Record<string, string> {
  if (!token) return { 'content-type': 'application/json' };
  return { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
}

/** Parses JSON response when possible and falls back to text content. */
async function safeJson(response: Awaited<ReturnType<APIRequestContext['get']>>): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return await response.text();
  }
}

/** Writes severity-aware logs with role, flow, attack, and redacted token details. */
function logJwtResult(options: JwtAttackOptions, attack: JwtAttackName, severity: Severity, status: number, token: string | null): void {
  const msg = `status=${status} token=${token ? redactToken(token) : 'none'}`;
  if (severity === 'CRITICAL') options.logger.critical(options.role, options.flow, attack, msg);
  else if (severity === 'WARN') options.logger.warn(options.role, options.flow, attack, msg);
  else options.logger.log('PASS', options.role, options.flow, attack, msg);
}
