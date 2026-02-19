import { APIRequestContext, Page, chromium, request as playwrightRequest } from 'playwright';
import { loadConfig, parseEnvArg, parseOnlyArg } from './tester/config/env';
import { AppConfig, OnlyMode } from './tester/config/schema';
import { runCandidateFlow } from './tester/flows/candidate.flow';
import { runRecruiterFlow } from './tester/flows/recruiter.flow';
import { runCompanyAdminFlow } from './tester/flows/admin.flow';
import { runSuperAdminFlow } from './tester/flows/superadmin.flow';
import { runJwtAttacks } from './tester/attacks/jwt.attack';
import { runIdorAttacks } from './tester/attacks/idor.attack';
import { runUploadAttacks } from './tester/attacks/upload.attack';
import { runPrivilegeAttacks } from './tester/attacks/privilege.attack';
import { runRateLimitAttacks } from './tester/attacks/ratelimit.attack';
import { runInputEdgeCases } from './tester/edgeCases/inputTester';
import { runFileEdgeCases } from './tester/edgeCases/fileTester';
import { attachConsoleWatcher } from './tester/watchers/console.watcher';
import { attachNetworkWatcher } from './tester/watchers/network.watcher';
import { createPerformanceWatcher } from './tester/watchers/performance.watcher';
import { ensureEvidenceDirs, saveWatcherLogs } from './tester/utils/evidence';
import { Logger, Severity } from './tester/utils/logger';
import { ReportFinding, generateHtmlReport } from './tester/utils/report';

type Role = keyof AppConfig['credentials'];
type RoleCred = { email: string; password: string; id?: string };
type Tokens = { candidateA: string; candidateB: string; recruiter: string; companyAdmin: string; superAdmin: string };
type SeedIds = { candidateAApplicationId: string; candidateBApplicationId: string; otherCandidateId: string; otherCompanyId: string; otherCompanyJobId: string };
type RuntimeState = { createdUsers: RoleCred[]; tokens: Tokens; ids: SeedIds };

/** Runs aggressive QA suite with mode-based execution and severity exits. */
async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const envName = parseEnvArg(argv);
  const only = parseOnlyArg(argv);
  const config = loadConfig(envName);
  const start = Date.now();
  const runDate = new Date().toISOString().slice(0, 10);
  const logger = new Logger();
  const browser = await chromium.launch({ headless: envName !== 'local' });
  const context = await browser.newContext({ baseURL: config.baseURL });
  const page = await context.newPage();
  const api = await playwrightRequest.newContext({ baseURL: config.apiBaseURL ?? config.baseURL });

  try {
    const consoleWatcher = attachConsoleWatcher(page);
    const networkWatcher = attachNetworkWatcher(page, config.slowThresholdMs);
    const perfWatcher = createPerformanceWatcher();
    const runtime = await prepareRuntimeState(api, config, logger);
    const findings = await executeSuite({ only, page, api, config, runDate, logger, consoleWatcher, networkWatcher, perfWatcher, runtime });
    await cleanupRuntime(api, config, runtime, logger);
    const reportPath = finalizeReport(findings, runDate, envName, start, logger, consoleWatcher.getLogs(), networkWatcher.getIssues(), perfWatcher.getIssues(), perfWatcher.getStats());
    const exitCode = computeExitCode([...findings.flow, ...findings.security, ...findings.business, ...findings.edge]);
    console.log(`Report -> ${reportPath}`);
    await api.dispose();
    await context.close();
    await browser.close();
    process.exit(exitCode);
  } catch (error) {
    logger.fail('runner', 'runner', 'fatal', error instanceof Error ? error.message : String(error));
    await api.dispose();
    await context.close();
    await browser.close();
    process.exit(1);
  }
}

type ExecuteOptions = {
  only: OnlyMode;
  page: Page;
  api: APIRequestContext;
  config: AppConfig;
  runDate: string;
  logger: Logger;
  consoleWatcher: ReturnType<typeof attachConsoleWatcher>;
  networkWatcher: ReturnType<typeof attachNetworkWatcher>;
  perfWatcher: ReturnType<typeof createPerformanceWatcher>;
  runtime: RuntimeState;
};

/** Executes flow, attack, and edge pipelines according to --only mode. */
async function executeSuite(options: ExecuteOptions): Promise<{ flow: ReportFinding[]; security: ReportFinding[]; business: ReportFinding[]; edge: ReportFinding[] }> {
  const flow: ReportFinding[] = [];
  const security: ReportFinding[] = [];
  const business: ReportFinding[] = [];
  const edge: ReportFinding[] = [];
  if (options.only === 'all' || options.only === 'flows' || options.only === 'performance') {
    const flowOut = await runFlows(options);
    flow.push(...flowOut.flow);
    business.push(...flowOut.business);
  }

  if (options.only === 'all' || options.only === 'attacks') {
    security.push(...(await runAttacks(options)));
  }

  if (options.only === 'all') {
    edge.push(...(await runEdges(options)));
  }

  return { flow, security, business, edge };
}

/** Runs all role flows and records performance metrics after each flow. */
async function runFlows(options: ExecuteOptions): Promise<{ flow: ReportFinding[]; business: ReportFinding[] }> {
  const flow: ReportFinding[] = [];
  const business: ReportFinding[] = [];
  const common = { logger: options.logger, consoleWatcher: options.consoleWatcher, networkWatcher: options.networkWatcher };
  const candidates = await runCandidateFlow(options.page, options.config, { ...common, evidenceDirs: ensureEvidenceDirs(options.runDate, 'candidate', 'flows') });
  const recruiters = await runRecruiterFlow(options.page, options.config, { ...common, evidenceDirs: ensureEvidenceDirs(options.runDate, 'recruiter', 'flows'), otherCompanyId: options.runtime.ids.otherCompanyId });
  const admins = await runCompanyAdminFlow(options.page, options.config, { ...common, evidenceDirs: ensureEvidenceDirs(options.runDate, 'companyAdmin', 'flows') });
  const supers = await runSuperAdminFlow(options.page, options.config, { ...common, evidenceDirs: ensureEvidenceDirs(options.runDate, 'superAdmin', 'flows') });
  for (const item of [...candidates, ...recruiters, ...admins, ...supers]) splitFlowFinding(item, flow, business);
  options.perfWatcher.setContext('global', 'flows');
  await options.perfWatcher.capturePageMetrics(options.page, options.networkWatcher.getLargestApiDurationMs());
  return { flow, business };
}

/** Runs all security attack modules with real tokens and seeded identifiers. */
async function runAttacks(options: ExecuteOptions): Promise<ReportFinding[]> {
  const out: ReportFinding[] = [];
  const ids = options.runtime.ids;
  const t = options.runtime.tokens;
  const jwt = await runJwtAttacks({
    role: 'candidate',
    flow: 'jwt',
    logger: options.logger,
    evidenceDirs: ensureEvidenceDirs(options.runDate, 'candidate', 'jwt-attack'),
    request: options.api,
    validToken: t.candidateA,
    protectedEndpoint: apiPath(options.config.apiBasePath, '/users/me'),
    logoutEndpoint: apiPath(options.config.apiBasePath, '/auth/logout')
  });
  const idor = await runIdorAttacks({
    logger: options.logger,
    request: options.api,
    evidenceDirs: ensureEvidenceDirs(options.runDate, 'candidate', 'idor-attack'),
    candidateAToken: t.candidateA,
    recruiterToken: t.recruiter,
    companyAdminToken: t.companyAdmin,
    candidateAApplicationId: ids.candidateAApplicationId,
    candidateBApplicationId: ids.candidateBApplicationId,
    otherCandidateId: ids.otherCandidateId,
    otherCompanyId: ids.otherCompanyId,
    otherCompanyJobId: ids.otherCompanyJobId,
    apiBasePath: options.config.apiBasePath
  });
  const upload = await runUploadAttacks({
    role: 'candidate',
    flow: 'upload',
    logger: options.logger,
    request: options.api,
    evidenceDirs: ensureEvidenceDirs(options.runDate, 'candidate', 'upload-attack'),
    token: t.candidateA,
    uploadEndpoint: apiPath(options.config.apiBasePath, '/cv/upload')
  });
  const privilege = await runPrivilegeAttacks({
    logger: options.logger,
    request: options.api,
    evidenceDirs: ensureEvidenceDirs(options.runDate, 'candidate', 'privilege-attack'),
    candidateToken: t.candidateA,
    recruiterToken: t.recruiter,
    companyAdminToken: t.companyAdmin,
    applicationId: ids.candidateAApplicationId,
    apiBasePath: options.config.apiBasePath
  });
  const rateLimit = await runRateLimitAttacks({
    role: 'candidate',
    flow: 'ratelimit',
    logger: options.logger,
    request: options.api,
    evidenceDirs: ensureEvidenceDirs(options.runDate, 'candidate', 'ratelimit-attack'),
    candidateToken: t.candidateA,
    recruiterToken: t.recruiter,
    loginPayload: options.config.credentials.candidate,
    applicationPayload: { jobId: process.env.TEST_JOB_ID ?? '1', coverLetter: 'rate-limit test' },
    applicationId: ids.candidateAApplicationId,
    apiBasePath: options.config.apiBasePath
  });
  for (const item of [...jwt, ...idor, ...upload, ...privilege, ...rateLimit]) out.push(asFinding(item, item.attack, item.details));
  return out;
}

/** Runs form and file edge-case engines against known candidate forms. */
async function runEdges(options: ExecuteOptions): Promise<ReportFinding[]> {
  const out: ReportFinding[] = [];
  const dirs = ensureEvidenceDirs(options.runDate, 'candidate', 'edge-cases');
  await options.page.goto(`${options.config.baseURL}/register`, { waitUntil: 'domcontentloaded' });
  const input = await runInputEdgeCases(options.page, { role: 'candidate', flow: 'edgeCases', submitSelector: process.env.MAIN_FORM_SUBMIT_SELECTOR ?? 'button[type="submit"]', errorSelector: process.env.MAIN_FORM_ERROR_SELECTOR ?? '[role="alert"]', logger: options.logger, evidenceDirs: dirs, getConsoleLogs: () => options.consoleWatcher.getLogs(), getNetworkIssues: () => options.networkWatcher.getIssues() });
  await options.page.goto(`${options.config.baseURL}/candidate/profile`, { waitUntil: 'domcontentloaded' });
  const files = await runFileEdgeCases(options.page, { role: 'candidate', flow: 'fileEdge', inputSelector: process.env.CV_FILE_SELECTOR ?? 'input[type="file"]', submitSelector: process.env.CV_SUBMIT_SELECTOR ?? 'button[type="submit"]', errorSelector: process.env.CV_ERROR_SELECTOR ?? '[role="alert"]', logger: options.logger, evidenceDirs: dirs });
  for (const item of input) out.push(asFinding(item, `${item.field}:${item.caseLabel}`, item.details));
  for (const item of files) out.push(asFinding(item, item.caseLabel, item.details));
  return out;
}

/** Creates role test users and acquires real authenticated tokens plus seed IDs. */
async function prepareRuntimeState(api: APIRequestContext, config: AppConfig, logger: Logger): Promise<RuntimeState> {
  const createdUsers = await createTestUsersPerRole(api, config, logger);
  const tokens = await issueTokens(api, config, createdUsers, logger);
  const ids = await resolveSeedIds(api, config, tokens, createdUsers, logger);
  return { createdUsers, tokens, ids };
}

/** Attempts to register two users per role; falls back silently when blocked. */
async function createTestUsersPerRole(api: APIRequestContext, config: AppConfig, logger: Logger): Promise<RoleCred[]> {
  const roles: Role[] = ['candidate', 'recruiter', 'companyAdmin', 'superAdmin'];
  const out: RoleCred[] = [];
  for (const role of roles) {
    for (let i = 1; i <= 2; i += 1) {
      const email = `qa.${role}.${Date.now()}.${i}@example.test`;
      const password = `Qa!${role}${i}Pass123`;
      try {
        const res = await api.post(apiPath(config.apiBasePath, '/auth/register'), { data: { email, password, role, fullName: `QA ${role} ${i}` } });
        const body = await safeBody(res);
        out.push({ email, password, id: readId(body) });
      } catch {
        logger.warn(role, 'seed', 'register-user', `registration skipped for ${email}`);
      }
    }
  }

  return out;
}

/** Logs in users for attack modules and returns real bearer tokens by role. */
async function issueTokens(api: APIRequestContext, config: AppConfig, users: RoleCred[], logger: Logger): Promise<Tokens> {
  const candidateA = process.env.CANDIDATE_A_TOKEN ?? await loginForToken(api, config.apiBasePath, pickUser(users, 0, config.credentials.candidate), logger, 'candidateA');
  const candidateB = process.env.CANDIDATE_B_TOKEN ?? await loginForToken(api, config.apiBasePath, pickUser(users, 1, config.credentials.candidate), logger, 'candidateB');
  const recruiter = process.env.RECRUITER_TOKEN ?? await loginForToken(api, config.apiBasePath, config.credentials.recruiter, logger, 'recruiter');
  const companyAdmin = process.env.COMPANY_ADMIN_TOKEN ?? await loginForToken(api, config.apiBasePath, config.credentials.companyAdmin, logger, 'companyAdmin');
  const superAdmin = process.env.SUPER_ADMIN_TOKEN ?? await loginForToken(api, config.apiBasePath, config.credentials.superAdmin, logger, 'superAdmin');
  return { candidateA, candidateB, recruiter, companyAdmin, superAdmin };
}

/** Resolves IDs used by IDOR/privilege/rate-limit tests from API or env fallback. */
async function resolveSeedIds(api: APIRequestContext, config: AppConfig, tokens: Tokens, users: RoleCred[], logger: Logger): Promise<SeedIds> {
  const candidateAApplicationId = await createApplication(api, config.apiBasePath, tokens.candidateA, 'candidateA', logger);
  const candidateBApplicationId = await createApplication(api, config.apiBasePath, tokens.candidateB, 'candidateB', logger);
  const otherCandidateId = process.env.OTHER_CANDIDATE_ID ?? users[1]?.id ?? '2';
  const otherCompanyId = process.env.OTHER_COMPANY_ID ?? '2';
  const otherCompanyJobId = process.env.OTHER_COMPANY_JOB_ID ?? '2';
  return { candidateAApplicationId, candidateBApplicationId, otherCandidateId, otherCompanyId, otherCompanyJobId };
}

/** Performs cleanup attempts for seeded applications and ephemeral users. */
async function cleanupRuntime(api: APIRequestContext, config: AppConfig, runtime: RuntimeState, logger: Logger): Promise<void> {
  const appIds = [runtime.ids.candidateAApplicationId, runtime.ids.candidateBApplicationId];
  for (const id of appIds) {
    if (!id || id === '1' || id === '2') continue;
    await api.delete(apiPath(config.apiBasePath, `/applications/${id}`), { headers: auth(runtime.tokens.candidateA) }).catch(() => logger.warn('candidate', 'cleanup', 'delete-application', `failed for ${id}`));
  }
}

/** Writes report files, watcher logs, and prints severity summary lines. */
function finalizeReport(
  findings: { flow: ReportFinding[]; security: ReportFinding[]; business: ReportFinding[]; edge: ReportFinding[] },
  runDate: string,
  environment: string,
  started: number,
  logger: Logger,
  consoleLogs: ReturnType<ReturnType<typeof attachConsoleWatcher>['getLogs']>,
  networkIssues: ReturnType<ReturnType<typeof attachNetworkWatcher>['getIssues']>,
  performanceIssues: ReturnType<ReturnType<typeof createPerformanceWatcher>['getIssues']>,
  performanceStats: ReturnType<ReturnType<typeof createPerformanceWatcher>['getStats']>
): string {
  const dirs = ensureEvidenceDirs(runDate, 'global', 'run');
  saveWatcherLogs(dirs, consoleLogs, networkIssues, 'watchers');
  const reportPath = generateHtmlReport(dirs.dayDir, { environment, startedAt: new Date(started).toISOString(), finishedAt: new Date().toISOString(), durationMs: Date.now() - started, flowResults: findings.flow, securityResults: findings.security, businessResults: findings.business, edgeResults: findings.edge, consoleLogs, networkIssues, performanceIssues, performanceStats });
  const all = [...findings.flow, ...findings.security, ...findings.business, ...findings.edge];
  const levels = summarize(all);
  logger.info('runner', 'summary', 'totals', `critical=${levels.critical} fail=${levels.fail} warn=${levels.warn} pass=${levels.pass}`);
  return reportPath;
}

/** Computes process exit code based on highest severity found in run output. */
function computeExitCode(all: ReportFinding[]): number {
  if (all.some((f) => f.severity === 'CRITICAL')) return 2;
  if (all.some((f) => f.severity === 'FAIL')) return 1;
  return 0;
}

/** Splits flow output into business-boundary vs regular flow findings. */
function splitFlowFinding(item: { step: string; severity: Severity; role: string; flow: string; details: string; screenshotPath?: string; htmlPath?: string }, flow: ReportFinding[], business: ReportFinding[]): void {
  const finding = asFinding(item, item.step, item.details);
  if (/forbidden-route|cross-company|status/i.test(item.step)) business.push(finding);
  else flow.push(finding);
}

/** Normalizes heterogeneous module outputs to unified report finding schema. */
function asFinding(item: { role: string; flow: string; severity: Severity; screenshotPath?: string; htmlPath?: string; evidencePath?: string }, step: string, details: string): ReportFinding {
  return { role: item.role, flow: item.flow, step, severity: item.severity, details, screenshotPath: item.screenshotPath, htmlPath: item.htmlPath, evidencePath: item.evidencePath };
}

/** Logs in using provided credentials and extracts bearer token from response. */
async function loginForToken(api: APIRequestContext, apiBasePath: string, cred: RoleCred, logger: Logger, label: string): Promise<string> {
  const res = await api.post(apiPath(apiBasePath, '/auth/login'), { data: cred, headers: { accept: 'application/json', 'content-type': 'application/json' } });
  const body = await safeBody(res);
  const token = readToken(body, res.headers()['set-cookie']);
  if (!res.ok()) {
    throw new Error(`Login failed for ${label}: status=${res.status()} body=${shortBody(body)}`);
  }

  if (!token) {
    throw new Error(`Unable to obtain token for ${label}: status=${res.status()} body=${shortBody(body)}`);
  }

  logger.info('runner', 'seed', 'token', `issued for ${label}`);
  return token;
}

/** Creates one candidate application and returns its ID for attack seeding. */
async function createApplication(api: APIRequestContext, apiBasePath: string, token: string, label: string, logger: Logger): Promise<string> {
  const payload = { jobId: process.env.TEST_JOB_ID ?? '1', coverLetter: `seed application ${label}` };
  const res = await api.post(apiPath(apiBasePath, '/applications'), { headers: auth(token), data: payload });
  const body = await safeBody(res);
  const id = readId(body) ?? '1';
  logger.info('candidate', 'seed', 'application', `seeded ${label}:${id}`);
  return id;
}

/** Picks generated user or falls back to configured role credentials. */
function pickUser(users: RoleCred[], index: number, fallback: RoleCred): RoleCred {
  return users.filter((u) => u.email.includes('.candidate.'))[index] ?? fallback;
}

/** Extracts a token string from common API response shapes. */
function readToken(body: unknown, setCookie?: string): string {
  const src = body as Record<string, unknown>;
  const data = src?.data as Record<string, unknown> | undefined;
  const payload = src?.payload as Record<string, unknown> | undefined;
  const direct = src?.token ?? src?.accessToken ?? src?.jwt;
  const nested = data?.token ?? data?.accessToken ?? data?.jwt ?? payload?.token ?? payload?.accessToken;
  const cookieToken = parseTokenFromCookie(setCookie);
  return String(direct ?? nested ?? cookieToken ?? '');
}

/** Extracts resource ID from common API response payload shapes. */
function readId(body: unknown): string | undefined {
  const src = body as Record<string, unknown>;
  const direct = src?.id;
  const nested = (src?.data as Record<string, unknown> | undefined)?.id;
  const value = direct ?? nested;
  return value ? String(value) : undefined;
}

/** Extracts bearer-like token from Set-Cookie when API uses cookie auth. */
function parseTokenFromCookie(setCookie?: string): string | undefined {
  if (!setCookie) return undefined;
  const match = setCookie.match(/(?:token|access_token|accessToken|jwt|authToken)=([^;]+)/i);
  return match?.[1];
}

/** Converts response body into short one-line diagnostics for errors. */
function shortBody(body: unknown): string {
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  return String(raw ?? '').slice(0, 200);
}

/** Parses HTTP response body safely using JSON fallback to text. */
async function safeBody(response: Awaited<ReturnType<APIRequestContext['get']>>): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return await response.text();
  }
}

/** Builds bearer authorization header map for authenticated API calls. */
function auth(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
}

/** Joins configured API base path with endpoint suffix safely. */
function apiPath(basePath: string, endpoint: string): string {
  const base = basePath.endsWith('/') ? basePath.slice(0, -1) : basePath;
  const tail = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return `${base}${tail}`;
}

/** Aggregates severity totals for console summary output. */
function summarize(all: ReportFinding[]): Record<'critical' | 'fail' | 'warn' | 'pass', number> {
  return all.reduce((acc, item) => {
    if (item.severity === 'CRITICAL') acc.critical += 1;
    if (item.severity === 'FAIL') acc.fail += 1;
    if (item.severity === 'WARN') acc.warn += 1;
    if (item.severity === 'PASS') acc.pass += 1;
    return acc;
  }, { critical: 0, fail: 0, warn: 0, pass: 0 });
}

main();
