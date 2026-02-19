# QA Automation Tool

TypeScript + Playwright automation runner for end-to-end quality, security, and edge-case validation of a recruitment SaaS platform.

## Overview

This project executes multiple testing layers in one run:

- Role-based browser flows for Candidate, Recruiter, Company Admin, and Super Admin journeys.
- API-focused security attack suites (JWT, IDOR, privilege escalation, upload abuse, and rate-limit pressure).
- Input and file edge-case fuzzing against key candidate forms.
- Runtime watchers for console errors, network anomalies, and performance thresholds.
- Consolidated HTML reporting with evidence artifacts and severity-based exit codes for CI gating.

## Coverage

### Functional Flows

- `candidate`: register, browse jobs, apply, upload CV, check status, route authorization boundaries.
- `recruiter`: candidate list/profile actions, status changes, admin-route blocking, cross-company isolation checks.
- `companyAdmin`: create/edit jobs, review recruiter activity, super-admin route blocking.
- `superAdmin`: platform-wide company/user views and account activation lifecycle.

### Security Attacks

- `jwt.attack.ts`: expired token, invalid signature, none algorithm, role escalation, malformed/missing token, token reuse after logout.
- `idor.attack.ts`: cross-application and cross-company object access checks.
- `privilege.attack.ts`: unauthorized action attempts across role boundaries.
- `upload.attack.ts`: malicious file upload scenarios and bypass vectors.
- `ratelimit.attack.ts`: flood/concurrency tests with status histogram capture.

### Edge Cases

- `inputTester.ts`: payload matrix for XSS, SQL injection strings, null bytes, overflow values, malformed email, and special characters.
- `fileTester.ts`: malformed, oversized, renamed, and suspicious CV file variants.

## Tech Stack

- Node.js + TypeScript
- Playwright (`browser` + `APIRequestContext`)
- Zod (runtime config validation)
- ts-node (TypeScript execution without build step)

## Project Structure

```text
.
├── testRunner.ts
├── playwright.config.ts
├── tester
│   ├── attacks
│   ├── edgeCases
│   ├── flows
│   ├── watchers
│   ├── config
│   └── utils
└── reports
```

## Prerequisites

- Node.js 18+ (recommended 20+)
- npm 9+
- Reachable target frontend/API environments
- Valid credentials for all configured roles

## Installation

```bash
npm install
```

## Configuration

The runner loads environment files using this convention:

- `.env.local`
- `.env.stage`
- `.env.prod`

### Required Variables

```dotenv
BASE_URL=https://your-frontend.example.com
API_BASE_PATH=/api

CANDIDATE_EMAIL=candidate@example.com
CANDIDATE_PASSWORD=your-password
RECRUITER_EMAIL=recruiter@example.com
RECRUITER_PASSWORD=your-password
COMPANY_ADMIN_EMAIL=admin@example.com
COMPANY_ADMIN_PASSWORD=your-password
SUPER_ADMIN_EMAIL=superadmin@example.com
SUPER_ADMIN_PASSWORD=your-password
```

### Optional Runtime Variables

- `API_BASE_URL` (if omitted, API calls use `BASE_URL`)
- `SLOW_THRESHOLD_MS` (default: `2000`)

### Optional Overrides

Use these only if your environment requires explicit IDs, tokens, or selector overrides:

- `CANDIDATE_A_TOKEN`
- `CANDIDATE_B_TOKEN`
- `RECRUITER_TOKEN`
- `COMPANY_ADMIN_TOKEN`
- `SUPER_ADMIN_TOKEN`
- `OTHER_CANDIDATE_ID`
- `OTHER_COMPANY_ID`
- `OTHER_COMPANY_JOB_ID`
- `TEST_JOB_ID`
- `MAIN_FORM_SUBMIT_SELECTOR`
- `MAIN_FORM_ERROR_SELECTOR`
- `CV_FILE_SELECTOR`
- `CV_SUBMIT_SELECTOR`
- `CV_ERROR_SELECTOR`

## Running the Suite

### Standard Scripts

```bash
npm test                 # all suites on local env
npm run test:local       # all suites, local
npm run test:stage       # all suites, stage
npm run test:prod        # all suites, prod
npm run test:flows       # flow-focused run
npm run test:security    # attacks-focused run
npm run test:perf        # performance-focused run
```

### Custom CLI Flags

```bash
npx ts-node testRunner.ts --env=stage --only=attacks
```

Supported values:

- `--env`: `local | stage | prod`
- `--only`: `all | flows | attacks | performance`

## Output and Reporting

Each run writes artifacts under:

- `reports/YYYY-MM-DD/report.html`
- `reports/YYYY-MM-DD/<role>/<scope>/screenshots/`
- `reports/YYYY-MM-DD/<role>/<scope>/snapshots/`
- `reports/YYYY-MM-DD/<role>/<scope>/logs/`

The HTML report includes:

- Executive severity summary
- Security, business-logic, performance, and edge-case sections
- Console and network watcher findings
- Evidence links for failures

## Exit Codes

The process exit code is severity-aware:

- `0`: no `FAIL` or `CRITICAL` findings
- `1`: at least one `FAIL`
- `2`: at least one `CRITICAL`

This behavior is intended for CI/CD quality gates.

## CI Usage Example

```bash
npm ci
npm run test:stage
```

If critical or failing findings are detected, the pipeline step fails automatically.

## Troubleshooting

- `Missing env file`: ensure `.env.<env>` exists for the selected `--env`.
- Frequent UI selector failures: confirm target app labels/selectors match the current frontend.
- API attack false negatives: verify `API_BASE_PATH`, role permissions, and seed IDs/tokens.
- Report did not open with `npm run report`: confirm `reports/<date>/report.html` exists for today’s run.
