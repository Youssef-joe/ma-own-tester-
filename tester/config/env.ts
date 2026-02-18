import fs from 'node:fs';
import path from 'node:path';
import dotenv from 'dotenv';
import { AppConfig, EnvName, OnlyMode, appConfigSchema, envNameSchema, onlyModeSchema } from './schema';

/** Parses --env from CLI args and validates allowed values. */
export function parseEnvArg(argv: string[]): EnvName {
  return envNameSchema.parse(readFlag(argv, '--env', 'local'));
}

/** Parses --only from CLI args and validates suite selector values. */
export function parseOnlyArg(argv: string[]): OnlyMode {
  return onlyModeSchema.parse(readFlag(argv, '--only', 'all'));
}

/** Loads matching .env file for env and returns validated runtime config. */
export function loadConfig(envName: EnvName): AppConfig {
  const envFile = path.resolve(process.cwd(), `.env.${envName}`);
  if (!fs.existsSync(envFile)) {
    throw new Error(`Missing env file: ${envFile}`);
  }

  dotenv.config({ path: envFile, override: true });
  const raw = {
    baseURL: process.env.BASE_URL,
    apiBasePath: process.env.API_BASE_PATH,
    slowThresholdMs: Number(process.env.SLOW_THRESHOLD_MS ?? 2000),
    credentials: {
      candidate: {
        email: process.env.CANDIDATE_EMAIL,
        password: process.env.CANDIDATE_PASSWORD
      },
      recruiter: {
        email: process.env.RECRUITER_EMAIL,
        password: process.env.RECRUITER_PASSWORD
      },
      companyAdmin: {
        email: process.env.COMPANY_ADMIN_EMAIL,
        password: process.env.COMPANY_ADMIN_PASSWORD
      },
      superAdmin: {
        email: process.env.SUPER_ADMIN_EMAIL,
        password: process.env.SUPER_ADMIN_PASSWORD
      }
    }
  };

  return appConfigSchema.parse(raw);
}

/** Reads a CLI flag using --key=value form with default fallback. */
function readFlag(argv: string[], key: '--env' | '--only', fallback: string): string {
  return argv.find((arg) => arg.startsWith(`${key}=`))?.split('=')[1] ?? fallback;
}
