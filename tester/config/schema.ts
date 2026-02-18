import { z } from 'zod';

/** Supported runtime environments. */
export const envNameSchema = z.enum(['local', 'stage', 'prod']);

/** Supported runner selection flags. */
export const onlyModeSchema = z.enum(['all', 'flows', 'attacks', 'performance']);

/** One role account credential pair. */
const roleCredentialSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});

/** Multi-role credential set used by the aggressive suite. */
const credentialsSchema = z.object({
  candidate: roleCredentialSchema,
  recruiter: roleCredentialSchema,
  companyAdmin: roleCredentialSchema,
  superAdmin: roleCredentialSchema
});

/** Runtime application config schema. */
export const appConfigSchema = z.object({
  baseURL: z.string().url(),
  apiBasePath: z.string().min(1),
  slowThresholdMs: z.number().int().positive().default(2000),
  credentials: credentialsSchema
});

export type EnvName = z.infer<typeof envNameSchema>;
export type OnlyMode = z.infer<typeof onlyModeSchema>;
export type AppConfig = z.infer<typeof appConfigSchema>;
