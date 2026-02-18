import crypto from 'node:crypto';

export type JwtPayload = Record<string, unknown> & {
  exp?: number;
  role?: string;
};

/** Decodes JWT payload safely without verifying signature. */
export function decodeJwtPayload(token: string): JwtPayload {
  const parts = token.split('.');
  if (parts.length < 2) throw new Error('Invalid JWT format');
  return JSON.parse(base64UrlDecode(parts[1])) as JwtPayload;
}

/** Creates an expired variant of a JWT by setting exp in the past. */
export function createExpiredToken(token: string, secret = ''): string {
  const payload = { ...decodeJwtPayload(token), exp: Math.floor(Date.now() / 1000) - 3600 };
  return rebuildToken(token, payload, secret);
}

/** Creates a tampered token with modified payload and original signature. */
export function tamperPayloadKeepSignature(token: string, patch: Partial<JwtPayload>): string {
  const [header, payload, signature] = token.split('.');
  if (!header || !payload || !signature) throw new Error('Invalid JWT format');
  const merged = { ...JSON.parse(base64UrlDecode(payload)), ...patch };
  return `${header}.${base64UrlEncode(JSON.stringify(merged))}.${signature}`;
}

/** Builds an alg=none JWT with manipulated payload and empty signature. */
export function createNoneAlgorithmToken(token: string, patch: Partial<JwtPayload>): string {
  const header = { alg: 'none', typ: 'JWT' };
  const payload = { ...decodeJwtPayload(token), ...patch };
  return `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(payload))}.`;
}

/** Creates a role-escalated token signed with provided secret or blank secret. */
export function forgeRoleToken(token: string, role: string, secret = ''): string {
  const payload = { ...decodeJwtPayload(token), role };
  return rebuildToken(token, payload, secret);
}

/** Returns a redacted token string preserving only the last 10 chars. */
export function redactToken(token: string): string {
  if (token.length <= 10) return '*'.repeat(token.length);
  return `${'*'.repeat(Math.max(0, token.length - 10))}${token.slice(-10)}`;
}

/** Rebuilds JWT using original header and a supplied payload. */
function rebuildToken(token: string, payload: JwtPayload, secret: string): string {
  const [header] = token.split('.');
  if (!header) throw new Error('Invalid JWT format');
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${header}.${encodedPayload}`;
  const signature = signHs256(signingInput, secret);
  return `${signingInput}.${signature}`;
}

/** Signs JWT data using HMAC SHA-256 and base64url output. */
function signHs256(data: string, secret: string): string {
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64');
  return sig.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/** Encodes a UTF-8 string using base64url encoding. */
function base64UrlEncode(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/** Decodes base64url content into a UTF-8 string. */
function base64UrlDecode(value: string): string {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  return Buffer.from(padded, 'base64').toString('utf8');
}
