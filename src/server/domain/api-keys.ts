import { createHash, randomBytes } from 'node:crypto';

/**
 * Personal API key rules.
 *
 * A key is a long-lived alternative to a browser session for one person and
 * one organization. It carries no scopes of its own: every request is
 * authorized through the owner's live membership, so removing someone from a
 * team or changing their role takes effect on the next call instead of waiting
 * for the credential to expire.
 *
 * Only the SHA-256 digest is stored. The plaintext value exists in the creation
 * response and nowhere else, which is why a lost key has to be replaced rather
 * than looked up.
 */

export const API_KEY_PREFIX = 'cnk_';
const KEY_RANDOM_BYTES = 32;
/** Clear-text characters kept after the prefix, e.g. `cnk_9fK2xQ`. */
const KEY_DISPLAY_CHARS = 6;

export const API_KEY_MIN_TTL_DAYS = 7;
export const API_KEY_MAX_TTL_DAYS = 365;
export const API_KEY_DEFAULT_TTL_DAYS = 90;

/**
 * Active keys one person may hold per organization. Keys are meant to replace a
 * handful of scripts, not to become an unmanaged credential store.
 */
export const MAX_ACTIVE_API_KEYS_PER_ORGANIZATION = 5;

const DAY_MS = 24 * 60 * 60 * 1000;

export interface IssuedApiKey {
  /** Plaintext credential, returned once and never persisted. */
  key: string;
  /** SHA-256 hex digest, which is what the database keeps. */
  hash: string;
  /** Clear-text display prefix, e.g. `cnk_9fK2xQ`. */
  prefix: string;
  expiresAt: Date;
}

export function hashApiKey(key: string): string {
  return createHash('sha256').update(key, 'utf8').digest('hex');
}

/** Cheap shape check so a malformed Authorization header never reaches the database. */
export function isApiKeyShape(key: string): boolean {
  return /^cnk_[A-Za-z0-9_-]{40,64}$/.test(key);
}

export function issueApiKey(ttlDays: number, now: Date = new Date()): IssuedApiKey {
  const key = `${API_KEY_PREFIX}${randomBytes(KEY_RANDOM_BYTES).toString('base64url')}`;
  const start = API_KEY_PREFIX.length;

  return {
    key,
    hash: hashApiKey(key),
    prefix: key.slice(0, start + KEY_DISPLAY_CHARS),
    expiresAt: new Date(now.getTime() + ttlDays * DAY_MS),
  };
}

export type ApiKeyStatus = 'ACTIVE' | 'EXPIRED' | 'REVOKED';

export interface ApiKeyLifetime {
  expiresAt: Date;
  revokedAt: Date | null;
}

/**
 * Derivation order matters: a revoked key stays `REVOKED` after its expiry date
 * so the console never suggests it merely aged out.
 */
export function apiKeyStatus(row: ApiKeyLifetime, now: Date = new Date()): ApiKeyStatus {
  if (row.revokedAt) {
    return 'REVOKED';
  }
  return row.expiresAt.getTime() <= now.getTime() ? 'EXPIRED' : 'ACTIVE';
}

export function isApiKeyUsable(row: ApiKeyLifetime, now: Date = new Date()): boolean {
  return apiKeyStatus(row, now) === 'ACTIVE';
}
