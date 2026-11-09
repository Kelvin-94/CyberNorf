import { prisma } from '@/lib/prisma';
import { hashApiKey, isApiKeyShape } from '@/server/domain/api-keys';
import { unauthenticated } from '@/server/errors';
import type { AuthenticatedUser } from './context';

/**
 * Bearer-key authentication for the console API.
 *
 * `Authorization: Bearer cnk_...` is resolved to the owning user and the one
 * organization the key was issued for. No session cookie is consulted, so a
 * key and a session can never be mixed into a single request: an Authorization
 * header that is present but unusable fails closed instead of falling back to
 * the cookie.
 */

const BEARER_PATTERN = /^Bearer\s+(\S+)$/i;

/**
 * Rewriting `lastUsedAt` on every request would turn a read into a write and
 * serialize concurrent calls on the same row. The console only needs a coarse
 * "last used" signal, so it is refreshed at most once per interval.
 */
const LAST_USED_WRITE_INTERVAL_MS = 5 * 60 * 1000;

/**
 * Extracts a bearer credential. Returns null when the header is absent and
 * throws when it is present but malformed, so a proxy that mangles the header
 * cannot silently downgrade the request to anonymous access.
 */
export function readBearerCredential(headers: Headers): string | null {
  const header = headers.get('authorization');
  if (header === null || header.trim().length === 0) {
    return null;
  }

  const match = BEARER_PATTERN.exec(header.trim());
  if (!match?.[1]) {
    throw unauthenticated();
  }
  return match[1];
}

export function hasAuthorizationHeader(headers: Headers): boolean {
  return (headers.get('authorization') ?? '').trim().length > 0;
}

/**
 * Resolves a personal API key to its owning user. Unknown, revoked and expired
 * keys are indistinguishable to the caller (all 401) so the endpoint cannot be
 * used to confirm which guessed credential once existed.
 */
export async function resolveApiKeyUser(
  headers: Headers,
  now: Date = new Date(),
): Promise<AuthenticatedUser | null> {
  const credential = readBearerCredential(headers);
  if (credential === null) {
    return null;
  }
  if (!isApiKeyShape(credential)) {
    throw unauthenticated();
  }

  const row = await prisma.userApiKey.findUnique({
    where: { keyHash: hashApiKey(credential) },
    select: {
      id: true,
      organizationId: true,
      expiresAt: true,
      revokedAt: true,
      lastUsedAt: true,
      user: {
        select: { id: true, name: true, email: true, twoFactorEnabled: true },
      },
    },
  });

  if (!row || row.revokedAt !== null || row.expiresAt.getTime() <= now.getTime()) {
    throw unauthenticated();
  }

  if (
    row.lastUsedAt === null ||
    now.getTime() - row.lastUsedAt.getTime() > LAST_USED_WRITE_INTERVAL_MS
  ) {
    try {
      await prisma.userApiKey.update({ where: { id: row.id }, data: { lastUsedAt: now } });
    } catch (error) {
      // Usage metadata must never turn a valid request into a failure.
      console.error('[api-key] failed to record last usage:', error);
    }
  }

  return {
    id: row.user.id,
    name: row.user.name,
    email: row.user.email,
    twoFactorEnabled: row.user.twoFactorEnabled === true,
    sessionId: null,
    apiKey: { id: row.id, organizationId: row.organizationId },
  };
}
