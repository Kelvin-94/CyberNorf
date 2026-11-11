import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { AuthenticatedUser } from '@/server/authz/context';
import {
  apiKeyStatus,
  issueApiKey,
  MAX_ACTIVE_API_KEYS_PER_ORGANIZATION,
  type ApiKeyStatus,
} from '@/server/domain/api-keys';
import { conflict, forbidden, notFound } from '@/server/errors';
import type { RequestMeta } from '@/server/http/request-meta';
import type { ApiKeyCreateInput } from '@/server/validation/api-keys';
import { assertQuotaAvailable } from './quotas';

/**
 * Personal API key lifecycle.
 *
 * Keys are owned by a person and bound to one organization, so there is no
 * organization-wide key an administrator could read or hand out. Creating a key
 * never widens what its owner can do: every request is authorized against the
 * live membership, and a key that outlives the membership stops working when
 * the membership is disabled. The plaintext credential is returned by
 * `createUserApiKey` only; no read path can reproduce it.
 */

/** Keys one console page lists before it stops; the table is small by design. */
const LIST_LIMIT = 50;

export interface UserApiKeyView {
  id: string;
  name: string;
  prefix: string;
  status: ApiKeyStatus;
  active: boolean;
  organization: { id: string; name: string; slug: string };
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

interface ApiKeyRow {
  id: string;
  name: string;
  keyPrefix: string;
  createdAt: Date;
  expiresAt: Date;
  lastUsedAt: Date | null;
  revokedAt: Date | null;
  organization: { id: string; name: string; slug: string };
}

const API_KEY_SELECT = {
  id: true,
  name: true,
  keyPrefix: true,
  createdAt: true,
  expiresAt: true,
  lastUsedAt: true,
  revokedAt: true,
  organization: { select: { id: true, name: true, slug: true } },
} as const;

function toView(row: ApiKeyRow, now: Date = new Date()): UserApiKeyView {
  const status = apiKeyStatus(row, now);
  return {
    id: row.id,
    name: row.name,
    prefix: row.keyPrefix,
    status,
    active: status === 'ACTIVE',
    organization: row.organization,
    createdAt: row.createdAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
    revokedAt: row.revokedAt?.toISOString() ?? null,
  };
}

export async function listUserApiKeys(
  userId: string,
  organizationId?: string,
): Promise<UserApiKeyView[]> {
  const rows = await prisma.userApiKey.findMany({
    where: organizationId ? { userId, organizationId } : { userId },
    orderBy: [{ createdAt: 'desc' }],
    take: LIST_LIMIT,
    select: API_KEY_SELECT,
  });

  const now = new Date();
  return rows.map((row) => toView(row, now));
}

export interface CreatedUserApiKey {
  /** Plaintext credential. Present in this response only. */
  key: string;
  apiKey: UserApiKeyView;
}

/**
 * Issues a key for the caller. Two-factor enrollment is required because a key
 * is a durable credential that bypasses the interactive sign-in flow, and the
 * account settings page is the only place a key may be created: an existing key
 * cannot mint its own successor.
 */
export async function createUserApiKey(
  user: AuthenticatedUser,
  input: ApiKeyCreateInput,
  meta: RequestMeta,
): Promise<CreatedUserApiKey> {
  if (user.apiKey) {
    throw forbidden(
      'Create API keys from the account settings page while signed in with a session.',
    );
  }

  if (!user.twoFactorEnabled) {
    throw forbidden('Enroll two-factor authentication before creating an API key.', 'MFA_REQUIRED');
  }

  const membership = await prisma.membership.findUnique({
    where: { userId_organizationId: { userId: user.id, organizationId: input.organizationId } },
    select: { id: true, status: true },
  });

  if (!membership || membership.status !== 'ACTIVE') {
    throw notFound('Organization not found.');
  }

  const now = new Date();
  const activeCount = await prisma.userApiKey.count({
    where: {
      userId: user.id,
      organizationId: input.organizationId,
      revokedAt: null,
      expiresAt: { gt: now },
    },
  });

  if (activeCount >= MAX_ACTIVE_API_KEYS_PER_ORGANIZATION) {
    throw conflict(
      `You already hold ${MAX_ACTIVE_API_KEYS_PER_ORGANIZATION} active keys for this organization. Revoke one before creating another.`,
    );
  }

  const issued = issueApiKey(input.expiresInDays, now);

  const row = await prisma.$transaction(async (tx) => {
    const organization = await tx.organization.findUnique({
      where: { id: input.organizationId },
      select: { tier: true },
    });

    if (!organization) {
      throw notFound('Organization not found.');
    }

    // The per-user cap above is a hard product limit; the tier quota is an
    // org-wide limit, so both apply and the stricter one wins.
    await assertQuotaAvailable(tx, {
      organizationId: input.organizationId,
      tier: organization.tier,
      resource: 'apiKeys',
    });

    const created = await tx.userApiKey.create({
      data: {
        name: input.name,
        keyHash: issued.hash,
        keyPrefix: issued.prefix,
        userId: user.id,
        organizationId: input.organizationId,
        expiresAt: issued.expiresAt,
      },
      select: API_KEY_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId: input.organizationId,
      actorType: 'USER',
      actorId: user.id,
      action: AuditActions.API_KEY_CREATED,
      outcome: 'SUCCESS',
      targetType: 'api_key',
      targetId: created.id,
      summary: `Created personal API key "${created.name}"`,
      metadata: {
        keyPrefix: created.keyPrefix,
        name: created.name,
        expiresAt: created.expiresAt.toISOString(),
      },
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      requestId: meta.requestId,
    });

    return created;
  });

  return { key: issued.key, apiKey: toView(row, now) };
}

/**
 * Revokes one of the caller's keys. Revocation is immediate: the next request
 * with that credential fails authentication because the hash lookup also checks
 * `revokedAt`.
 */
export async function revokeUserApiKey(
  user: AuthenticatedUser,
  keyId: string,
  meta: RequestMeta,
): Promise<UserApiKeyView> {
  const existing = await prisma.userApiKey.findFirst({
    where: { id: keyId, userId: user.id },
    select: { id: true, name: true, keyPrefix: true, organizationId: true, revokedAt: true },
  });

  if (!existing) {
    throw notFound('API key not found.');
  }

  if (existing.revokedAt) {
    throw conflict('This API key is already revoked.');
  }

  const revokedAt = new Date();

  const row = await prisma.$transaction(async (tx) => {
    const updated = await tx.userApiKey.update({
      where: { id: existing.id },
      data: { revokedAt },
      select: API_KEY_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId: existing.organizationId,
      actorType: 'USER',
      actorId: user.id,
      action: AuditActions.API_KEY_REVOKED,
      outcome: 'SUCCESS',
      targetType: 'api_key',
      targetId: updated.id,
      summary: `Revoked personal API key "${updated.name}"`,
      metadata: {
        keyPrefix: updated.keyPrefix,
        via: user.apiKey ? 'api_key' : 'session',
      },
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      requestId: meta.requestId,
    });

    return updated;
  });

  return toView(row, revokedAt);
}
