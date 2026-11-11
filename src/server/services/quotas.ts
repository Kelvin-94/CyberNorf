import type { Prisma, SubscriptionTier } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import {
  BYTES_PER_MB,
  QUOTA_RESOURCE_LABELS,
  QUOTA_RESOURCES,
  type QuotaLimits,
  type QuotaResource,
  describeLimit,
  resolveLimit,
} from '@/server/domain/quotas';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import { AppError } from '@/server/errors';

/**
 * Per-tenant resource quotas.
 *
 * The enforcement point is `assertQuotaAvailable`, called inside the same
 * transaction as the insert it guards. Checking outside the transaction would be
 * a time-of-check/time-of-use bug: two concurrent requests both read "limit - 1"
 * rows and both insert. A transaction alone is not enough either, because
 * READ COMMITTED lets both transactions count before either commits, so the
 * check takes a per-tenant, per-resource advisory lock first. The lock is
 * released when the transaction ends, including on rollback.
 *
 * The lock key includes the resource so that a burst of asset creations does not
 * serialise behind a burst of findings, and the tenant id so one tenant can never
 * block another.
 */

/** Namespace for quota advisory locks; distinct from the audit chain's lock. */
const QUOTA_LOCK_NAMESPACE = 0x514e4641; // "QNFA"

type Tx = Prisma.TransactionClient | typeof prisma;

/** Raised when a create would exceed the tenant's limit. */
export class QuotaExceededError extends AppError {
  readonly resource: QuotaResource;
  readonly limit: number;
  readonly used: number;

  constructor(resource: QuotaResource, limit: number, used: number) {
    super(
      409,
      'CONFLICT',
      `This organization has reached its ${QUOTA_RESOURCE_LABELS[resource]} limit (${describeLimit(limit, resource)}). Delete unused records or contact the operator to raise the limit.`,
    );
    this.resource = resource;
    this.limit = limit;
    this.used = used;
  }
}

/** Reads a tenant's overrides, keeping unset limits as `undefined`. */
async function loadOverrides(
  organizationId: string,
): Promise<Partial<Record<QuotaResource, number>>> {
  const row = await prisma.organizationQuota.findUnique({
    where: { organizationId },
    select: {
      assets: true,
      findings: true,
      incidents: true,
      identities: true,
      agents: true,
      indicators: true,
      apiKeys: true,
      evidenceStorageMb: true,
    },
  });
  if (!row) {
    return {};
  }
  const overrides: Partial<Record<QuotaResource, number>> = {};
  for (const resource of QUOTA_RESOURCES) {
    const value = row[resource];
    // A NULL column means "not overridden", not "unlimited". Unlimited is
    // expressed by the tier default (ENTERPRISE) or by an explicit override that
    // the operator cannot express as NULL, so it is deliberately not reachable
    // here — the schema only stores positive integers.
    if (value !== null) {
      overrides[resource] = value;
    }
  }
  return overrides;
}

/** The limits that actually apply to a tenant: tier defaults plus overrides. */
export async function getEffectiveLimits(
  organizationId: string,
  tier: SubscriptionTier,
): Promise<QuotaLimits> {
  const overrides = await loadOverrides(organizationId);
  const limits = {} as QuotaLimits;
  for (const resource of QUOTA_RESOURCES) {
    limits[resource] = resolveLimit(tier, resource, overrides[resource]);
  }
  return limits;
}

/** Row counts for every count-based resource, in one round trip. */
async function countUsage(
  organizationId: string,
): Promise<Record<Exclude<QuotaResource, 'evidenceStorageMb'>, number>> {
  const [assets, findings, incidents, identities, agents, indicators, apiKeys] =
    await prisma.$transaction([
      prisma.asset.count({ where: { organizationId } }),
      prisma.finding.count({ where: { organizationId } }),
      prisma.incident.count({ where: { organizationId } }),
      prisma.identity.count({ where: { organizationId } }),
      prisma.agent.count({ where: { organizationId } }),
      prisma.indicator.count({ where: { organizationId } }),
      prisma.userApiKey.count({ where: { organizationId, revokedAt: null } }),
    ]);
  return { assets, findings, incidents, identities, agents, indicators, apiKeys };
}

/** Bytes of stored evidence, summed from the recorded sizes. */
async function evidenceBytes(organizationId: string): Promise<number> {
  const result = await prisma.controlEvidence.aggregate({
    where: { organizationId, kind: 'FILE' },
    _sum: { sizeBytes: true },
  });
  return result._sum.sizeBytes ?? 0;
}

export interface QuotaUsage {
  resource: QuotaResource;
  limit: number | null;
  used: number;
  /** Null when unlimited; otherwise the share of the limit in use, 0-1. */
  proportion: number | null;
}

/**
 * Current usage and limits for the settings screen. Storage is reported in the
 * unit the limit uses (whole megabytes, rounded up) so the two numbers can be
 * compared without the reader doing arithmetic.
 */
export async function getQuotaUsage(
  organizationId: string,
  tier: SubscriptionTier,
): Promise<{ limits: QuotaLimits; usage: QuotaUsage[] }> {
  const [limits, counts, bytes] = await Promise.all([
    getEffectiveLimits(organizationId, tier),
    countUsage(organizationId),
    evidenceBytes(organizationId),
  ]);

  const usage = QUOTA_RESOURCES.map((resource): QuotaUsage => {
    const limit = limits[resource];
    const used =
      resource === 'evidenceStorageMb' ? Math.ceil(bytes / BYTES_PER_MB) : counts[resource];
    return {
      resource,
      limit,
      used,
      proportion: limit === null || limit === 0 ? null : Math.min(1, used / limit),
    };
  });

  return { limits, usage };
}

/**
 * Asserts that one more of `resource` fits, after taking the lock that makes the
 * check safe. Must be called inside the transaction that performs the insert.
 *
 * `units` is the number of *additional* units about to be consumed. It is 1 for a
 * row-based resource and the artifact size for storage.
 */
export async function assertQuotaAvailable(
  tx: Tx,
  input: {
    organizationId: string;
    tier: SubscriptionTier;
    resource: QuotaResource;
    units?: number;
  },
): Promise<void> {
  const units = input.units ?? 1;
  if (units <= 0) {
    return;
  }

  // Serialise quota checks for this tenant and resource until the transaction
  // commits. The lock is transaction-scoped, so a crash or rollback releases it.
  await tx.$queryRaw`SELECT 1::int AS locked FROM (SELECT pg_advisory_xact_lock(hashtextextended(${`${input.organizationId}:${input.resource}`}, ${QUOTA_LOCK_NAMESPACE}))) AS quota_lock`;

  const overrides = await loadOverrides(input.organizationId);
  const limit = resolveLimit(input.tier, input.resource, overrides[input.resource]);
  if (limit === null) {
    return;
  }

  let used: number;
  switch (input.resource) {
    case 'evidenceStorageMb':
      used = Math.ceil((await evidenceBytes(input.organizationId)) / BYTES_PER_MB);
      break;
    case 'apiKeys':
      used = await tx.userApiKey.count({
        where: { organizationId: input.organizationId, revokedAt: null },
      });
      break;
    case 'assets':
      used = await tx.asset.count({ where: { organizationId: input.organizationId } });
      break;
    case 'findings':
      used = await tx.finding.count({ where: { organizationId: input.organizationId } });
      break;
    case 'incidents':
      used = await tx.incident.count({ where: { organizationId: input.organizationId } });
      break;
    case 'identities':
      used = await tx.identity.count({ where: { organizationId: input.organizationId } });
      break;
    case 'agents':
      used = await tx.agent.count({ where: { organizationId: input.organizationId } });
      break;
    case 'indicators':
      used = await tx.indicator.count({ where: { organizationId: input.organizationId } });
      break;
    default: {
      const exhaustive: never = input.resource;
      throw new Error(`Unhandled quota resource: ${String(exhaustive)}`);
    }
  }

  if (used + units > limit) {
    throw new QuotaExceededError(input.resource, limit, used);
  }
}

/**
 * Sets or clears a tenant override. Passing `null` removes the override so the
 * tier default applies again; this is why the parameter is `number | null` and
 * not optional — "clear it" and "leave it alone" are different requests.
 *
 * Every change is written to the tenant's audit chain in the same transaction as
 * the row, because raising a limit is a security-relevant decision that must be
 * attributable. `actorId` is a user id and is subject to the audit table's
 * foreign key; an out-of-band operator has no user row, so the CLI passes
 * `actorLabel` instead and the label is recorded in the event metadata.
 */
export async function setQuotaOverride(
  organizationId: string,
  resource: QuotaResource,
  value: number | null,
  options: { actorId?: string | null; actorLabel?: string } = {},
): Promise<void> {
  if (value !== null && (!Number.isInteger(value) || value <= 0)) {
    throw new AppError(400, 'BAD_REQUEST', 'A quota override must be a positive whole number.');
  }

  await prisma.$transaction(async (tx) => {
    const existing = await tx.organizationQuota.findUnique({ where: { organizationId } });
    const previous = existing ? existing[resource] : null;

    await tx.organizationQuota.upsert({
      where: { organizationId },
      create: { organizationId, [resource]: value },
      update: { [resource]: value },
    });

    const changedBy = options.actorLabel ?? options.actorId ?? 'unspecified';

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'SYSTEM',
      actorId: options.actorId ?? null,
      action: AuditActions.QUOTA_OVERRIDE_CHANGED,
      outcome: 'SUCCESS',
      targetType: 'organization_quota',
      targetId: organizationId,
      summary:
        value === null
          ? `Cleared the ${QUOTA_RESOURCE_LABELS[resource]} override`
          : `Set the ${QUOTA_RESOURCE_LABELS[resource]} limit to ${describeLimit(value, resource)}`,
      metadata: { resource, previous, limit: value, changedBy },
    });
  });
}
