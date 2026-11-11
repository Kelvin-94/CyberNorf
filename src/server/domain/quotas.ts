import type { SubscriptionTier } from '@/generated/prisma/client';

/**
 * Resource limits per tenant.
 *
 * Two rules keep this honest:
 *
 * 1. A quota bounds *growth*, not correctness. Nothing here may deny a read, and
 *    nothing here is an authorization decision — a tenant at its asset limit can
 *    still read every asset it has.
 * 2. Limits are per tenant, not per user, because the resource is owned by the
 *    tenant. Two analysts sharing one organization share one budget, which is the
 *    point: it bounds what the tenant can cost the operator.
 *
 * `null` means unlimited. Community is deliberately limited; Enterprise is not,
 * because a contract decides that, not a default.
 */

export type QuotaResource =
  | 'assets'
  | 'findings'
  | 'incidents'
  | 'identities'
  | 'agents'
  | 'indicators'
  | 'apiKeys'
  | 'evidenceStorageMb';

export type QuotaLimits = Record<QuotaResource, number | null>;

export const QUOTA_RESOURCES: readonly QuotaResource[] = [
  'assets',
  'findings',
  'incidents',
  'identities',
  'agents',
  'indicators',
  'apiKeys',
  'evidenceStorageMb',
];

/**
 * Defaults by tier. The numbers are chosen so the limits are reachable in normal
 * use but a runaway import or a stuck loop hits a wall long before it becomes an
 * operator problem: 10k findings for a small team is roughly two years of real
 * output, and 500 MB of evidence is a few thousand screenshots.
 *
 * `apiKeys` is deliberately unset at every tier. A person is already limited to
 * five active keys per organization (`MAX_ACTIVE_API_KEYS_PER_ORGANIZATION`), and
 * an organization-wide cap expressed as a fixed number would undercut that: a
 * three-person team sharing one tenant needs more than three keys for CI. The
 * column still exists so an operator can impose a tenant-wide ceiling through an
 * override when a customer's key sprawl warrants it.
 */
export const TIER_QUOTAS: Record<SubscriptionTier, QuotaLimits> = {
  COMMUNITY: {
    assets: 50,
    findings: 2_000,
    incidents: 200,
    identities: 100,
    agents: 5,
    indicators: 1_000,
    apiKeys: null,
    evidenceStorageMb: 50,
  },
  STUDENT: {
    assets: 100,
    findings: 5_000,
    incidents: 500,
    identities: 250,
    agents: 10,
    indicators: 5_000,
    apiKeys: null,
    evidenceStorageMb: 100,
  },
  PROFESSIONAL: {
    assets: 2_000,
    findings: 100_000,
    incidents: 5_000,
    identities: 2_000,
    agents: 100,
    indicators: 50_000,
    apiKeys: null,
    evidenceStorageMb: 5_000,
  },
  // Unlimited: an Enterprise agreement states the real limits, and a default here
  // would silently contradict a signed contract.
  ENTERPRISE: {
    assets: null,
    findings: null,
    incidents: null,
    identities: null,
    agents: null,
    indicators: null,
    apiKeys: null,
    evidenceStorageMb: null,
  },
};

export const BYTES_PER_MB = 1024 * 1024;

/** Hard ceiling on a single uploaded artifact, independent of the tenant quota. */
export const MAX_EVIDENCE_BYTES = 10 * BYTES_PER_MB;

/**
 * Content types accepted for evidence. Narrow on purpose: these are the formats
 * an auditor actually receives, and everything else is a container that would
 * need a parser we do not have. The extension is not trusted; the declared type
 * is checked against this list and the bytes are hashed, never interpreted.
 */
export const ALLOWED_EVIDENCE_TYPES = [
  'application/pdf',
  'image/png',
  'image/jpeg',
  'image/webp',
  'text/plain',
  'text/csv',
  'application/json',
  'text/markdown',
] as const;

export type AllowedEvidenceType = (typeof ALLOWED_EVIDENCE_TYPES)[number];

export function isAllowedEvidenceType(value: string): value is AllowedEvidenceType {
  return (ALLOWED_EVIDENCE_TYPES as readonly string[]).includes(value);
}

/**
 * Combines a tier default with a tenant override. An override of `undefined`
 * means "not set" and keeps the default; an override of `null` would mean
 * unlimited, but the column is nullable for "not set", so the two are
 * distinguished before this is called — the caller passes `undefined` for unset.
 */
export function resolveLimit(
  tier: SubscriptionTier,
  resource: QuotaResource,
  override: number | undefined,
): number | null {
  if (override !== undefined) {
    return override;
  }
  return TIER_QUOTAS[tier][resource];
}

/** Formats a limit for an error message; unlimited reads as text, not as 0. */
export function describeLimit(limit: number | null, resource: QuotaResource): string {
  if (limit === null) {
    return 'unlimited';
  }
  if (resource === 'evidenceStorageMb') {
    return limit >= 1024 ? `${(limit / 1024).toFixed(1)} GB` : `${limit} MB`;
  }
  return limit.toLocaleString('en-US');
}

/** The resource's name as a human reads it in a message. */
export const QUOTA_RESOURCE_LABELS: Record<QuotaResource, string> = {
  assets: 'assets',
  findings: 'findings',
  incidents: 'incidents',
  identities: 'identities',
  agents: 'agents',
  indicators: 'indicators',
  apiKeys: 'API keys',
  evidenceStorageMb: 'evidence storage',
};
