import { createHash } from 'node:crypto';
import type { AssetCriticality, FindingSeverity } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { computeRiskScore, remediationDueAt } from '@/server/domain/risk';
import { badRequest, notFound } from '@/server/errors';

/**
 * The two derived columns every finding write path must keep consistent.
 * Callers already know (or have just loaded) the asset criticality, so this
 * stays pure and usable inside a transaction.
 */
export function riskFields(input: {
  severity: FindingSeverity;
  cvssScore?: number | null;
  assetCriticality?: AssetCriticality | null;
  firstSeenAt: Date;
}): { riskScore: number; dueAt: Date } {
  return {
    riskScore: computeRiskScore({
      severity: input.severity,
      cvssScore: input.cvssScore ?? null,
      assetCriticality: input.assetCriticality ?? null,
    }),
    dueAt: remediationDueAt({ severity: input.severity, firstSeenAt: input.firstSeenAt }),
  };
}

export function isUniqueConstraintError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 'P2002'
  );
}

/** Stable identity for a finding within a tenant, used for import deduplication. */
export function findingFingerprint(input: {
  organizationId: string;
  assetId: string | null;
  title: string;
  source: string;
}): string {
  return createHash('sha256')
    .update(
      [
        input.organizationId,
        input.assetId ?? '',
        input.title.trim().toLowerCase().replace(/\s+/g, ' '),
        input.source,
      ].join('|'),
    )
    .digest('hex');
}

/**
 * Stable identity for a finding raised by an agent check. The check id plus the
 * scanned target is the identity, so two agents reporting the same weakness on
 * the same host converge on one finding instead of duplicating it every run.
 */
export function agentFingerprint(organizationId: string, checkId: string, target: string): string {
  return createHash('sha256')
    .update(
      [organizationId, 'agent', checkId.trim().toLowerCase(), target.trim().toLowerCase()].join(
        '|',
      ),
    )
    .digest('hex');
}

/**
 * Stable identity for a vulnerability raised by advisory matching. The advisory
 * identifier, the package and the host form the identity, so the same host
 * reported twice refreshes one finding and an installed upgrade stops matching
 * instead of leaving a duplicate behind.
 */
export function advisoryFingerprint(
  organizationId: string,
  identifier: string,
  packageName: string,
  target: string,
): string {
  return createHash('sha256')
    .update(
      [
        organizationId,
        'advisory',
        identifier.trim().toLowerCase(),
        packageName.trim().toLowerCase(),
        target.trim().toLowerCase(),
      ].join('|'),
    )
    .digest('hex');
}

export async function assertAssetInOrganization(
  organizationId: string,
  assetId: string | null | undefined,
): Promise<void> {
  if (!assetId) {
    return;
  }
  const asset = await prisma.asset.findFirst({
    where: { id: assetId, organizationId },
    select: { id: true },
  });
  if (!asset) {
    throw notFound('Asset not found in this organization.');
  }
}

export async function assertActiveMember(
  organizationId: string,
  userId: string | null | undefined,
): Promise<void> {
  if (!userId) {
    return;
  }
  const membership = await prisma.membership.findFirst({
    where: { organizationId, userId, status: 'ACTIVE' },
    select: { id: true },
  });
  if (!membership) {
    throw badRequest('The assignee must be an active member of this organization.');
  }
}

export async function assertIncidentInOrganization(
  organizationId: string,
  incidentId: string | null | undefined,
): Promise<void> {
  if (!incidentId) {
    return;
  }
  const incident = await prisma.incident.findFirst({
    where: { id: incidentId, organizationId },
    select: { id: true },
  });
  if (!incident) {
    throw notFound('Incident not found in this organization.');
  }
}

export function paginationMeta(page: number, pageSize: number, total: number) {
  return {
    page,
    pageSize,
    total,
    pageCount: Math.max(1, Math.ceil(total / pageSize)),
  };
}
