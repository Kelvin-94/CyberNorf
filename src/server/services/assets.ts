import type { AssetCriticality, AssetStatus, AssetType, Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import { conflict, notFound } from '@/server/errors';
import { findingFingerprint, isUniqueConstraintError, paginationMeta } from './shared';

export interface AssetListQuery {
  search?: string | null;
  type?: AssetType;
  status?: AssetStatus;
  criticality?: AssetCriticality;
  page: number;
  pageSize: number;
  sort: 'name' | 'createdAt' | 'updatedAt' | 'criticality';
  direction: 'asc' | 'desc';
}

const ASSET_SUMMARY_SELECT = {
  id: true,
  name: true,
  type: true,
  identifier: true,
  criticality: true,
  status: true,
  verificationStatus: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.AssetSelect;

export async function listAssets(organizationId: string, query: AssetListQuery) {
  const where: Prisma.AssetWhereInput = {
    organizationId,
    ...(query.type ? { type: query.type } : {}),
    ...(query.status ? { status: query.status } : {}),
    ...(query.criticality ? { criticality: query.criticality } : {}),
    ...(query.search
      ? {
          OR: [
            { name: { contains: query.search, mode: 'insensitive' } },
            { identifier: { contains: query.search, mode: 'insensitive' } },
            { description: { contains: query.search, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [items, total] = await prisma.$transaction([
    prisma.asset.findMany({
      where,
      select: {
        ...ASSET_SUMMARY_SELECT,
        _count: {
          select: { findings: { where: { status: { in: ['OPEN', 'TRIAGED', 'IN_PROGRESS'] } } } },
        },
      },
      orderBy: { [query.sort]: query.direction },
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
    prisma.asset.count({ where }),
  ]);

  return {
    items: items.map((asset) => ({
      ...asset,
      openFindings: asset._count.findings,
    })),
    ...paginationMeta(query.page, query.pageSize, total),
  };
}

export async function getAssetDetail(ctx: TenantContext, assetId: string) {
  const asset = await prisma.asset.findFirst({
    where: { id: assetId, organizationId: ctx.organization.id },
    select: {
      ...ASSET_SUMMARY_SELECT,
      description: true,
      createdAt: true,
      createdBy: { select: { id: true, name: true, email: true } },
      findings: {
        select: {
          id: true,
          title: true,
          severity: true,
          status: true,
          createdAt: true,
        },
        orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }],
        take: 50,
      },
    },
  });

  if (!asset) {
    throw notFound('Asset not found.');
  }

  return asset;
}

export async function createAsset(
  ctx: TenantContext,
  input: {
    name: string;
    type: AssetType;
    identifier: string;
    description?: string | null;
    criticality: AssetCriticality;
    status: AssetStatus;
  },
) {
  try {
    return await prisma.$transaction(async (tx) => {
      const asset = await tx.asset.create({
        data: {
          organizationId: ctx.organization.id,
          createdById: ctx.user.id,
          name: input.name,
          type: input.type,
          identifier: input.identifier,
          description: input.description ?? null,
          criticality: input.criticality,
          status: input.status,
        },
        select: ASSET_SUMMARY_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.ASSET_CREATED,
        outcome: 'SUCCESS',
        targetType: 'asset',
        targetId: asset.id,
        summary: `Asset ${asset.name} registered`,
        metadata: { name: asset.name, type: asset.type, identifier: asset.identifier },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return asset;
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict('An asset with this identifier already exists in this organization.');
    }
    throw error;
  }
}

export async function updateAsset(
  ctx: TenantContext,
  assetId: string,
  input: Partial<{
    name: string;
    type: AssetType;
    identifier: string;
    description: string | null;
    criticality: AssetCriticality;
    status: AssetStatus;
  }>,
) {
  const existing = await prisma.asset.findFirst({
    where: { id: assetId, organizationId: ctx.organization.id },
    select: { id: true, name: true, type: true, identifier: true, criticality: true, status: true },
  });

  if (!existing) {
    throw notFound('Asset not found.');
  }

  try {
    return await prisma.$transaction(async (tx) => {
      const asset = await tx.asset.update({
        where: { id: existing.id },
        data: input,
        select: ASSET_SUMMARY_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.ASSET_UPDATED,
        outcome: 'SUCCESS',
        targetType: 'asset',
        targetId: asset.id,
        summary: `Asset ${asset.name} updated`,
        metadata: {
          changedFields: Object.keys(input),
          before: existing,
          after: {
            name: asset.name,
            type: asset.type,
            identifier: asset.identifier,
            criticality: asset.criticality,
            status: asset.status,
          },
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return asset;
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict('An asset with this identifier already exists in this organization.');
    }
    throw error;
  }
}

export async function deleteAsset(ctx: TenantContext, assetId: string): Promise<void> {
  const existing = await prisma.asset.findFirst({
    where: { id: assetId, organizationId: ctx.organization.id },
    select: { id: true, name: true, identifier: true },
  });

  if (!existing) {
    throw notFound('Asset not found.');
  }

  await prisma.$transaction(async (tx) => {
    // The finding fingerprint covers the asset id, so findings left behind by the
    // delete (assetId is set to NULL) need theirs recomputed or a later import of
    // the same title would no longer match them.
    const orphaned = await tx.finding.findMany({
      where: { organizationId: ctx.organization.id, assetId: existing.id },
      select: { id: true, title: true, source: true },
    });

    await tx.asset.delete({ where: { id: existing.id } });

    for (const finding of orphaned) {
      const fingerprint = findingFingerprint({
        organizationId: ctx.organization.id,
        assetId: null,
        title: finding.title,
        source: finding.source,
      });
      // Guarded in SQL so an existing unscoped finding that already owns the same
      // fingerprint keeps it instead of aborting the transaction.
      await tx.$executeRaw`
        UPDATE "findings" SET "fingerprint" = ${fingerprint}
        WHERE "id" = ${finding.id}
          AND "organizationId" = ${ctx.organization.id}
          AND NOT EXISTS (
            SELECT 1 FROM "findings" AS other
            WHERE other."organizationId" = ${ctx.organization.id}
              AND other."fingerprint" = ${fingerprint}
          )`;
    }

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ASSET_DELETED,
      outcome: 'SUCCESS',
      targetType: 'asset',
      targetId: existing.id,
      summary: `Asset ${existing.name} deleted`,
      metadata: {
        name: existing.name,
        identifier: existing.identifier,
        findingsKept: orphaned.length,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });
}

/** Lightweight option list for form selectors within one tenant. */
export async function listAssetOptions(organizationId: string) {
  return prisma.asset.findMany({
    where: { organizationId, status: { not: 'RETIRED' } },
    select: { id: true, name: true, identifier: true },
    orderBy: { name: 'asc' },
    take: 500,
  });
}
