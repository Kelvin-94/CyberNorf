import type {
  FindingSeverity,
  FindingSource,
  FindingStatus,
  Prisma,
} from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import { canTransitionFinding } from '@/server/domain/transitions';
import { conflict, notFound } from '@/server/errors';
import {
  assertActiveMember,
  assertAssetInOrganization,
  assertIncidentInOrganization,
  findingFingerprint,
  isUniqueConstraintError,
  paginationMeta,
  riskFields,
} from './shared';

export interface FindingListQuery {
  search?: string | null;
  status?: FindingStatus;
  severity?: FindingSeverity;
  assetId?: string;
  incidentId?: string;
  assignedToId?: string;
  /** Only findings past their remediation deadline and still open. */
  overdue?: boolean;
  page: number;
  pageSize: number;
  sort:
    | 'createdAt'
    | 'updatedAt'
    | 'severity'
    | 'status'
    | 'title'
    | 'lastSeenAt'
    | 'riskScore'
    | 'dueAt';
  direction: 'asc' | 'desc';
}

const CLOSED_STATUSES: FindingStatus[] = ['RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE'];
const OPEN_FINDING_STATUSES: FindingStatus[] = ['OPEN', 'TRIAGED', 'IN_PROGRESS'];

const FINDING_SUMMARY_SELECT = {
  id: true,
  title: true,
  severity: true,
  status: true,
  source: true,
  cveId: true,
  cvssScore: true,
  riskScore: true,
  dueAt: true,
  firstSeenAt: true,
  lastSeenAt: true,
  resolvedAt: true,
  createdAt: true,
  updatedAt: true,
  asset: { select: { id: true, name: true, identifier: true } },
  assignedTo: { select: { id: true, name: true, email: true } },
} satisfies Prisma.FindingSelect;

type FindingSummaryRow = Prisma.FindingGetPayload<{ select: typeof FINDING_SUMMARY_SELECT }>;

function serializeFinding<T extends { cvssScore: Prisma.Decimal | null }>(finding: T) {
  return { ...finding, cvssScore: finding.cvssScore === null ? null : Number(finding.cvssScore) };
}

export async function listFindings(organizationId: string, query: FindingListQuery) {
  // "Overdue" means open work past its deadline. A closed status combined with
  // it can only ever be empty, so the filter short-circuits instead of returning
  // resolved findings just because they once missed their deadline.
  const statusFilter: Prisma.FindingWhereInput['status'] = query.overdue
    ? query.status && CLOSED_STATUSES.includes(query.status)
      ? { in: [] }
      : (query.status ?? { in: OPEN_FINDING_STATUSES })
    : query.status;

  const where: Prisma.FindingWhereInput = {
    organizationId,
    ...(statusFilter ? { status: statusFilter } : {}),
    ...(query.severity ? { severity: query.severity } : {}),
    ...(query.assetId ? { assetId: query.assetId } : {}),
    ...(query.incidentId ? { incidentId: query.incidentId } : {}),
    ...(query.assignedToId ? { assignedToId: query.assignedToId } : {}),
    ...(query.overdue ? { dueAt: { lt: new Date() } } : {}),
    ...(query.search
      ? {
          OR: [
            { title: { contains: query.search, mode: 'insensitive' } },
            { description: { contains: query.search, mode: 'insensitive' } },
            { cveId: { contains: query.search, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [rows, total] = await prisma.$transaction([
    prisma.finding.findMany({
      where,
      select: FINDING_SUMMARY_SELECT,
      orderBy: { [query.sort]: query.direction },
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
    prisma.finding.count({ where }),
  ]);

  return {
    items: rows.map(serializeFinding),
    ...paginationMeta(query.page, query.pageSize, total),
  };
}

export async function getFindingDetail(ctx: TenantContext, findingId: string) {
  const finding = await prisma.finding.findFirst({
    where: { id: findingId, organizationId: ctx.organization.id },
    select: {
      ...FINDING_SUMMARY_SELECT,
      organizationId: true,
      description: true,
      remediation: true,
      fingerprint: true,
      createdBy: { select: { id: true, name: true, email: true } },
      // Agent-raised findings keep both provenances: the operator who registered
      // the agent and the agent itself.
      agent: { select: { id: true, name: true } },
      incident: { select: { id: true, title: true, status: true } },
      asset: { select: { id: true, name: true, identifier: true, criticality: true } },
    },
  });

  if (!finding) {
    throw notFound('Finding not found.');
  }

  // Status history is derived from the append-only audit trail.
  const history = await prisma.auditEvent.findMany({
    where: {
      organizationId: ctx.organization.id,
      targetType: 'finding',
      targetId: finding.id,
    },
    select: {
      id: true,
      action: true,
      actorType: true,
      outcome: true,
      summary: true,
      metadata: true,
      createdAt: true,
      actor: { select: { name: true } },
    },
    // Sequence is monotonic per organization, so events written in the same
    // millisecond still come back in the order they were appended.
    orderBy: { sequence: 'asc' },
    take: 200,
  });

  return { ...serializeFinding(finding), history };
}

export async function createFinding(
  ctx: TenantContext,
  input: {
    title: string;
    description?: string | null;
    severity: FindingSeverity;
    assetId?: string | null;
    assignedToId?: string | null;
    incidentId?: string | null;
    cveId?: string | null;
    cvssScore?: number | null;
    remediation?: string | null;
    firstSeenAt?: Date;
  },
) {
  const assetId = input.assetId ?? null;
  const assignedToId = input.assignedToId ?? null;
  const incidentId = input.incidentId ?? null;

  await assertAssetInOrganization(ctx.organization.id, assetId);
  await assertActiveMember(ctx.organization.id, assignedToId);
  await assertIncidentInOrganization(ctx.organization.id, incidentId);

  const source: FindingSource = 'MANUAL';
  const fingerprint = findingFingerprint({
    organizationId: ctx.organization.id,
    assetId,
    title: input.title,
    source,
  });

  // The asset's criticality feeds the risk score, so it is loaded once here
  // rather than in a second assertion query. A missing asset still fails closed.
  const asset = assetId
    ? await prisma.asset.findFirst({
        where: { id: assetId, organizationId: ctx.organization.id },
        select: { criticality: true },
      })
    : null;
  if (assetId && !asset) {
    throw notFound('Asset not found in this organization.');
  }

  const firstSeenAt = input.firstSeenAt ?? new Date();
  const risk = riskFields({
    severity: input.severity,
    cvssScore: input.cvssScore ?? null,
    assetCriticality: asset?.criticality ?? null,
    firstSeenAt,
  });

  try {
    return await prisma.$transaction(async (tx) => {
      const finding = await tx.finding.create({
        data: {
          organizationId: ctx.organization.id,
          createdById: ctx.user.id,
          title: input.title,
          description: input.description ?? null,
          severity: input.severity,
          source,
          fingerprint,
          assetId,
          assignedToId,
          incidentId,
          cveId: input.cveId ?? null,
          cvssScore: input.cvssScore ?? null,
          remediation: input.remediation ?? null,
          firstSeenAt,
          riskScore: risk.riskScore,
          dueAt: risk.dueAt,
        },
        select: FINDING_SUMMARY_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.FINDING_CREATED,
        outcome: 'SUCCESS',
        targetType: 'finding',
        targetId: finding.id,
        summary: `Finding "${finding.title}" created`,
        metadata: { severity: finding.severity, assetId, source },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return serializeFinding(finding);
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict(
        'A finding with the same title and asset already exists in this organization.',
      );
    }
    throw error;
  }
}

export async function updateFinding(
  ctx: TenantContext,
  findingId: string,
  input: Partial<{
    title: string;
    description: string | null;
    severity: FindingSeverity;
    assetId: string | null;
    assignedToId: string | null;
    incidentId: string | null;
    cveId: string | null;
    cvssScore: number | null;
    remediation: string | null;
  }>,
) {
  const existing = await prisma.finding.findFirst({
    where: { id: findingId, organizationId: ctx.organization.id },
    select: {
      id: true,
      title: true,
      severity: true,
      source: true,
      fingerprint: true,
      assetId: true,
      assignedToId: true,
      incidentId: true,
      cvssScore: true,
      firstSeenAt: true,
    },
  });

  if (!existing) {
    throw notFound('Finding not found.');
  }

  if (input.assetId !== undefined) {
    await assertAssetInOrganization(ctx.organization.id, input.assetId);
  }
  if (input.assignedToId !== undefined) {
    await assertActiveMember(ctx.organization.id, input.assignedToId);
  }
  if (input.incidentId !== undefined) {
    await assertIncidentInOrganization(ctx.organization.id, input.incidentId);
  }

  // The fingerprint is the dedupe key, so it has to follow the fields it is
  // derived from; otherwise re-imports stop matching this record.
  const nextTitle = input.title ?? existing.title;
  const nextAssetId = input.assetId !== undefined ? input.assetId : existing.assetId;
  const fingerprint =
    nextTitle === existing.title && nextAssetId === existing.assetId
      ? existing.fingerprint
      : findingFingerprint({
          organizationId: ctx.organization.id,
          assetId: nextAssetId,
          title: nextTitle,
          source: existing.source,
        });

  // The risk score is derived from three inputs. Recompute it only when one of
  // them changes, and always from firstSeenAt so the deadline does not drift
  // forward each time a finding is edited.
  const nextSeverity = input.severity ?? existing.severity;
  const nextCvss =
    input.cvssScore !== undefined
      ? input.cvssScore
      : existing.cvssScore === null
        ? null
        : Number(existing.cvssScore);
  const riskInputsChanged =
    nextSeverity !== existing.severity ||
    nextCvss !== (existing.cvssScore === null ? null : Number(existing.cvssScore)) ||
    nextAssetId !== existing.assetId;

  let derived: { riskScore: number; dueAt: Date } | null = null;
  if (riskInputsChanged) {
    const asset = nextAssetId
      ? await prisma.asset.findFirst({
          where: { id: nextAssetId, organizationId: ctx.organization.id },
          select: { criticality: true },
        })
      : null;
    derived = riskFields({
      severity: nextSeverity,
      cvssScore: nextCvss,
      assetCriticality: asset?.criticality ?? null,
      firstSeenAt: existing.firstSeenAt,
    });
  }

  try {
    return await prisma.$transaction(async (tx) => {
      const finding = await tx.finding.update({
        where: { id: existing.id },
        data: { ...input, fingerprint, ...(derived ?? {}) },
        select: FINDING_SUMMARY_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.FINDING_UPDATED,
        outcome: 'SUCCESS',
        targetType: 'finding',
        targetId: finding.id,
        summary: `Finding "${finding.title}" updated`,
        metadata: {
          changedFields: Object.keys(input),
          // The snapshot is written to audit metadata, so it has to be plain
          // JSON: Prisma's Decimal is a class instance and cannot be stored.
          before: {
            ...existing,
            cvssScore: existing.cvssScore === null ? null : Number(existing.cvssScore),
          },
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return serializeFinding(finding);
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict(
        'A finding with the same title and asset already exists in this organization.',
      );
    }
    throw error;
  }
}

export async function changeFindingStatus(
  ctx: TenantContext,
  findingId: string,
  nextStatus: FindingStatus,
  note?: string | null,
) {
  const existing = await prisma.finding.findFirst({
    where: { id: findingId, organizationId: ctx.organization.id },
    select: { id: true, title: true, status: true },
  });

  if (!existing) {
    throw notFound('Finding not found.');
  }

  if (existing.status === nextStatus) {
    return { id: existing.id, status: existing.status, changed: false };
  }

  if (!canTransitionFinding(existing.status, nextStatus)) {
    throw conflict(`A finding cannot move from ${existing.status} to ${nextStatus}.`);
  }

  return prisma.$transaction(async (tx) => {
    const resolvedAt = nextStatus === 'RESOLVED' ? new Date() : null;
    const finding = await tx.finding.update({
      where: { id: existing.id },
      data: { status: nextStatus, resolvedAt },
      select: { id: true, title: true, status: true, resolvedAt: true },
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.FINDING_STATUS_CHANGED,
      outcome: 'SUCCESS',
      targetType: 'finding',
      targetId: finding.id,
      summary: `Finding "${finding.title}" moved from ${existing.status} to ${nextStatus}`,
      metadata: { from: existing.status, to: nextStatus, note: note ?? null },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return { ...finding, changed: true };
  });
}

export async function deleteFinding(ctx: TenantContext, findingId: string): Promise<void> {
  const existing = await prisma.finding.findFirst({
    where: { id: findingId, organizationId: ctx.organization.id },
    select: { id: true, title: true, status: true },
  });

  if (!existing) {
    throw notFound('Finding not found.');
  }

  await prisma.$transaction(async (tx) => {
    await tx.finding.delete({ where: { id: existing.id } });
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.FINDING_DELETED,
      outcome: 'SUCCESS',
      targetType: 'finding',
      targetId: existing.id,
      summary: `Finding "${existing.title}" deleted`,
      metadata: { title: existing.title, statusAtDeletion: existing.status },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });
}

export interface ImportFindingItem {
  title: string;
  description?: string | null;
  severity: FindingSeverity;
  assetId?: string;
  assetIdentifier?: string;
  cveId?: string;
  cvssScore?: number;
  remediation?: string | null;
}

export type ImportSkipReason =
  'asset_not_found' | 'asset_identifier_not_found' | 'duplicate_in_payload';

export interface ImportResult {
  created: number;
  updated: number;
  skipped: Array<{ index: number; title: string; reason: ImportSkipReason }>;
}

interface PreparedImportItem {
  index: number;
  assetId: string | null;
  fingerprint: string;
  item: ImportFindingItem;
}

/**
 * Imports normalized findings from a JSON document. Items are deduplicated by
 * fingerprint within the organization: existing findings have their last-seen
 * timestamp refreshed, new items are inserted. Unknown asset identifiers are
 * reported per item rather than failing the whole import. Concurrent batches
 * that race on the same fingerprint are replayed once instead of failing.
 */
export async function importFindings(
  ctx: TenantContext,
  items: ImportFindingItem[],
): Promise<ImportResult> {
  // Referenced assets are resolved with two bounded lookups instead of loading
  // the whole inventory, so imports stay correct for large inventories.
  const identifiers = [...new Set(items.flatMap((item) => item.assetIdentifier ?? []))];
  const assetIds = [...new Set(items.flatMap((item) => item.assetId ?? []))];

  const [assetsByIdentifier, assetsById] = await Promise.all([
    identifiers.length === 0
      ? Promise.resolve<Array<{ id: string; identifier: string }>>([])
      : prisma.asset.findMany({
          where: { organizationId: ctx.organization.id, identifier: { in: identifiers } },
          select: { id: true, identifier: true },
        }),
    assetIds.length === 0
      ? Promise.resolve<Array<{ id: string }>>([])
      : prisma.asset.findMany({
          where: { organizationId: ctx.organization.id, id: { in: assetIds } },
          select: { id: true },
        }),
  ]);

  const knownAssetIds = new Set(assetsById.map((asset) => asset.id));
  const identifierToId = new Map(assetsByIdentifier.map((asset) => [asset.identifier, asset.id]));

  const skipped: ImportResult['skipped'] = [];
  const prepared: PreparedImportItem[] = [];
  const seenFingerprints = new Set<string>();

  items.forEach((item, index) => {
    let assetId: string | null = null;
    if (item.assetId) {
      if (!knownAssetIds.has(item.assetId)) {
        skipped.push({ index, title: item.title, reason: 'asset_not_found' });
        return;
      }
      assetId = item.assetId;
    } else if (item.assetIdentifier) {
      const resolved = identifierToId.get(item.assetIdentifier);
      if (!resolved) {
        skipped.push({ index, title: item.title, reason: 'asset_identifier_not_found' });
        return;
      }
      assetId = resolved;
    }

    const fingerprint = findingFingerprint({
      organizationId: ctx.organization.id,
      assetId,
      title: item.title,
      source: 'IMPORT',
    });

    // Repeating an item inside one payload would violate the fingerprint unique
    // index when the batch is inserted, so the first occurrence wins.
    if (seenFingerprints.has(fingerprint)) {
      skipped.push({ index, title: item.title, reason: 'duplicate_in_payload' });
      return;
    }
    seenFingerprints.add(fingerprint);
    prepared.push({ index, assetId, fingerprint, item });
  });

  if (prepared.length === 0) {
    return { created: 0, updated: 0, skipped };
  }

  try {
    return await applyImport(ctx, prepared, items.length, skipped);
  } catch (error) {
    if (!isUniqueConstraintError(error)) {
      throw error;
    }
    // A concurrent import inserted the same fingerprint between the read and the
    // write. Replaying the batch turns the conflict into a last-seen refresh.
    return applyImport(ctx, prepared, items.length, skipped);
  }
}

async function applyImport(
  ctx: TenantContext,
  prepared: PreparedImportItem[],
  submitted: number,
  skipped: ImportResult['skipped'],
): Promise<ImportResult> {
  return prisma.$transaction(async (tx) => {
    const existing = await tx.finding.findMany({
      where: {
        organizationId: ctx.organization.id,
        fingerprint: { in: prepared.map((entry) => entry.fingerprint) },
      },
      select: { fingerprint: true },
    });
    const existingFingerprints = new Set(existing.map((row) => row.fingerprint));

    const toCreate = prepared.filter((entry) => !existingFingerprints.has(entry.fingerprint));
    const toRefresh = prepared.filter((entry) => existingFingerprints.has(entry.fingerprint));

    let createdFindings: Array<{ id: string; title: string }> = [];
    if (toCreate.length > 0) {
      // Imported findings get the same derived fields as manually created ones.
      // Criticality is resolved from the assets already validated above, in one
      // pass, so a large import does not issue one query per row.
      const assetIdsToLoad = [...new Set(toCreate.flatMap((entry) => entry.assetId ?? []))];
      const criticalityRows =
        assetIdsToLoad.length === 0
          ? []
          : await tx.asset.findMany({
              where: { organizationId: ctx.organization.id, id: { in: assetIdsToLoad } },
              select: { id: true, criticality: true },
            });
      const criticalityById = new Map(criticalityRows.map((row) => [row.id, row.criticality]));
      const importedAt = new Date();

      await tx.finding.createMany({
        data: toCreate.map((entry) => {
          const risk = riskFields({
            severity: entry.item.severity,
            cvssScore: entry.item.cvssScore ?? null,
            assetCriticality: entry.assetId ? (criticalityById.get(entry.assetId) ?? null) : null,
            firstSeenAt: importedAt,
          });
          return {
            organizationId: ctx.organization.id,
            createdById: ctx.user.id,
            title: entry.item.title,
            description: entry.item.description ?? null,
            severity: entry.item.severity,
            status: 'OPEN' as const,
            source: 'IMPORT' as const,
            fingerprint: entry.fingerprint,
            assetId: entry.assetId,
            cveId: entry.item.cveId ?? null,
            cvssScore: entry.item.cvssScore ?? null,
            remediation: entry.item.remediation ?? null,
            riskScore: risk.riskScore,
            dueAt: risk.dueAt,
          };
        }),
      });

      createdFindings = await tx.finding.findMany({
        where: {
          organizationId: ctx.organization.id,
          fingerprint: { in: toCreate.map((entry) => entry.fingerprint) },
        },
        select: { id: true, title: true },
        orderBy: { createdAt: 'asc' },
      });
    }

    if (toRefresh.length > 0) {
      await tx.finding.updateMany({
        where: {
          organizationId: ctx.organization.id,
          fingerprint: { in: toRefresh.map((entry) => entry.fingerprint) },
        },
        data: { lastSeenAt: new Date() },
      });
    }

    // Every imported finding gets its own audit event so the finding detail view
    // can show where the record came from, in addition to the batch summary.
    for (const finding of createdFindings) {
      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.FINDING_IMPORTED,
        outcome: 'SUCCESS',
        targetType: 'finding',
        targetId: finding.id,
        summary: `Imported finding ${finding.title}`,
        metadata: { source: 'IMPORT' },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });
    }

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.FINDING_IMPORTED,
      outcome: 'SUCCESS',
      targetType: 'organization',
      targetId: ctx.organization.id,
      summary: `Imported ${toCreate.length} finding(s); refreshed ${toRefresh.length}`,
      metadata: {
        created: toCreate.length,
        refreshed: toRefresh.length,
        skipped: skipped.length,
        submitted,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return { created: toCreate.length, updated: toRefresh.length, skipped };
  });
}

export interface FindingFormOptions {
  assets: Array<{ id: string; name: string; identifier: string }>;
  members: Array<{ id: string; name: string; email: string }>;
  incidents: Array<{ id: string; title: string }>;
}

export async function listFindingFormOptions(organizationId: string): Promise<FindingFormOptions> {
  const [assets, members, incidents] = await Promise.all([
    prisma.asset.findMany({
      where: { organizationId, status: { not: 'RETIRED' } },
      select: { id: true, name: true, identifier: true },
      orderBy: { name: 'asc' },
      take: 500,
    }),
    prisma.membership.findMany({
      where: { organizationId, status: 'ACTIVE' },
      select: { user: { select: { id: true, name: true, email: true } } },
      orderBy: { user: { name: 'asc' } },
      take: 200,
    }),
    prisma.incident.findMany({
      where: { organizationId, status: { notIn: ['CLOSED'] } },
      select: { id: true, title: true },
      orderBy: { createdAt: 'desc' },
      take: 100,
    }),
  ]);

  return {
    assets,
    members: members.map((membership) => membership.user),
    incidents,
  };
}

export type { FindingSummaryRow };
