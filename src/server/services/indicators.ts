import type {
  IndicatorRelation,
  IndicatorSourceKind,
  IndicatorStatus,
  IndicatorType,
  Prisma,
} from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import {
  IndicatorFormatError,
  normalizeIndicator,
  type IndicatorType as DomainIndicatorType,
} from '@/server/domain/indicators';
import { badRequest, conflict, notFound } from '@/server/errors';
import { assertQuotaAvailable } from './quotas';
import { assertIncidentInOrganization, isUniqueConstraintError, paginationMeta } from './shared';

/**
 * Indicators of compromise.
 *
 * Two properties are load-bearing:
 *
 * 1. A value is stored once per tenant per type. Importing the same feed twice
 *    must not create a second row, because a duplicate splits the observation
 *    history and makes "when did we first see this" unanswerable. The unique
 *    constraint does the deduplication; the service decides whether a repeat is
 *    an error (manual create) or a refresh (import).
 * 2. A link carries a relation. `OBSERVED` says the indicator was seen in
 *    telemetry attached to that record; `REFERENCED` says the record merely cites
 *    it. Collapsing the two would let a citation read as a sighting, which is how
 *    an investigation ends up chasing a value that never appeared.
 */

export interface IndicatorListQuery {
  search?: string | null;
  type?: IndicatorType;
  status?: IndicatorStatus;
  /** Only indicators whose expiry has passed but which are still ACTIVE. */
  expiredOnly?: boolean;
  page: number;
  pageSize: number;
  sort: 'lastSeenAt' | 'firstSeenAt' | 'createdAt' | 'confidence';
  direction: 'asc' | 'desc';
}

const INDICATOR_SELECT = {
  id: true,
  type: true,
  value: true,
  displayValue: true,
  status: true,
  confidence: true,
  sourceKind: true,
  sourceName: true,
  sourceUrl: true,
  sourceRef: true,
  firstSeenAt: true,
  lastSeenAt: true,
  expiresAt: true,
  note: true,
  createdAt: true,
  updatedAt: true,
  createdBy: { select: { id: true, name: true, email: true } },
  _count: { select: { links: true } },
} satisfies Prisma.IndicatorSelect;

export async function listIndicators(organizationId: string, query: IndicatorListQuery) {
  const where: Prisma.IndicatorWhereInput = {
    organizationId,
    ...(query.type ? { type: query.type } : {}),
    ...(query.status ? { status: query.status } : {}),
    ...(query.expiredOnly ? { status: 'ACTIVE', expiresAt: { lt: new Date() } } : {}),
    ...(query.search
      ? {
          OR: [
            { value: { contains: query.search, mode: 'insensitive' } },
            { displayValue: { contains: query.search, mode: 'insensitive' } },
            { sourceName: { contains: query.search, mode: 'insensitive' } },
            { note: { contains: query.search, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [rows, total] = await prisma.$transaction([
    prisma.indicator.findMany({
      where,
      select: INDICATOR_SELECT,
      orderBy: { [query.sort]: query.direction },
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
    prisma.indicator.count({ where }),
  ]);

  return {
    items: rows.map((row) => ({ ...row, linkCount: row._count.links, _count: undefined })),
    ...paginationMeta(query.page, query.pageSize, total),
  };
}

export interface IndicatorDetail {
  indicator: Prisma.IndicatorGetPayload<{ select: typeof INDICATOR_SELECT }> & {
    /** Number of investigation records that cite this indicator. */
    linkCount: number;
    links: Array<{
      id: string;
      relation: IndicatorRelation;
      note: string | null;
      createdAt: Date;
      createdBy: { id: string; name: string };
      finding: { id: string; title: string; status: string } | null;
      incident: { id: string; title: string; status: string } | null;
    }>;
  };
}

export async function getIndicatorDetail(
  ctx: TenantContext,
  indicatorId: string,
): Promise<IndicatorDetail> {
  const indicator = await prisma.indicator.findFirst({
    where: { id: indicatorId, organizationId: ctx.organization.id },
    select: {
      ...INDICATOR_SELECT,
      links: {
        select: {
          id: true,
          relation: true,
          note: true,
          createdAt: true,
          createdBy: { select: { id: true, name: true } },
          finding: { select: { id: true, title: true, status: true } },
          incident: { select: { id: true, title: true, status: true } },
        },
        orderBy: { createdAt: 'desc' },
      },
    },
  });

  if (!indicator) {
    throw notFound('Indicator not found.');
  }

  const { _count, ...rest } = indicator;
  return {
    indicator: { ...rest, linkCount: _count.links, _count: undefined },
  } as unknown as IndicatorDetail;
}

export interface IndicatorInput {
  type?: DomainIndicatorType | undefined;
  value: string;
  confidence?: number | undefined;
  sourceName: string;
  sourceUrl?: string | null | undefined;
  sourceRef?: string | null | undefined;
  firstSeenAt?: Date | undefined;
  lastSeenAt?: Date | undefined;
  expiresAt?: Date | null | undefined;
  note?: string | null | undefined;
  sourceKind?: IndicatorSourceKind | undefined;
}

/**
 * Normalises and validates, converting the domain error into a 400 so the caller
 * gets "that is not a domain" rather than a stack trace.
 */
function prepare(input: IndicatorInput) {
  try {
    const normalized = normalizeIndicator({ type: input.type, value: input.value });
    const firstSeenAt = input.firstSeenAt ?? new Date();
    const lastSeenAt = input.lastSeenAt ?? firstSeenAt;
    if (lastSeenAt.getTime() < firstSeenAt.getTime()) {
      throw badRequest('lastSeenAt cannot be earlier than firstSeenAt.');
    }
    if (input.expiresAt && input.expiresAt.getTime() <= lastSeenAt.getTime()) {
      throw badRequest(
        'expiresAt must be later than lastSeenAt, or the indicator would be born expired.',
      );
    }
    return { normalized, firstSeenAt, lastSeenAt };
  } catch (error) {
    if (error instanceof IndicatorFormatError) {
      throw badRequest(error.message);
    }
    throw error;
  }
}

export async function createIndicator(ctx: TenantContext, input: IndicatorInput) {
  const { normalized, firstSeenAt, lastSeenAt } = prepare(input);

  return prisma.$transaction(async (tx) => {
    await assertQuotaAvailable(tx, {
      organizationId: ctx.organization.id,
      tier: ctx.organization.tier,
      resource: 'indicators',
    });

    if (input.sourceUrl) {
      assertHttpUrl(input.sourceUrl);
    }

    let indicator;
    try {
      indicator = await tx.indicator.create({
        data: {
          organizationId: ctx.organization.id,
          type: normalized.type as IndicatorType,
          value: normalized.value,
          displayValue: normalized.displayValue,
          confidence: input.confidence ?? 50,
          sourceKind: input.sourceKind ?? 'MANUAL',
          sourceName: input.sourceName,
          sourceUrl: input.sourceUrl ?? null,
          sourceRef: input.sourceRef ?? null,
          firstSeenAt,
          lastSeenAt,
          expiresAt: input.expiresAt ?? null,
          note: input.note ?? null,
          createdById: ctx.user.id,
        },
        select: INDICATOR_SELECT,
      });
    } catch (error) {
      if (isUniqueConstraintError(error)) {
        // Deliberately a conflict, not a silent merge: a manual create that
        // collides means the analyst should see the existing record and decide
        // whether to update its provenance rather than overwrite it blindly.
        throw conflict(
          `That ${normalized.type.toLowerCase()} is already recorded for this organization.`,
        );
      }
      throw error;
    }

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.INDICATOR_CREATED,
      outcome: 'SUCCESS',
      targetType: 'indicator',
      targetId: indicator.id,
      summary: `Recorded ${normalized.type} indicator`,
      // The value is not a secret, but it is untrusted input, so it goes in as
      // data rather than being interpolated into the summary.
      metadata: { type: normalized.type, sourceName: input.sourceName },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return indicator;
  });
}

export interface ImportResult {
  created: number;
  refreshed: number;
  rejected: Array<{ index: number; value: string; reason: string }>;
}

export interface ImportInput {
  sourceName: string;
  sourceKind?: IndicatorSourceKind | undefined;
  sourceUrl?: string | null | undefined;
  indicators: Array<{ type?: DomainIndicatorType | undefined; value: string }>;
}

/**
 * Bulk import. Invalid rows are rejected individually and reported, because a
 * feed with one malformed line should still import the other 999; aborting the
 * batch would make the operator clean the feed by hand before every import.
 *
 * A value that already exists is *refreshed*: lastSeenAt moves forward and the
 * source that reported it most recently becomes the recorded source, while
 * firstSeenAt is preserved. That is the only interpretation that keeps "when did
 * we first see this" honest across repeated imports.
 */
export async function importIndicators(
  ctx: TenantContext,
  input: ImportInput,
): Promise<ImportResult> {
  if (input.indicators.length === 0) {
    throw badRequest('No indicators were supplied.');
  }
  if (input.sourceUrl) {
    assertHttpUrl(input.sourceUrl);
  }

  const now = new Date();
  const prepared: Array<{
    index: number;
    type: IndicatorType;
    value: string;
    displayValue: string | null;
  }> = [];
  const rejected: ImportResult['rejected'] = [];
  const seenInBatch = new Set<string>();

  for (const [index, entry] of input.indicators.entries()) {
    try {
      const normalized = normalizeIndicator({ type: entry.type, value: entry.value });
      const key = `${normalized.type}:${normalized.value}`;
      // A feed that repeats a value within one file must not be reported as
      // "refreshed" by its own earlier line.
      if (seenInBatch.has(key)) {
        continue;
      }
      seenInBatch.add(key);
      prepared.push({
        index,
        type: normalized.type as IndicatorType,
        value: normalized.value,
        displayValue: normalized.displayValue,
      });
    } catch (error) {
      rejected.push({
        index,
        value: entry.value,
        reason: error instanceof IndicatorFormatError ? error.message : 'Invalid indicator.',
      });
    }
  }

  if (prepared.length === 0) {
    return { created: 0, refreshed: 0, rejected };
  }

  const result = await prisma.$transaction(async (tx) => {
    await assertQuotaAvailable(tx, {
      organizationId: ctx.organization.id,
      tier: ctx.organization.tier,
      resource: 'indicators',
      // Quota counts rows, and an import may create many at once; a single
      // "one more row" check would let a large feed jump the limit entirely.
      units: prepared.length,
    });

    // `createMany` with `skipDuplicates` cannot report which rows existed, so the
    // existing set is read first. The read and the writes share the transaction,
    // and the unique constraint is the final arbiter if another import runs
    // concurrently.
    const existing = await tx.indicator.findMany({
      where: {
        organizationId: ctx.organization.id,
        OR: prepared.map((entry) => ({ type: entry.type, value: entry.value })),
      },
      select: { id: true, type: true, value: true },
    });
    const existingByKey = new Map(existing.map((row) => [`${row.type}:${row.value}`, row.id]));

    const toCreate = prepared.filter((entry) => !existingByKey.has(`${entry.type}:${entry.value}`));
    const toRefresh = prepared.filter((entry) => existingByKey.has(`${entry.type}:${entry.value}`));

    if (toCreate.length > 0) {
      await tx.indicator.createMany({
        data: toCreate.map((entry) => ({
          organizationId: ctx.organization.id,
          type: entry.type,
          value: entry.value,
          displayValue: entry.displayValue,
          sourceKind: input.sourceKind ?? 'IMPORT',
          sourceName: input.sourceName,
          sourceUrl: input.sourceUrl ?? null,
          firstSeenAt: now,
          lastSeenAt: now,
          createdById: ctx.user.id,
        })),
        skipDuplicates: true,
      });
    }

    if (toRefresh.length > 0) {
      // One statement per existing row: lastSeenAt is per-value and a bulk update
      // cannot carry a different timestamp per row without a temporary table.
      await Promise.all(
        toRefresh.map((entry) =>
          tx.indicator.update({
            where: { id: existingByKey.get(`${entry.type}:${entry.value}`) as string },
            data: {
              lastSeenAt: now,
              sourceName: input.sourceName,
              sourceUrl: input.sourceUrl ?? null,
              sourceKind: input.sourceKind ?? 'IMPORT',
              // An expired indicator that reappears is active again: the
              // observation is evidence the value is back in play.
              status: 'ACTIVE',
            },
          }),
        ),
      );
    }

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.INDICATOR_IMPORTED,
      outcome: 'SUCCESS',
      targetType: 'indicator',
      summary: `Imported indicator feed from ${input.sourceName}`,
      metadata: {
        sourceName: input.sourceName,
        created: toCreate.length,
        refreshed: toRefresh.length,
        rejected: rejected.length,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return { created: toCreate.length, refreshed: toRefresh.length };
  });

  return { ...result, rejected };
}

export interface IndicatorUpdateInput {
  status?: IndicatorStatus | undefined;
  confidence?: number | undefined;
  expiresAt?: Date | null | undefined;
  note?: string | null | undefined;
  lastSeenAt?: Date | undefined;
}

export async function updateIndicator(
  ctx: TenantContext,
  indicatorId: string,
  input: IndicatorUpdateInput,
) {
  return prisma.$transaction(async (tx) => {
    const existing = await tx.indicator.findFirst({
      where: { id: indicatorId, organizationId: ctx.organization.id },
      select: { id: true, lastSeenAt: true, firstSeenAt: true, status: true },
    });
    if (!existing) {
      throw notFound('Indicator not found.');
    }
    if (input.lastSeenAt && input.lastSeenAt.getTime() < existing.firstSeenAt.getTime()) {
      throw badRequest('lastSeenAt cannot be earlier than firstSeenAt.');
    }
    if (input.expiresAt) {
      const lastSeen = input.lastSeenAt ?? existing.lastSeenAt;
      if (input.expiresAt.getTime() <= lastSeen.getTime()) {
        throw badRequest('expiresAt must be later than lastSeenAt.');
      }
    }

    const updated = await tx.indicator.update({
      where: { id: existing.id },
      data: {
        ...(input.status ? { status: input.status } : {}),
        ...(input.confidence !== undefined ? { confidence: input.confidence } : {}),
        ...(input.expiresAt !== undefined ? { expiresAt: input.expiresAt } : {}),
        ...(input.note !== undefined ? { note: input.note } : {}),
        ...(input.lastSeenAt ? { lastSeenAt: input.lastSeenAt } : {}),
      },
      select: INDICATOR_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.INDICATOR_UPDATED,
      outcome: 'SUCCESS',
      targetType: 'indicator',
      targetId: updated.id,
      summary:
        input.status && input.status !== existing.status
          ? `Indicator marked ${input.status.toLowerCase().replace('_', ' ')}`
          : 'Indicator updated',
      metadata: {
        ...(input.status ? { status: input.status } : {}),
        ...(input.confidence !== undefined ? { confidence: input.confidence } : {}),
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return updated;
  });
}

export async function deleteIndicator(ctx: TenantContext, indicatorId: string) {
  return prisma.$transaction(async (tx) => {
    const existing = await tx.indicator.findFirst({
      where: { id: indicatorId, organizationId: ctx.organization.id },
      select: { id: true, type: true, links: { select: { id: true } } },
    });
    if (!existing) {
      throw notFound('Indicator not found.');
    }

    // Links cascade, which is intended: a link has no meaning without its
    // indicator. The count is recorded so the audit trail shows what was lost.
    await tx.indicator.delete({ where: { id: existing.id } });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.INDICATOR_DELETED,
      outcome: 'SUCCESS',
      targetType: 'indicator',
      targetId: existing.id,
      summary: 'Indicator deleted',
      metadata: { type: existing.type, removedLinks: existing.links.length },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });
}

export interface LinkInput {
  findingId?: string | undefined;
  incidentId?: string | undefined;
  relation?: IndicatorRelation | undefined;
  note?: string | null | undefined;
}

/**
 * Links an indicator to exactly one investigation record. The target is checked
 * against the tenant before the link is written, so a caller cannot attach an
 * indicator to another tenant's finding by guessing its id.
 */
export async function linkIndicator(ctx: TenantContext, indicatorId: string, input: LinkInput) {
  const targets = [input.findingId, input.incidentId].filter(Boolean);
  if (targets.length !== 1) {
    throw badRequest('Supply exactly one of findingId or incidentId.');
  }

  return prisma.$transaction(async (tx) => {
    const indicator = await tx.indicator.findFirst({
      where: { id: indicatorId, organizationId: ctx.organization.id },
      select: { id: true, type: true },
    });
    if (!indicator) {
      throw notFound('Indicator not found.');
    }

    if (input.findingId) {
      const finding = await tx.finding.findFirst({
        where: { id: input.findingId, organizationId: ctx.organization.id },
        select: { id: true },
      });
      if (!finding) {
        throw notFound('Finding not found in this organization.');
      }
    }
    await assertIncidentInOrganization(ctx.organization.id, input.incidentId);

    let link;
    try {
      link = await tx.indicatorLink.create({
        data: {
          organizationId: ctx.organization.id,
          indicatorId: indicator.id,
          findingId: input.findingId ?? null,
          incidentId: input.incidentId ?? null,
          relation: input.relation ?? 'REFERENCED',
          note: input.note ?? null,
          createdById: ctx.user.id,
        },
        select: {
          id: true,
          relation: true,
          note: true,
          createdAt: true,
          findingId: true,
          incidentId: true,
        },
      });
    } catch (error) {
      if (isUniqueConstraintError(error)) {
        throw conflict('That indicator is already linked to this record.');
      }
      throw error;
    }

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.INDICATOR_LINKED,
      outcome: 'SUCCESS',
      targetType: 'indicator',
      targetId: indicator.id,
      summary: `Indicator ${link.relation === 'OBSERVED' ? 'observed in' : 'referenced by'} ${input.findingId ? 'a finding' : 'an incident'}`,
      metadata: {
        relation: link.relation,
        findingId: input.findingId ?? null,
        incidentId: input.incidentId ?? null,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return link;
  });
}

export async function unlinkIndicator(ctx: TenantContext, indicatorId: string, linkId: string) {
  return prisma.$transaction(async (tx) => {
    const link = await tx.indicatorLink.findFirst({
      where: { id: linkId, indicatorId, organizationId: ctx.organization.id },
      select: { id: true, indicatorId: true, relation: true },
    });
    if (!link) {
      throw notFound('Indicator link not found.');
    }
    await tx.indicatorLink.delete({ where: { id: link.id } });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.INDICATOR_UNLINKED,
      outcome: 'SUCCESS',
      targetType: 'indicator',
      targetId: link.indicatorId,
      summary: 'Indicator link removed',
      metadata: { linkId: link.id },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });
}

/**
 * Indicators attached to one finding or incident, for the investigation view.
 * Kept here rather than in the findings service so the indicator projection
 * stays in one place.
 */
export async function listIndicatorsForTarget(
  organizationId: string,
  target: { findingId: string } | { incidentId: string },
) {
  const links = await prisma.indicatorLink.findMany({
    where: {
      organizationId,
      ...('findingId' in target
        ? { findingId: target.findingId }
        : { incidentId: target.incidentId }),
    },
    select: {
      id: true,
      relation: true,
      note: true,
      createdAt: true,
      indicator: { select: INDICATOR_SELECT },
    },
    orderBy: [{ relation: 'asc' }, { createdAt: 'desc' }],
  });

  // The indicator and the link both have a `note` field, and they mean different
  // things: the link note is why this value is attached to this record, the
  // indicator note is what is known about the value itself. Spreading one over
  // the other would silently drop the analyst's reasoning, so they stay separate.
  return links.map((link) => ({
    linkId: link.id,
    relation: link.relation,
    linkNote: link.note,
    linkedAt: link.createdAt,
    indicator: link.indicator,
  }));
}

/** Only http(s) sources are stored, so a `javascript:` or `file:` URL cannot be
 * rendered as a link later. */
function assertHttpUrl(value: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw badRequest('sourceUrl must be an absolute URL.');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw badRequest('sourceUrl must use http or https.');
  }
}
