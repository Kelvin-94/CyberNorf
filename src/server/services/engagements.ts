import type { EngagementStatus, Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent, recordAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import {
  ScopeFormatError,
  normalizeScopeValue,
  type ScopeEntryKind,
  type ScopeTargetType,
} from '@/server/domain/execution';
import { badRequest, conflict, forbidden, notFound } from '@/server/errors';
import { isUniqueConstraintError, paginationMeta } from './shared';

/**
 * Engagements and the authorization to test.
 *
 * The model exists so that "run this scan" cannot be expressed without first
 * naming a customer, a window, an explicit target list, and a signed
 * authorization with an expiry. Nothing here executes anything; dispatch and
 * execution enforcement live in services/execution.ts.
 *
 * Two invariants are enforced here:
 *
 * 1. An engagement reaches ACTIVE only with at least one inclusion in scope.
 *    Activating an empty engagement would make "no scope" look like "ready".
 * 2. Only one authorization can be APPROVED at a time. Approval takes an
 *    advisory lock on the engagement, because two concurrent approvals would
 *    otherwise both observe "none approved" and both succeed.
 */

export const ENGAGEMENT_TRANSITIONS: Readonly<
  Record<EngagementStatus, readonly EngagementStatus[]>
> = {
  DRAFT: ['ACTIVE', 'CLOSED'],
  ACTIVE: ['PAUSED', 'CLOSED'],
  PAUSED: ['ACTIVE', 'CLOSED'],
  CLOSED: [],
};

const ENGAGEMENT_LOCK_NAMESPACE = 0x454e4747; // "ENGG"

const SUMMARY_INCLUDE = {
  createdBy: { select: { id: true, name: true, email: true } },
  _count: { select: { scopeEntries: true, authorizations: true, jobs: true } },
} satisfies Prisma.EngagementInclude;

const DETAIL_INCLUDE = {
  createdBy: { select: { id: true, name: true, email: true } },
  scopeEntries: {
    orderBy: [{ kind: 'asc' }, { targetType: 'asc' }, { value: 'asc' }],
    select: {
      id: true,
      kind: true,
      targetType: true,
      value: true,
      note: true,
      createdAt: true,
      createdBy: { select: { id: true, name: true, email: true } },
    },
  },
  authorizations: {
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      status: true,
      reference: true,
      conditions: true,
      expiresAt: true,
      decidedAt: true,
      revokedAt: true,
      createdAt: true,
      requestedBy: { select: { id: true, name: true, email: true } },
      decidedBy: { select: { id: true, name: true, email: true } },
      revokedBy: { select: { id: true, name: true, email: true } },
    },
  },
} satisfies Prisma.EngagementInclude;

type EngagementRow = Prisma.EngagementGetPayload<{ include: typeof DETAIL_INCLUDE }>;
type AuthorizationRow = EngagementRow['authorizations'][number];

export interface EngagementListQuery {
  search?: string | undefined;
  status?: EngagementStatus | undefined;
  page: number;
  pageSize: number;
  sort: 'createdAt' | 'endsAt' | 'name';
  direction: 'asc' | 'desc';
}

export interface EngagementSummary {
  id: string;
  name: string;
  description: string | null;
  status: EngagementStatus;
  startsAt: string;
  endsAt: string;
  closedAt: string | null;
  createdAt: string;
  updatedAt: string;
  createdBy: { id: string; name: string; email: string };
  counts: { scopeEntries: number; authorizations: number; jobs: number };
}

export interface EngagementScopeEntryView {
  id: string;
  kind: ScopeEntryKind;
  targetType: ScopeTargetType;
  value: string;
  note: string | null;
  createdAt: string;
  createdBy: { id: string; name: string; email: string };
}

export interface AuthorizationView {
  id: string;
  status: AuthorizationRow['status'];
  /** APPROVED but past `expiresAt` is reported as EXPIRED without rewriting the row. */
  effectiveStatus: 'PENDING' | 'APPROVED' | 'REJECTED' | 'REVOKED' | 'EXPIRED';
  reference: string | null;
  conditions: string | null;
  expiresAt: string;
  decidedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
  requestedBy: { id: string; name: string; email: string };
  decidedBy: { id: string; name: string; email: string } | null;
  revokedBy: { id: string; name: string; email: string } | null;
}

export interface EngagementDetail extends EngagementSummary {
  scopeEntries: EngagementScopeEntryView[];
  authorizations: AuthorizationView[];
}

export function effectiveAuthorizationStatus(
  status: AuthorizationRow['status'],
  expiresAt: Date,
  now: Date,
): AuthorizationView['effectiveStatus'] {
  if (status === 'APPROVED' && expiresAt.getTime() <= now.getTime()) {
    return 'EXPIRED';
  }
  return status;
}

function toSummary(
  row: Prisma.EngagementGetPayload<{ include: typeof SUMMARY_INCLUDE }>,
): EngagementSummary {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    status: row.status,
    startsAt: row.startsAt.toISOString(),
    endsAt: row.endsAt.toISOString(),
    closedAt: row.closedAt?.toISOString() ?? null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    createdBy: row.createdBy,
    counts: {
      scopeEntries: row._count.scopeEntries,
      authorizations: row._count.authorizations,
      jobs: row._count.jobs,
    },
  };
}

function toDetail(row: EngagementRow, now: Date): EngagementDetail {
  const counts = {
    scopeEntries: row.scopeEntries.length,
    authorizations: row.authorizations.length,
    jobs: 0,
  };
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    status: row.status,
    startsAt: row.startsAt.toISOString(),
    endsAt: row.endsAt.toISOString(),
    closedAt: row.closedAt?.toISOString() ?? null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    createdBy: row.createdBy,
    counts,
    scopeEntries: row.scopeEntries.map((entry) => ({
      id: entry.id,
      kind: entry.kind,
      targetType: entry.targetType,
      value: entry.value,
      note: entry.note,
      createdAt: entry.createdAt.toISOString(),
      createdBy: entry.createdBy,
    })),
    authorizations: row.authorizations.map((authorization) => ({
      id: authorization.id,
      status: authorization.status,
      effectiveStatus: effectiveAuthorizationStatus(
        authorization.status,
        authorization.expiresAt,
        now,
      ),
      reference: authorization.reference,
      conditions: authorization.conditions,
      expiresAt: authorization.expiresAt.toISOString(),
      decidedAt: authorization.decidedAt?.toISOString() ?? null,
      revokedAt: authorization.revokedAt?.toISOString() ?? null,
      createdAt: authorization.createdAt.toISOString(),
      requestedBy: authorization.requestedBy,
      decidedBy: authorization.decidedBy,
      revokedBy: authorization.revokedBy,
    })),
  };
}

export async function listEngagements(
  organizationId: string,
  query: EngagementListQuery,
): Promise<{ items: EngagementSummary[]; pagination: ReturnType<typeof paginationMeta> }> {
  const where: Prisma.EngagementWhereInput = {
    organizationId,
    ...(query.status ? { status: query.status } : {}),
    ...(query.search
      ? {
          OR: [
            { name: { contains: query.search, mode: 'insensitive' } },
            { description: { contains: query.search, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [rows, total] = await prisma.$transaction([
    prisma.engagement.findMany({
      where,
      include: SUMMARY_INCLUDE,
      orderBy: { [query.sort]: query.direction },
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
    prisma.engagement.count({ where }),
  ]);

  return {
    items: rows.map(toSummary),
    pagination: paginationMeta(query.page, query.pageSize, total),
  };
}

export async function getEngagement(
  organizationId: string,
  engagementId: string,
  now = new Date(),
): Promise<EngagementDetail> {
  const row = await prisma.engagement.findFirst({
    where: { id: engagementId, organizationId },
    include: DETAIL_INCLUDE,
  });
  if (!row) {
    throw notFound('The engagement was not found.');
  }
  const jobs = await prisma.executionJob.count({ where: { engagementId, organizationId } });
  const detail = toDetail(row, now);
  detail.counts.jobs = jobs;
  return detail;
}

export async function createEngagement(
  ctx: TenantContext,
  input: { name: string; description?: string | null; startsAt: Date; endsAt: Date },
): Promise<EngagementDetail> {
  if (input.endsAt.getTime() <= input.startsAt.getTime()) {
    throw badRequest('The engagement must end after it starts.');
  }

  try {
    const engagement = await prisma.$transaction(async (tx) => {
      const created = await tx.engagement.create({
        data: {
          organizationId: ctx.organization.id,
          name: input.name,
          description: input.description ?? null,
          startsAt: input.startsAt,
          endsAt: input.endsAt,
          createdById: ctx.user.id,
        },
      });
      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.ENGAGEMENT_CREATED,
        outcome: 'SUCCESS',
        targetType: 'engagement',
        targetId: created.id,
        summary: `Created engagement "${created.name}"`,
        metadata: {
          startsAt: input.startsAt.toISOString(),
          endsAt: input.endsAt.toISOString(),
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });
      return created;
    });

    return getEngagement(ctx.organization.id, engagement.id);
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict('An engagement with that name already exists.');
    }
    throw error;
  }
}

export async function updateEngagement(
  ctx: TenantContext,
  engagementId: string,
  input: {
    name?: string;
    description?: string | null;
    status?: EngagementStatus;
    startsAt?: Date;
    endsAt?: Date;
  },
): Promise<EngagementDetail> {
  const existing = await prisma.engagement.findFirst({
    where: { id: engagementId, organizationId: ctx.organization.id },
    include: { _count: { select: { scopeEntries: true } } },
  });
  if (!existing) {
    throw notFound('The engagement was not found.');
  }
  if (existing.status === 'CLOSED') {
    throw conflict('A closed engagement cannot be changed.');
  }

  const startsAt = input.startsAt ?? existing.startsAt;
  const endsAt = input.endsAt ?? existing.endsAt;
  if (endsAt.getTime() <= startsAt.getTime()) {
    throw badRequest('The engagement must end after it starts.');
  }

  const nextStatus = input.status ?? existing.status;
  if (nextStatus !== existing.status) {
    const allowed = ENGAGEMENT_TRANSITIONS[existing.status];
    if (!allowed.includes(nextStatus)) {
      throw conflict(`An engagement cannot move from ${existing.status} to ${nextStatus}.`);
    }
  }
  if (nextStatus === 'ACTIVE' && existing.status !== 'ACTIVE') {
    const includes = await prisma.engagementScopeEntry.count({
      where: { engagementId, organizationId: ctx.organization.id, kind: 'INCLUDE' },
    });
    if (includes === 0) {
      throw badRequest('Add at least one included target before activating the engagement.');
    }
  }

  await prisma.$transaction(async (tx) => {
    await tx.engagement.update({
      where: { id: engagementId },
      data: {
        ...(input.name !== undefined ? { name: input.name } : {}),
        ...(input.description !== undefined ? { description: input.description } : {}),
        ...(input.startsAt !== undefined ? { startsAt: input.startsAt } : {}),
        ...(input.endsAt !== undefined ? { endsAt: input.endsAt } : {}),
        ...(nextStatus !== existing.status ? { status: nextStatus } : {}),
        ...(nextStatus === 'CLOSED' ? { closedAt: new Date() } : {}),
      },
    });
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action:
        nextStatus === 'CLOSED' && existing.status !== 'CLOSED'
          ? AuditActions.ENGAGEMENT_CLOSED
          : AuditActions.ENGAGEMENT_UPDATED,
      outcome: 'SUCCESS',
      targetType: 'engagement',
      targetId: engagementId,
      summary:
        nextStatus !== existing.status
          ? `Moved engagement from ${existing.status} to ${nextStatus}`
          : 'Updated engagement details',
      metadata: {
        previousStatus: existing.status,
        status: nextStatus,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });

  return getEngagement(ctx.organization.id, engagementId);
}

export async function addScopeEntry(
  ctx: TenantContext,
  engagementId: string,
  input: { kind: ScopeEntryKind; targetType: ScopeTargetType; value: string; note?: string | null },
): Promise<EngagementScopeEntryView> {
  const engagement = await prisma.engagement.findFirst({
    where: { id: engagementId, organizationId: ctx.organization.id },
    select: { id: true, status: true },
  });
  if (!engagement) {
    throw notFound('The engagement was not found.');
  }
  if (engagement.status === 'CLOSED') {
    throw conflict('A closed engagement cannot accept new scope.');
  }

  let normalized: string;
  try {
    normalized = normalizeScopeValue(input.targetType, input.value);
  } catch (error) {
    if (error instanceof ScopeFormatError) {
      throw badRequest(error.message);
    }
    throw error;
  }

  try {
    const entry = await prisma.$transaction(async (tx) => {
      const created = await tx.engagementScopeEntry.create({
        data: {
          organizationId: ctx.organization.id,
          engagementId,
          kind: input.kind,
          targetType: input.targetType,
          value: normalized,
          note: input.note ?? null,
          createdById: ctx.user.id,
        },
        include: { createdBy: { select: { id: true, name: true, email: true } } },
      });
      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.ENGAGEMENT_SCOPE_ADDED,
        outcome: 'SUCCESS',
        targetType: 'engagement',
        targetId: engagementId,
        summary: `Added ${input.kind.toLowerCase()} scope ${input.targetType} ${normalized}`,
        metadata: { kind: input.kind, targetType: input.targetType, value: normalized },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });
      return created;
    });

    return {
      id: entry.id,
      kind: entry.kind,
      targetType: entry.targetType,
      value: entry.value,
      note: entry.note,
      createdAt: entry.createdAt.toISOString(),
      createdBy: entry.createdBy,
    };
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict('That target is already listed with the same rule kind.');
    }
    throw error;
  }
}

export async function removeScopeEntry(
  ctx: TenantContext,
  engagementId: string,
  entryId: string,
): Promise<void> {
  const engagement = await prisma.engagement.findFirst({
    where: { id: engagementId, organizationId: ctx.organization.id },
    select: { status: true },
  });
  if (!engagement) {
    throw notFound('The engagement was not found.');
  }
  if (engagement.status === 'CLOSED') {
    throw conflict('A closed engagement cannot change scope.');
  }

  const entry = await prisma.engagementScopeEntry.findFirst({
    where: { id: entryId, engagementId, organizationId: ctx.organization.id },
  });
  if (!entry) {
    throw notFound('The scope entry was not found.');
  }

  await prisma.$transaction(async (tx) => {
    await tx.engagementScopeEntry.delete({ where: { id: entryId } });
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ENGAGEMENT_SCOPE_REMOVED,
      outcome: 'SUCCESS',
      targetType: 'engagement',
      targetId: engagementId,
      summary: `Removed ${entry.kind.toLowerCase()} scope ${entry.targetType} ${entry.value}`,
      metadata: { kind: entry.kind, targetType: entry.targetType, value: entry.value },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });
}

export async function requestAuthorization(
  ctx: TenantContext,
  engagementId: string,
  input: { expiresAt: Date; reference: string; conditions?: string | null },
): Promise<AuthorizationView> {
  const engagement = await prisma.engagement.findFirst({
    where: { id: engagementId, organizationId: ctx.organization.id },
    select: { id: true, status: true, endsAt: true },
  });
  if (!engagement) {
    throw notFound('The engagement was not found.');
  }
  if (engagement.status === 'CLOSED') {
    throw conflict('A closed engagement cannot be authorized.');
  }

  const now = new Date();
  if (input.expiresAt.getTime() <= now.getTime()) {
    throw badRequest('The authorization must expire in the future.');
  }
  if (input.expiresAt.getTime() > engagement.endsAt.getTime()) {
    throw badRequest('The authorization cannot outlive the engagement window.');
  }

  const pending = await prisma.engagementAuthorization.count({
    where: { engagementId, organizationId: ctx.organization.id, status: 'PENDING' },
  });
  if (pending > 0) {
    throw conflict('An authorization request is already pending for this engagement.');
  }

  const created = await prisma.$transaction(async (tx) => {
    const authorization = await tx.engagementAuthorization.create({
      data: {
        organizationId: ctx.organization.id,
        engagementId,
        status: 'PENDING',
        reference: input.reference,
        conditions: input.conditions ?? null,
        requestedById: ctx.user.id,
        expiresAt: input.expiresAt,
      },
      include: {
        requestedBy: { select: { id: true, name: true, email: true } },
        decidedBy: { select: { id: true, name: true, email: true } },
        revokedBy: { select: { id: true, name: true, email: true } },
      },
    });
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ENGAGEMENT_AUTHORIZATION_REQUESTED,
      outcome: 'SUCCESS',
      targetType: 'engagement_authorization',
      targetId: authorization.id,
      summary: 'Requested authorization to test',
      metadata: {
        engagementId,
        reference: input.reference,
        expiresAt: input.expiresAt.toISOString(),
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
    return authorization;
  });

  return {
    id: created.id,
    status: created.status,
    effectiveStatus: created.status,
    reference: created.reference,
    conditions: created.conditions,
    expiresAt: created.expiresAt.toISOString(),
    decidedAt: null,
    revokedAt: null,
    createdAt: created.createdAt.toISOString(),
    requestedBy: created.requestedBy,
    decidedBy: created.decidedBy,
    revokedBy: created.revokedBy,
  };
}

async function loadAuthorization(
  organizationId: string,
  engagementId: string,
  authorizationId: string,
) {
  const authorization = await prisma.engagementAuthorization.findFirst({
    where: { id: authorizationId, engagementId, organizationId },
  });
  if (!authorization) {
    throw notFound('The authorization was not found.');
  }
  return authorization;
}

export async function decideAuthorization(
  ctx: TenantContext,
  engagementId: string,
  authorizationId: string,
  input: { decision: 'APPROVED' | 'REJECTED'; note?: string | null },
): Promise<AuthorizationView> {
  // Capability policy already restricts this to owners; the check is repeated so
  // a future route mistake cannot turn an admin into an authorizer.
  if (ctx.membership.role !== 'OWNER') {
    throw forbidden('Only an owner can decide an authorization.');
  }

  return prisma.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT 1::int AS locked FROM (SELECT pg_advisory_xact_lock(hashtextextended(${engagementId}, ${ENGAGEMENT_LOCK_NAMESPACE}))) AS engagement_lock`;

    const authorization = await tx.engagementAuthorization.findFirst({
      where: { id: authorizationId, engagementId, organizationId: ctx.organization.id },
    });
    if (!authorization) {
      throw notFound('The authorization was not found.');
    }
    if (authorization.status !== 'PENDING') {
      throw conflict('Only a pending authorization can be decided.');
    }
    if (authorization.requestedById === ctx.user.id) {
      throw forbidden('The person who requested an authorization cannot decide it.');
    }

    const now = new Date();
    if (input.decision === 'APPROVED') {
      if (authorization.expiresAt.getTime() <= now.getTime()) {
        throw badRequest('This authorization has already expired.');
      }
      const approved = await tx.engagementAuthorization.count({
        where: {
          engagementId,
          organizationId: ctx.organization.id,
          status: 'APPROVED',
          id: { not: authorizationId },
        },
      });
      if (approved > 0) {
        throw conflict('Revoke the active authorization before approving another.');
      }
    }

    const updated = await tx.engagementAuthorization.update({
      where: { id: authorizationId },
      data: {
        status: input.decision,
        decidedById: ctx.user.id,
        decidedAt: now,
      },
      include: {
        requestedBy: { select: { id: true, name: true, email: true } },
        decidedBy: { select: { id: true, name: true, email: true } },
        revokedBy: { select: { id: true, name: true, email: true } },
      },
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action:
        input.decision === 'APPROVED'
          ? AuditActions.ENGAGEMENT_AUTHORIZATION_APPROVED
          : AuditActions.ENGAGEMENT_AUTHORIZATION_REJECTED,
      outcome: 'SUCCESS',
      targetType: 'engagement_authorization',
      targetId: authorizationId,
      summary:
        input.decision === 'APPROVED'
          ? 'Approved authorization to test'
          : 'Rejected authorization to test',
      metadata: {
        engagementId,
        reference: authorization.reference,
        expiresAt: authorization.expiresAt.toISOString(),
        note: input.note ?? null,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return {
      id: updated.id,
      status: updated.status,
      effectiveStatus: updated.status,
      reference: updated.reference,
      conditions: updated.conditions,
      expiresAt: updated.expiresAt.toISOString(),
      decidedAt: updated.decidedAt?.toISOString() ?? null,
      revokedAt: null,
      createdAt: updated.createdAt.toISOString(),
      requestedBy: updated.requestedBy,
      decidedBy: updated.decidedBy,
      revokedBy: null,
    };
  });
}

export async function revokeAuthorization(
  ctx: TenantContext,
  engagementId: string,
  authorizationId: string,
  input: { reason: string },
): Promise<AuthorizationView> {
  const authorization = await loadAuthorization(ctx.organization.id, engagementId, authorizationId);
  if (authorization.status === 'REVOKED') {
    throw conflict('This authorization is already revoked.');
  }
  if (authorization.status !== 'APPROVED') {
    throw conflict('Only an approved authorization can be revoked.');
  }

  // Revocation is an owner decision, matching approval. An admin can stop
  // execution through the job-cancel path without changing the authorization.
  if (ctx.membership.role !== 'OWNER' && authorization.requestedById !== ctx.user.id) {
    throw forbidden('Only an owner can revoke an authorization.');
  }

  const revoked = await prisma.$transaction(async (tx) => {
    const updated = await tx.engagementAuthorization.update({
      where: { id: authorizationId },
      data: { status: 'REVOKED', revokedAt: new Date(), revokedById: ctx.user.id },
      include: {
        requestedBy: { select: { id: true, name: true, email: true } },
        decidedBy: { select: { id: true, name: true, email: true } },
        revokedBy: { select: { id: true, name: true, email: true } },
      },
    });
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ENGAGEMENT_AUTHORIZATION_REVOKED,
      outcome: 'SUCCESS',
      targetType: 'engagement_authorization',
      targetId: authorizationId,
      summary: 'Revoked authorization to test',
      metadata: { engagementId, reason: input.reason },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
    return updated;
  });

  return {
    id: revoked.id,
    status: revoked.status,
    effectiveStatus: revoked.status,
    reference: revoked.reference,
    conditions: revoked.conditions,
    expiresAt: revoked.expiresAt.toISOString(),
    decidedAt: revoked.decidedAt?.toISOString() ?? null,
    revokedAt: revoked.revokedAt?.toISOString() ?? null,
    createdAt: revoked.createdAt.toISOString(),
    requestedBy: revoked.requestedBy,
    decidedBy: revoked.decidedBy,
    revokedBy: revoked.revokedBy,
  };
}

/**
 * Audit helper for a dispatch that never becomes a job because no authorization
 * exists. Written outside any transaction so the denial survives the throw.
 */
export async function auditDispatchDenied(
  ctx: TenantContext,
  engagementId: string,
  reason: string,
  target: { targetType: string; targetValue: string },
): Promise<void> {
  await recordAuditEvent({
    organizationId: ctx.organization.id,
    actorType: 'USER',
    actorId: ctx.user.id,
    action: AuditActions.EXECUTION_DISPATCH_DENIED,
    outcome: 'DENIED',
    targetType: 'engagement',
    targetId: engagementId,
    summary: `Denied execution request: ${reason}`,
    metadata: { reason, ...target },
    ipAddress: ctx.meta.ipAddress,
    userAgent: ctx.meta.userAgent,
    requestId: ctx.meta.requestId,
  });
}
