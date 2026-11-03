import type { IncidentSeverity, IncidentStatus, Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import { canTransitionIncident } from '@/server/domain/transitions';
import { conflict, notFound } from '@/server/errors';
import { assertActiveMember, paginationMeta } from './shared';

export interface IncidentListQuery {
  search?: string | null;
  status?: IncidentStatus;
  severity?: IncidentSeverity;
  assignedToId?: string;
  page: number;
  pageSize: number;
  sort: 'createdAt' | 'updatedAt' | 'severity' | 'status' | 'title' | 'detectedAt';
  direction: 'asc' | 'desc';
}

const INCIDENT_SUMMARY_SELECT = {
  id: true,
  title: true,
  severity: true,
  status: true,
  detectedAt: true,
  resolvedAt: true,
  closedAt: true,
  createdAt: true,
  updatedAt: true,
  assignedTo: { select: { id: true, name: true, email: true } },
  _count: { select: { notes: true, findings: true } },
} satisfies Prisma.IncidentSelect;

export async function listIncidents(organizationId: string, query: IncidentListQuery) {
  const where: Prisma.IncidentWhereInput = {
    organizationId,
    ...(query.status ? { status: query.status } : {}),
    ...(query.severity ? { severity: query.severity } : {}),
    ...(query.assignedToId ? { assignedToId: query.assignedToId } : {}),
    ...(query.search
      ? {
          OR: [
            { title: { contains: query.search, mode: 'insensitive' } },
            { description: { contains: query.search, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [rows, total] = await prisma.$transaction([
    prisma.incident.findMany({
      where,
      select: INCIDENT_SUMMARY_SELECT,
      orderBy: { [query.sort]: query.direction },
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
    prisma.incident.count({ where }),
  ]);

  return {
    items: rows.map((row) => ({
      ...row,
      noteCount: row._count.notes,
      findingCount: row._count.findings,
    })),
    ...paginationMeta(query.page, query.pageSize, total),
  };
}

export async function getIncidentDetail(ctx: TenantContext, incidentId: string) {
  const incident = await prisma.incident.findFirst({
    where: { id: incidentId, organizationId: ctx.organization.id },
    select: {
      ...INCIDENT_SUMMARY_SELECT,
      organizationId: true,
      description: true,
      createdBy: { select: { id: true, name: true, email: true } },
      notes: {
        select: {
          id: true,
          body: true,
          createdAt: true,
          author: { select: { id: true, name: true, email: true } },
        },
        orderBy: { createdAt: 'asc' },
        take: 500,
      },
      findings: {
        select: { id: true, title: true, severity: true, status: true },
        orderBy: { createdAt: 'desc' },
        take: 100,
      },
    },
  });

  if (!incident) {
    throw notFound('Incident not found.');
  }

  const history = await prisma.auditEvent.findMany({
    where: {
      organizationId: ctx.organization.id,
      targetType: 'incident',
      targetId: incident.id,
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
    orderBy: { createdAt: 'asc' },
    take: 300,
  });

  return { ...incident, history };
}

export async function createIncident(
  ctx: TenantContext,
  input: {
    title: string;
    description?: string | null;
    severity: IncidentSeverity;
    assignedToId?: string | null;
    detectedAt?: Date;
  },
) {
  const assignedToId = input.assignedToId ?? null;
  await assertActiveMember(ctx.organization.id, assignedToId);

  return prisma.$transaction(async (tx) => {
    const incident = await tx.incident.create({
      data: {
        organizationId: ctx.organization.id,
        createdById: ctx.user.id,
        title: input.title,
        description: input.description ?? null,
        severity: input.severity,
        assignedToId,
        ...(input.detectedAt ? { detectedAt: input.detectedAt } : {}),
      },
      select: INCIDENT_SUMMARY_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.INCIDENT_CREATED,
      outcome: 'SUCCESS',
      targetType: 'incident',
      targetId: incident.id,
      summary: `Incident "${incident.title}" created`,
      metadata: { severity: incident.severity, assignedToId },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return incident;
  });
}

export async function updateIncident(
  ctx: TenantContext,
  incidentId: string,
  input: Partial<{
    title: string;
    description: string | null;
    severity: IncidentSeverity;
    assignedToId: string | null;
  }>,
) {
  const existing = await prisma.incident.findFirst({
    where: { id: incidentId, organizationId: ctx.organization.id },
    select: { id: true, title: true, severity: true, assignedToId: true },
  });

  if (!existing) {
    throw notFound('Incident not found.');
  }

  if (input.assignedToId !== undefined) {
    await assertActiveMember(ctx.organization.id, input.assignedToId);
  }

  return prisma.$transaction(async (tx) => {
    const incident = await tx.incident.update({
      where: { id: existing.id },
      data: input,
      select: INCIDENT_SUMMARY_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.INCIDENT_UPDATED,
      outcome: 'SUCCESS',
      targetType: 'incident',
      targetId: incident.id,
      summary: `Incident "${incident.title}" updated`,
      metadata: { changedFields: Object.keys(input), before: existing },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return incident;
  });
}

export async function changeIncidentStatus(
  ctx: TenantContext,
  incidentId: string,
  nextStatus: IncidentStatus,
  note?: string | null,
) {
  const existing = await prisma.incident.findFirst({
    where: { id: incidentId, organizationId: ctx.organization.id },
    select: { id: true, title: true, status: true },
  });

  if (!existing) {
    throw notFound('Incident not found.');
  }

  if (existing.status === nextStatus) {
    return { id: existing.id, status: existing.status, changed: false };
  }

  if (!canTransitionIncident(existing.status, nextStatus)) {
    throw conflict(`An incident cannot move from ${existing.status} to ${nextStatus}.`);
  }

  return prisma.$transaction(async (tx) => {
    const now = new Date();
    const data: Prisma.IncidentUpdateInput = { status: nextStatus };
    if (nextStatus === 'RESOLVED') {
      data.resolvedAt = now;
      data.closedAt = null;
    } else if (nextStatus === 'CLOSED') {
      data.closedAt = now;
    } else if (nextStatus === 'OPEN') {
      // Reopening an incident clears the resolution timestamps.
      data.resolvedAt = null;
      data.closedAt = null;
    }

    const incident = await tx.incident.update({
      where: { id: existing.id },
      data,
      select: { id: true, title: true, status: true, resolvedAt: true, closedAt: true },
    });

    if (note) {
      await tx.incidentNote.create({
        data: {
          organizationId: ctx.organization.id,
          incidentId: incident.id,
          authorId: ctx.user.id,
          body: note,
        },
      });
    }

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.INCIDENT_STATUS_CHANGED,
      outcome: 'SUCCESS',
      targetType: 'incident',
      targetId: incident.id,
      summary: `Incident "${incident.title}" moved from ${existing.status} to ${nextStatus}`,
      metadata: { from: existing.status, to: nextStatus, note: note ?? null },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return { ...incident, changed: true };
  });
}

export async function addIncidentNote(ctx: TenantContext, incidentId: string, body: string) {
  const incident = await prisma.incident.findFirst({
    where: { id: incidentId, organizationId: ctx.organization.id },
    select: { id: true, title: true },
  });

  if (!incident) {
    throw notFound('Incident not found.');
  }

  return prisma.$transaction(async (tx) => {
    const note = await tx.incidentNote.create({
      data: {
        organizationId: ctx.organization.id,
        incidentId: incident.id,
        authorId: ctx.user.id,
        body,
      },
      select: {
        id: true,
        body: true,
        createdAt: true,
        author: { select: { id: true, name: true } },
      },
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.INCIDENT_NOTE_ADDED,
      outcome: 'SUCCESS',
      targetType: 'incident',
      targetId: incident.id,
      summary: `Investigation note added to "${incident.title}"`,
      metadata: { noteId: note.id, length: body.length },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return note;
  });
}

export async function linkFindingsToIncident(
  ctx: TenantContext,
  incidentId: string,
  findingIds: string[],
) {
  const incident = await prisma.incident.findFirst({
    where: { id: incidentId, organizationId: ctx.organization.id },
    select: { id: true, title: true },
  });

  if (!incident) {
    throw notFound('Incident not found.');
  }

  const findings = await prisma.finding.findMany({
    where: { id: { in: findingIds }, organizationId: ctx.organization.id },
    select: { id: true, title: true },
  });

  if (findings.length !== new Set(findingIds).size) {
    throw notFound('One or more findings were not found in this organization.');
  }

  return prisma.$transaction(async (tx) => {
    await tx.finding.updateMany({
      where: {
        id: { in: findings.map((finding) => finding.id) },
        organizationId: ctx.organization.id,
      },
      data: { incidentId: incident.id },
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.INCIDENT_FINDING_LINKED,
      outcome: 'SUCCESS',
      targetType: 'incident',
      targetId: incident.id,
      summary: `${findings.length} finding(s) linked to "${incident.title}"`,
      metadata: { findingIds: findings.map((finding) => finding.id) },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return { linked: findings.length };
  });
}

export async function listIncidentAssignees(organizationId: string) {
  const memberships = await prisma.membership.findMany({
    where: { organizationId, status: 'ACTIVE' },
    select: { user: { select: { id: true, name: true, email: true } } },
    orderBy: { user: { name: 'asc' } },
    take: 200,
  });
  return memberships.map((membership) => membership.user);
}
