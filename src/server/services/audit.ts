import type { AuditOutcome, Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { verifyAuditChain } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import { paginationMeta } from './shared';

export interface AuditListQuery {
  search?: string | null;
  action?: string;
  outcome?: AuditOutcome;
  targetType?: string;
  actorId?: string;
  from?: Date;
  to?: Date;
  page: number;
  pageSize: number;
  direction: 'asc' | 'desc';
}

export async function listAuditEvents(organizationId: string, query: AuditListQuery) {
  const where: Prisma.AuditEventWhereInput = {
    organizationId,
    ...(query.action ? { action: query.action } : {}),
    ...(query.outcome ? { outcome: query.outcome } : {}),
    ...(query.targetType ? { targetType: query.targetType } : {}),
    ...(query.actorId ? { actorId: query.actorId } : {}),
    ...(query.from || query.to
      ? {
          createdAt: {
            ...(query.from ? { gte: query.from } : {}),
            ...(query.to ? { lte: query.to } : {}),
          },
        }
      : {}),
    ...(query.search
      ? {
          OR: [
            { action: { contains: query.search, mode: 'insensitive' } },
            { summary: { contains: query.search, mode: 'insensitive' } },
            { targetId: { contains: query.search, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [items, total] = await prisma.$transaction([
    prisma.auditEvent.findMany({
      where,
      select: {
        id: true,
        sequence: true,
        action: true,
        outcome: true,
        actorType: true,
        actorId: true,
        targetType: true,
        targetId: true,
        summary: true,
        metadata: true,
        ipAddress: true,
        requestId: true,
        createdAt: true,
        hash: true,
        prevHash: true,
        actor: { select: { name: true, email: true } },
      },
      orderBy: [{ createdAt: query.direction }, { sequence: query.direction }],
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
    prisma.auditEvent.count({ where }),
  ]);

  return { items, ...paginationMeta(query.page, query.pageSize, total) };
}

export async function getAuditIntegrityReport(ctx: TenantContext) {
  const verification = await verifyAuditChain(ctx.organization.id);
  const eventCount = await prisma.auditEvent.count({
    where: { organizationId: ctx.organization.id },
  });
  return { ...verification, eventCount };
}
