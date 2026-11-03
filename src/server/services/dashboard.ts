import type { FindingSeverity } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import type { TenantContext } from '@/server/authz/context';

const OPEN_FINDING_STATUSES = ['OPEN', 'TRIAGED', 'IN_PROGRESS'] as const;
const SEVERITIES: FindingSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export async function getDashboardSummary(ctx: TenantContext) {
  const organizationId = ctx.organization.id;

  const [
    assetCounts,
    findingsBySeverity,
    findingsByStatus,
    incidentsByStatus,
    latestFindings,
    recentEvents,
    openIncidentCount,
    members,
  ] = await Promise.all([
    prisma.asset.groupBy({ by: ['status'], where: { organizationId }, _count: { _all: true } }),
    prisma.finding.groupBy({
      by: ['severity'],
      where: { organizationId, status: { in: [...OPEN_FINDING_STATUSES] } },
      _count: { _all: true },
    }),
    prisma.finding.groupBy({ by: ['status'], where: { organizationId }, _count: { _all: true } }),
    prisma.incident.groupBy({ by: ['status'], where: { organizationId }, _count: { _all: true } }),
    prisma.finding.findMany({
      where: { organizationId, status: { in: [...OPEN_FINDING_STATUSES] } },
      select: {
        id: true,
        title: true,
        severity: true,
        status: true,
        createdAt: true,
        asset: { select: { id: true, name: true } },
      },
      orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }],
      take: 6,
    }),
    prisma.auditEvent.findMany({
      where: { organizationId },
      select: {
        id: true,
        action: true,
        outcome: true,
        summary: true,
        createdAt: true,
        targetType: true,
        targetId: true,
        actor: { select: { name: true } },
      },
      orderBy: [{ createdAt: 'desc' }, { sequence: 'desc' }],
      take: 8,
    }),
    prisma.incident.count({
      where: { organizationId, status: { in: ['OPEN', 'INVESTIGATING', 'CONTAINED'] } },
    }),
    prisma.membership.count({ where: { organizationId, status: 'ACTIVE' } }),
  ]);

  const assetsByStatus = Object.fromEntries(
    assetCounts.map((row) => [row.status, row._count._all]),
  );
  const severityTotals = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0])) as Record<
    FindingSeverity,
    number
  >;
  for (const row of findingsBySeverity) {
    severityTotals[row.severity] = row._count._all;
  }

  return {
    organization: ctx.organization,
    role: ctx.membership.role,
    assets: {
      total: assetCounts.reduce((sum, row) => sum + row._count._all, 0),
      active: assetsByStatus.ACTIVE ?? 0,
      inactive: assetsByStatus.INACTIVE ?? 0,
      retired: assetsByStatus.RETIRED ?? 0,
    },
    findings: {
      bySeverity: severityTotals,
      openTotal: findingsBySeverity.reduce((sum, row) => sum + row._count._all, 0),
      byStatus: Object.fromEntries(findingsByStatus.map((row) => [row.status, row._count._all])),
    },
    incidents: {
      open: openIncidentCount,
      byStatus: Object.fromEntries(incidentsByStatus.map((row) => [row.status, row._count._all])),
    },
    members,
    latestFindings,
    recentEvents,
  };
}
