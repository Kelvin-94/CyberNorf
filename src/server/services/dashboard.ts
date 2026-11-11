import type { FindingSeverity } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import type { TenantContext } from '@/server/authz/context';
import { DUE_SOON_DAYS, summarizeResolutions } from '@/server/domain/risk';

/** Resolution figures are reported over a rolling quarter. */
const RESOLUTION_WINDOW_DAYS = 90;
/** Upper bound on resolved rows pulled for the compliance/MTTR averages. */
const RESOLUTION_SAMPLE_LIMIT = 5000;
const DAY_MS = 86_400_000;

const OPEN_FINDING_STATUSES = ['OPEN', 'TRIAGED', 'IN_PROGRESS'] as const;
const SEVERITIES: FindingSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export async function getDashboardSummary(ctx: TenantContext) {
  const organizationId = ctx.organization.id;
  // One clock for every window, so "overdue" and "due soon" cannot overlap or
  // leave a gap at the boundary.
  const now = new Date();

  const [
    assetCounts,
    findingsBySeverity,
    findingsByStatus,
    incidentsByStatus,
    latestFindings,
    recentEvents,
    openIncidentCount,
    members,
    overdueFindings,
    dueSoonFindings,
    resolvedWindow,
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
    // Counted in SQL rather than derived from a fetched page: an organisation
    // with thousands of open findings must still get an exact overdue figure.
    prisma.finding.count({
      where: {
        organizationId,
        status: { in: [...OPEN_FINDING_STATUSES] },
        dueAt: { lt: now },
      },
    }),
    prisma.finding.count({
      where: {
        organizationId,
        status: { in: [...OPEN_FINDING_STATUSES] },
        dueAt: {
          gte: now,
          lte: new Date(now.getTime() + DUE_SOON_DAYS * DAY_MS),
        },
      },
    }),
    prisma.finding.findMany({
      where: {
        organizationId,
        status: 'RESOLVED',
        resolvedAt: { gte: new Date(now.getTime() - RESOLUTION_WINDOW_DAYS * DAY_MS) },
      },
      select: { status: true, dueAt: true, resolvedAt: true, createdAt: true },
      orderBy: { resolvedAt: 'desc' },
      take: RESOLUTION_SAMPLE_LIMIT,
    }),
  ]);

  const resolutions = summarizeResolutions(resolvedWindow);

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
    remediation: {
      overdue: overdueFindings,
      dueSoon: dueSoonFindings,
      open: findingsBySeverity.reduce((sum, row) => sum + row._count._all, 0),
      slaCompliance: resolutions.slaCompliance,
      meanTimeToResolveDays: resolutions.meanTimeToResolveDays,
      resolutionSampleSize: resolutions.sampleSize,
      windowDays: RESOLUTION_WINDOW_DAYS,
    },
  };
}
