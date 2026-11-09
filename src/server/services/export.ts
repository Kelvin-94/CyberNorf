import { prisma } from '@/lib/prisma';

/**
 * Whole-organization export for portability, archival, and a customer's
 * "give me my data" request.
 *
 * The export deliberately contains business records and the audit trail, and
 * deliberately contains no secrets: agent token hashes and prefixes, sealed
 * webhook secrets, sessions, second-factor secrets, and password hashes are
 * never selected, because an export is a file that travels.
 *
 * Records are exported as stored, including internal ids, so a restore can keep
 * relations intact; the audit chain is exported with its hashes so an importer
 * or auditor can verify it outside the platform.
 */

export const EXPORT_VERSION = 1;

export interface OrganizationExport {
  meta: {
    format: 'cybernorf.export';
    version: number;
    exportedAt: string;
    organization: { id: string; name: string; slug: string; tier: string };
    counts: Record<string, number>;
    excludes: string[];
  };
  organization: unknown;
  members: unknown[];
  assets: unknown[];
  findings: unknown[];
  incidents: unknown[];
  compliance: {
    frameworks: unknown[];
    controls: unknown[];
    evidence: unknown[];
    checkMappings: unknown[];
  };
  agents: unknown[];
  agentRuns: unknown[];
  advisories: unknown[];
  softwareItems: unknown[];
  notificationChannels: unknown[];
  notificationEvents: unknown[];
  auditEvents: unknown[];
}

const EXCLUDED = [
  'agent token hashes, prefixes, and expiry',
  'sealed webhook signing secrets',
  'sessions, accounts, password hashes, and second-factor secrets',
  'rate-limit windows',
];

export async function exportOrganization(organizationId: string): Promise<OrganizationExport> {
  const organization = await prisma.organization.findUniqueOrThrow({
    where: { id: organizationId },
    select: { id: true, name: true, slug: true, tier: true, createdAt: true, updatedAt: true },
  });

  const [
    members,
    assets,
    findings,
    incidents,
    frameworks,
    controls,
    evidence,
    checkMappings,
    agents,
    agentRuns,
    advisories,
    softwareItems,
    notificationChannels,
    notificationEvents,
    auditEvents,
  ] = await Promise.all([
    prisma.membership.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'asc' },
      select: {
        id: true,
        role: true,
        status: true,
        createdAt: true,
        updatedAt: true,
        user: { select: { id: true, name: true, email: true, twoFactorEnabled: true } },
      },
    }),
    prisma.asset.findMany({ where: { organizationId }, orderBy: { createdAt: 'asc' } }),
    prisma.finding.findMany({ where: { organizationId }, orderBy: { createdAt: 'asc' } }),
    prisma.incident.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'asc' },
      include: { notes: { orderBy: { createdAt: 'asc' } } },
    }),
    prisma.organizationFramework.findMany({
      where: { organizationId },
      orderBy: { adoptedAt: 'asc' },
      include: { framework: true },
    }),
    prisma.organizationControl.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'asc' },
      include: { control: true },
    }),
    prisma.controlEvidence.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'asc' },
    }),
    prisma.checkControlMap.findMany({ where: { organizationId }, orderBy: { createdAt: 'asc' } }),
    prisma.agent.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'asc' },
      select: {
        id: true,
        name: true,
        description: true,
        source: true,
        status: true,
        scopes: true,
        expectedIntervalMinutes: true,
        lastSeenAt: true,
        lastRunAt: true,
        runCount: true,
        createdById: true,
        approvedById: true,
        approvedAt: true,
        revokedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    }),
    prisma.agentRun.findMany({ where: { organizationId }, orderBy: { startedAt: 'asc' } }),
    prisma.advisory.findMany({ where: { organizationId }, orderBy: { createdAt: 'asc' } }),
    prisma.softwareItem.findMany({ where: { organizationId }, orderBy: { name: 'asc' } }),
    prisma.notificationChannel.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'asc' },
      select: {
        id: true,
        name: true,
        kind: true,
        url: true,
        enabled: true,
        createdById: true,
        createdAt: true,
        updatedAt: true,
        lastDeliveredAt: true,
        lastError: true,
      },
    }),
    prisma.notificationEvent.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'asc' },
      select: {
        id: true,
        channelId: true,
        type: true,
        status: true,
        attempts: true,
        deliveredAt: true,
        lastError: true,
        createdAt: true,
      },
    }),
    prisma.auditEvent.findMany({
      where: { organizationId },
      orderBy: { sequence: 'asc' },
    }),
  ]);

  const counts: Record<string, number> = {
    members: members.length,
    assets: assets.length,
    findings: findings.length,
    incidents: incidents.length,
    frameworks: frameworks.length,
    controls: controls.length,
    evidence: evidence.length,
    checkMappings: checkMappings.length,
    agents: agents.length,
    agentRuns: agentRuns.length,
    advisories: advisories.length,
    softwareItems: softwareItems.length,
    notificationChannels: notificationChannels.length,
    notificationEvents: notificationEvents.length,
    auditEvents: auditEvents.length,
  };

  return {
    meta: {
      format: 'cybernorf.export',
      version: EXPORT_VERSION,
      exportedAt: new Date().toISOString(),
      organization: {
        id: organization.id,
        name: organization.name,
        slug: organization.slug,
        tier: organization.tier,
      },
      counts,
      excludes: EXCLUDED,
    },
    organization,
    members,
    assets,
    findings,
    incidents,
    compliance: { frameworks, controls, evidence, checkMappings },
    agents,
    agentRuns,
    advisories,
    softwareItems,
    notificationChannels,
    notificationEvents,
    auditEvents,
  };
}
