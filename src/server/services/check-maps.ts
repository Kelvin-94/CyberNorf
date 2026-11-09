import { Prisma, type ControlStatus } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import { conflict, notFound } from '@/server/errors';
import { isUniqueConstraintError } from '@/server/services/shared';
import type { CreateCheckMapInput } from '@/server/validation/agents';

/** How many recent runs are scanned to discover the checks an agent reports. */
const OBSERVED_RUN_WINDOW = 20;

/** Upper bound on controls one check may feed; a human maps these by hand. */
const MAX_MAPS_PER_CHECK = 25;

const MAP_SELECT = {
  id: true,
  checkId: true,
  createdAt: true,
  organizationControl: {
    select: {
      id: true,
      status: true,
      organizationFrameworkId: true,
      control: { select: { code: true, title: true } },
      organizationFramework: {
        select: { framework: { select: { code: true, name: true } } },
      },
      _count: { select: { evidence: true } },
    },
  },
} as const satisfies Prisma.CheckControlMapSelect;

type MapRow = Prisma.CheckControlMapGetPayload<{ select: typeof MAP_SELECT }>;

export interface CheckMapControlView {
  mapId: string;
  organizationControlId: string;
  frameworkCode: string;
  frameworkName: string;
  controlCode: string;
  controlTitle: string;
  status: ControlStatus;
  evidenceCount: number;
  createdAt: string;
}

export interface ObservedCheckView {
  checkId: string;
  title: string;
  lastStatus: 'PASS' | 'FAIL' | 'SKIP' | 'UNKNOWN';
  lastSeenAt: string | null;
  mappings: CheckMapControlView[];
}

export interface MapTargetControl {
  id: string;
  frameworkCode: string;
  controlCode: string;
  controlTitle: string;
  status: ControlStatus;
}

export interface CheckMapOverview {
  /** Checks this agent actually reported, newest observation per check id. */
  checks: ObservedCheckView[];
  /** Controls from frameworks the tenant has adopted, for the mapping picker. */
  controls: MapTargetControl[];
}

function serializeMap(row: MapRow): CheckMapControlView {
  return {
    mapId: row.id,
    organizationControlId: row.organizationControl.id,
    frameworkCode: row.organizationControl.organizationFramework.framework.code,
    frameworkName: row.organizationControl.organizationFramework.framework.name,
    controlCode: row.organizationControl.control.code,
    controlTitle: row.organizationControl.control.title,
    status: row.organizationControl.status,
    evidenceCount: row.organizationControl._count.evidence,
    createdAt: row.createdAt.toISOString(),
  };
}

/**
 * Builds the mapping overview for one agent: the checks it reported (so the
 * operator maps what the host really emits, not a documented list) plus every
 * control of an adopted framework to choose from.
 */
export async function listCheckMaps(
  ctx: TenantContext,
  agentId: string | null,
): Promise<CheckMapOverview> {
  if (agentId) {
    const agent = await prisma.agent.findFirst({
      where: { id: agentId, organizationId: ctx.organization.id },
      select: { id: true },
    });
    if (!agent) {
      throw notFound('Agent not found in this organization.');
    }
  }

  const [runs, maps, controls] = await Promise.all([
    prisma.agentRun.findMany({
      where: {
        organizationId: ctx.organization.id,
        ...(agentId ? { agentId } : {}),
      },
      orderBy: { startedAt: 'desc' },
      take: OBSERVED_RUN_WINDOW,
      select: { checks: true, startedAt: true },
    }),
    prisma.checkControlMap.findMany({
      where: { organizationId: ctx.organization.id },
      orderBy: { createdAt: 'asc' },
      take: 500,
      select: MAP_SELECT,
    }),
    prisma.organizationControl.findMany({
      where: { organizationId: ctx.organization.id },
      orderBy: [
        { organizationFramework: { framework: { code: 'asc' } } },
        { control: { position: 'asc' } },
      ],
      take: 500,
      select: {
        id: true,
        status: true,
        control: { select: { code: true, title: true } },
        organizationFramework: { select: { framework: { select: { code: true } } } },
      },
    }),
  ]);

  const mappedByCheck = new Map<string, CheckMapControlView[]>();
  for (const row of maps) {
    const list = mappedByCheck.get(row.checkId) ?? [];
    list.push(serializeMap(row));
    mappedByCheck.set(row.checkId, list);
  }

  // Runs arrive newest first, so the first sighting of a check id wins.
  const observed = new Map<string, ObservedCheckView>();
  for (const run of runs) {
    const checks = Array.isArray(run.checks) ? run.checks : [];
    for (const raw of checks) {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
        continue;
      }
      const entry = raw as Record<string, unknown>;
      const checkId = typeof entry.id === 'string' ? entry.id : null;
      if (!checkId || observed.has(checkId)) {
        continue;
      }
      const status = entry.status;
      observed.set(checkId, {
        checkId,
        title: typeof entry.title === 'string' ? entry.title : checkId,
        lastStatus:
          status === 'PASS' || status === 'FAIL' || status === 'SKIP' ? status : 'UNKNOWN',
        lastSeenAt: run.startedAt.toISOString(),
        mappings: mappedByCheck.get(checkId) ?? [],
      });
    }
  }

  // A mapping can outlive the run window; keep it visible so it can be removed.
  for (const [checkId, list] of mappedByCheck) {
    if (!observed.has(checkId)) {
      observed.set(checkId, {
        checkId,
        title: checkId,
        lastStatus: 'UNKNOWN',
        lastSeenAt: null,
        mappings: list,
      });
    }
  }

  return {
    checks: [...observed.values()].sort((a, b) => a.checkId.localeCompare(b.checkId)),
    controls: controls.map((control) => ({
      id: control.id,
      frameworkCode: control.organizationFramework.framework.code,
      controlCode: control.control.code,
      controlTitle: control.control.title,
      status: control.status,
    })),
  };
}

export interface CreateCheckMapResult {
  map: CheckMapControlView;
}

/**
 * Maps one monitoring check onto one control of an adopted framework. The
 * control must already exist in the tenant, which also proves the framework is
 * adopted: an unmapped catalog cannot receive evidence.
 */
export async function createCheckMap(
  ctx: TenantContext,
  input: CreateCheckMapInput,
): Promise<CreateCheckMapResult> {
  const control = await prisma.organizationControl.findFirst({
    where: { id: input.organizationControlId, organizationId: ctx.organization.id },
    select: {
      id: true,
      organizationFrameworkId: true,
      control: { select: { code: true } },
      organizationFramework: { select: { framework: { select: { code: true } } } },
    },
  });
  if (!control) {
    throw notFound('Control not found in this organization.');
  }

  const existingForCheck = await prisma.checkControlMap.count({
    where: { organizationId: ctx.organization.id, checkId: input.checkId },
  });
  if (existingForCheck >= MAX_MAPS_PER_CHECK) {
    throw conflict(`A check can be mapped to at most ${MAX_MAPS_PER_CHECK} controls.`);
  }

  try {
    const map = await prisma.$transaction(async (tx) => {
      const created = await tx.checkControlMap.create({
        data: {
          organizationId: ctx.organization.id,
          checkId: input.checkId,
          organizationControlId: control.id,
          createdById: ctx.user.id,
        },
        select: MAP_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.AGENT_CHECK_MAPPED,
        outcome: 'SUCCESS',
        targetType: 'compliance_framework',
        targetId: control.organizationFrameworkId,
        summary: `Check ${input.checkId} mapped to ${control.control.code}`,
        metadata: {
          mapId: created.id,
          checkId: input.checkId,
          organizationControlId: control.id,
          controlCode: control.control.code,
          frameworkCode: control.organizationFramework.framework.code,
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return created;
    });

    return { map: serializeMap(map) };
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict('This check is already mapped to that control.');
    }
    throw error;
  }
}

export async function deleteCheckMap(ctx: TenantContext, mapId: string): Promise<{ id: string }> {
  const existing = await prisma.checkControlMap.findFirst({
    where: { id: mapId, organizationId: ctx.organization.id },
    select: {
      id: true,
      checkId: true,
      organizationControl: {
        select: {
          id: true,
          organizationFrameworkId: true,
          control: { select: { code: true } },
          organizationFramework: { select: { framework: { select: { code: true } } } },
        },
      },
    },
  });
  if (!existing) {
    throw notFound('Check mapping not found in this organization.');
  }

  await prisma.$transaction(async (tx) => {
    await tx.checkControlMap.delete({ where: { id: existing.id } });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.AGENT_CHECK_UNMAPPED,
      outcome: 'SUCCESS',
      targetType: 'compliance_framework',
      targetId: existing.organizationControl.organizationFrameworkId,
      summary: `Check ${existing.checkId} unmapped from ${existing.organizationControl.control.code}`,
      metadata: {
        mapId: existing.id,
        checkId: existing.checkId,
        organizationControlId: existing.organizationControl.id,
        controlCode: existing.organizationControl.control.code,
        frameworkCode: existing.organizationControl.organizationFramework.framework.code,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });

  return { id: existing.id };
}

interface MappedControl {
  organizationControlId: string;
  organizationFrameworkId: string;
  controlCode: string;
}

/**
 * Loads the controls each failing check feeds, keyed by check id. Called once
 * per run so ingestion does not query the mapping table per finding.
 */
export async function loadMappedControls(
  tx: Prisma.TransactionClient,
  organizationId: string,
  checkIds: readonly string[],
): Promise<Map<string, MappedControl[]>> {
  if (checkIds.length === 0) {
    return new Map();
  }

  const rows = await tx.checkControlMap.findMany({
    where: { organizationId, checkId: { in: [...new Set(checkIds)] } },
    take: 500,
    select: {
      checkId: true,
      organizationControl: {
        select: {
          id: true,
          organizationFrameworkId: true,
          control: { select: { code: true } },
        },
      },
    },
  });

  const mapped = new Map<string, MappedControl[]>();
  for (const row of rows) {
    const list = mapped.get(row.checkId) ?? [];
    list.push({
      organizationControlId: row.organizationControl.id,
      organizationFrameworkId: row.organizationControl.organizationFrameworkId,
      controlCode: row.organizationControl.control.code,
    });
    mapped.set(row.checkId, list);
  }
  return mapped;
}

/**
 * Attaches a finding to every control mapped to the check that produced it.
 *
 * Evidence is idempotent per (control, finding): a failing check that keeps
 * failing refreshes the same finding and does not pile up duplicate evidence.
 * Each new attachment is audited as an AGENT action so the compliance history
 * shows that a machine, not a person, filed it.
 */
export async function attachMappedEvidence(
  tx: Prisma.TransactionClient,
  input: {
    organizationId: string;
    agentId: string;
    agentName: string;
    runId: string;
    checkId: string;
    findingId: string;
    findingTitle: string;
    /** The operator who registered the agent; evidence requires a user row. */
    createdById: string;
    controls: readonly MappedControl[];
  },
): Promise<number> {
  if (input.controls.length === 0) {
    return 0;
  }

  const alreadyAttached = await tx.controlEvidence.findMany({
    where: {
      organizationId: input.organizationId,
      findingId: input.findingId,
      organizationControlId: { in: input.controls.map((control) => control.organizationControlId) },
    },
    select: { organizationControlId: true },
  });
  const attached = new Set(alreadyAttached.map((row) => row.organizationControlId));

  let created = 0;
  for (const control of input.controls) {
    if (attached.has(control.organizationControlId)) {
      continue;
    }

    const evidence = await tx.controlEvidence.create({
      data: {
        organizationId: input.organizationId,
        organizationControlId: control.organizationControlId,
        kind: 'FINDING',
        findingId: input.findingId,
        note: `Agent "${input.agentName}" check ${input.checkId} failed: ${input.findingTitle}`,
        createdById: input.createdById,
      },
      select: { id: true },
    });

    await appendAuditEvent(tx, {
      organizationId: input.organizationId,
      actorType: 'AGENT',
      actorId: null,
      action: AuditActions.COMPLIANCE_EVIDENCE_ADDED,
      outcome: 'SUCCESS',
      targetType: 'compliance_framework',
      targetId: control.organizationFrameworkId,
      summary: `Evidence attached to ${control.controlCode} by agent "${input.agentName}"`,
      metadata: {
        organizationControlId: control.organizationControlId,
        controlCode: control.controlCode,
        evidenceId: evidence.id,
        kind: 'FINDING',
        findingId: input.findingId,
        agentId: input.agentId,
        runId: input.runId,
        checkId: input.checkId,
        automatic: true,
      },
      ipAddress: null,
      userAgent: null,
      requestId: null,
    });

    created += 1;
  }

  return created;
}
