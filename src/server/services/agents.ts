import { Prisma, type Agent, type AgentSource, type AgentStatus } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import {
  canTransitionAgent,
  defaultAgentScopes,
  hashAgentToken,
  initialAgentStatus,
  isAgentTokenShape,
  issueAgentToken,
  runStatusForCounts,
  summarizeChecks,
  type AgentCheckCounts,
} from '@/server/domain/agents';
import { deriveAgentHealth, type AgentHealth } from '@/server/domain/notifications';
import { badRequest, conflict, forbidden, notFound, unauthenticated } from '@/server/errors';
import { attachMappedEvidence, loadMappedControls } from '@/server/services/check-maps';
import { agentFingerprint, isUniqueConstraintError } from '@/server/services/shared';
import { syncInventoryAndMatch } from '@/server/services/software';
import type {
  AgentHeartbeatInput,
  AgentRunReportInput,
  AgentScopeInput,
  RegisterAgentInput,
} from '@/server/validation/agents';

/** Agent row shape returned to the console. The token hash never leaves the server. */
export interface AgentView {
  id: string;
  name: string;
  description: string | null;
  source: AgentSource;
  status: AgentStatus;
  scopes: string[];
  tokenPrefix: string | null;
  tokenExpiresAt: string | null;
  lastSeenAt: string | null;
  lastRunAt: string | null;
  /** Operator-configured reporting cadence; null disables offline detection. */
  expectedIntervalMinutes: number | null;
  /** When an offline alert was queued, cleared by the next healthy run. */
  offlineNotifiedAt: string | null;
  /** Derived from status, cadence and last run: ONLINE, STALE, OFFLINE or UNKNOWN. */
  health: AgentHealth;
  runCount: number;
  createdById: string;
  approvedById: string | null;
  approvedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}

export interface AgentRunCheckView {
  id: string;
  title: string;
  status: 'PASS' | 'FAIL' | 'SKIP';
  severity: string;
  target: string | null;
  detail: string | null;
  remediation: string | null;
}

export interface AgentRunView {
  id: string;
  status: 'COMPLETED' | 'PARTIAL' | 'FAILED';
  hostname: string | null;
  platform: string | null;
  startedAt: string;
  finishedAt: string | null;
  durationMs: number | null;
  checkCount: number;
  passCount: number;
  failCount: number;
  skipCount: number;
  findingsCreated: number;
  findingsRefreshed: number;
}

/** Authenticated agent identity used by agent-facing routes. */
export interface AgentPrincipal {
  id: string;
  organizationId: string;
  name: string;
  source: AgentSource;
  scopes: string[];
  createdById: string;
}

export const AGENT_SELECT = {
  id: true,
  name: true,
  description: true,
  source: true,
  status: true,
  scopes: true,
  tokenPrefix: true,
  tokenExpiresAt: true,
  lastSeenAt: true,
  lastRunAt: true,
  expectedIntervalMinutes: true,
  offlineNotifiedAt: true,
  runCount: true,
  createdById: true,
  approvedById: true,
  approvedAt: true,
  revokedAt: true,
  createdAt: true,
} as const satisfies Prisma.AgentSelect;

const AGENT_RUN_SELECT = {
  id: true,
  status: true,
  hostname: true,
  platform: true,
  startedAt: true,
  finishedAt: true,
  durationMs: true,
  checkCount: true,
  passCount: true,
  failCount: true,
  skipCount: true,
  findingsCreated: true,
  findingsRefreshed: true,
} as const satisfies Prisma.AgentRunSelect;

type AgentRow = Pick<Agent, keyof typeof AGENT_SELECT>;

export function serializeAgent(agent: AgentRow): AgentView {
  return {
    id: agent.id,
    name: agent.name,
    description: agent.description,
    source: agent.source,
    status: agent.status,
    scopes: agent.scopes,
    tokenPrefix: agent.tokenPrefix,
    tokenExpiresAt: agent.tokenExpiresAt ? agent.tokenExpiresAt.toISOString() : null,
    lastSeenAt: agent.lastSeenAt ? agent.lastSeenAt.toISOString() : null,
    lastRunAt: agent.lastRunAt ? agent.lastRunAt.toISOString() : null,
    expectedIntervalMinutes: agent.expectedIntervalMinutes,
    offlineNotifiedAt: agent.offlineNotifiedAt ? agent.offlineNotifiedAt.toISOString() : null,
    health: deriveAgentHealth({
      status: agent.status,
      lastRunAt: agent.lastRunAt,
      expectedIntervalMinutes: agent.expectedIntervalMinutes,
    }),
    runCount: agent.runCount,
    createdById: agent.createdById,
    approvedById: agent.approvedById,
    approvedAt: agent.approvedAt ? agent.approvedAt.toISOString() : null,
    revokedAt: agent.revokedAt ? agent.revokedAt.toISOString() : null,
    createdAt: agent.createdAt.toISOString(),
  };
}

function serializeRun(
  run: Prisma.AgentRunGetPayload<{ select: typeof AGENT_RUN_SELECT }>,
): AgentRunView {
  return {
    id: run.id,
    status: run.status,
    hostname: run.hostname,
    platform: run.platform,
    startedAt: run.startedAt.toISOString(),
    finishedAt: run.finishedAt ? run.finishedAt.toISOString() : null,
    durationMs: run.durationMs,
    checkCount: run.checkCount,
    passCount: run.passCount,
    failCount: run.failCount,
    skipCount: run.skipCount,
    findingsCreated: run.findingsCreated,
    findingsRefreshed: run.findingsRefreshed,
  };
}

export interface AgentListResult {
  agents: AgentView[];
  counts: Record<AgentStatus, number>;
  tokenPolicy: { builtinDays: number; externalDays: number };
}

export async function listAgents(ctx: TenantContext): Promise<AgentListResult> {
  const agents = await prisma.agent.findMany({
    where: { organizationId: ctx.organization.id },
    orderBy: [{ name: 'asc' }],
    select: AGENT_SELECT,
  });

  const counts: Record<AgentStatus, number> = {
    PENDING_APPROVAL: 0,
    ACTIVE: 0,
    SUSPENDED: 0,
    REVOKED: 0,
  };
  for (const agent of agents) {
    counts[agent.status] += 1;
  }

  return {
    agents: agents.map(serializeAgent),
    counts,
    tokenPolicy: { builtinDays: 365, externalDays: 90 },
  };
}

export interface AgentDetailResult {
  agent: AgentView;
  runs: AgentRunView[];
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    lastSeenAt: string;
  }>;
}

export async function getAgentDetail(
  ctx: TenantContext,
  agentId: string,
): Promise<AgentDetailResult> {
  const agent = await prisma.agent.findFirst({
    where: { id: agentId, organizationId: ctx.organization.id },
    select: AGENT_SELECT,
  });
  if (!agent) {
    throw notFound('Agent not found in this organization.');
  }

  const [runs, findings] = await Promise.all([
    prisma.agentRun.findMany({
      where: { organizationId: ctx.organization.id, agentId: agent.id },
      orderBy: { startedAt: 'desc' },
      take: 10,
      select: AGENT_RUN_SELECT,
    }),
    prisma.finding.findMany({
      where: { organizationId: ctx.organization.id, agentId: agent.id },
      orderBy: { lastSeenAt: 'desc' },
      take: 20,
      select: { id: true, title: true, severity: true, status: true, lastSeenAt: true },
    }),
  ]);

  return {
    agent: serializeAgent(agent),
    runs: runs.map(serializeRun),
    findings: findings.map((finding) => ({
      id: finding.id,
      title: finding.title,
      severity: finding.severity,
      status: finding.status,
      lastSeenAt: finding.lastSeenAt.toISOString(),
    })),
  };
}

export interface RegisterAgentResult {
  agent: AgentView;
  /**
   * Plaintext credential, present only for builtin agents (activated at
   * registration). External sources stay inert until an owner approves them,
   * which is when their token is revealed.
   */
  token: string | null;
  tokenExpiresAt: string | null;
}

function resolveScopes(
  source: AgentSource,
  requested: readonly AgentScopeInput[] | undefined,
): AgentScopeInput[] {
  const allowed = defaultAgentScopes();
  if (!requested || requested.length === 0) {
    return [...allowed];
  }
  const rejected = requested.filter((scope) => !allowed.includes(scope));
  if (rejected.length > 0) {
    throw badRequest(
      `A ${source.toLowerCase()} agent cannot request ${rejected.join(', ')}. Allowed scopes: ${allowed.join(', ')}.`,
    );
  }
  return [...new Set(requested)];
}

/**
 * Registers an agent. Builtin agents activate immediately because an OWNER or
 * ADMIN is installing them on a host the tenant already controls. Every
 * external source is created without a credential and becomes usable only after
 * the organization owner approves that specific agent.
 */
export async function registerAgent(
  ctx: TenantContext,
  input: RegisterAgentInput,
): Promise<RegisterAgentResult> {
  const scopes = resolveScopes(input.source, input.scopes);
  const status = initialAgentStatus(input.source);
  const issued = status === 'ACTIVE' ? issueAgentToken(input.source) : null;

  try {
    const agent = await prisma.$transaction(async (tx) => {
      const created = await tx.agent.create({
        data: {
          organizationId: ctx.organization.id,
          name: input.name,
          description: input.description ?? null,
          source: input.source,
          status,
          scopes,
          tokenHash: issued?.hash ?? null,
          tokenPrefix: issued?.prefix ?? null,
          tokenExpiresAt: issued?.expiresAt ?? null,
          createdById: ctx.user.id,
          approvedById: status === 'ACTIVE' ? ctx.user.id : null,
          approvedAt: status === 'ACTIVE' ? new Date() : null,
        },
        select: AGENT_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.AGENT_REGISTERED,
        outcome: 'SUCCESS',
        targetType: 'agent',
        targetId: created.id,
        summary: `Registered ${input.source} agent "${created.name}" (${status})`,
        metadata: {
          source: input.source,
          status,
          scopes,
          tokenIssued: issued !== null,
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return created;
    });

    return {
      agent: serializeAgent(agent),
      token: issued?.token ?? null,
      tokenExpiresAt: issued ? issued.expiresAt.toISOString() : null,
    };
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict(`An agent named "${input.name}" already exists in this organization.`);
    }
    throw error;
  }
}

/** Approval and revocation are owner decisions, so the role check sits in the service. */
function assertOwner(ctx: TenantContext): void {
  if (ctx.membership.role !== 'OWNER') {
    throw forbidden('Only an organization owner can approve, suspend, resume or revoke agents.');
  }
}

async function loadAgent(
  ctx: TenantContext,
  agentId: string,
): Promise<{
  id: string;
  name: string;
  source: AgentSource;
  status: AgentStatus;
  scopes: string[];
  tokenPrefix: string | null;
}> {
  const agent = await prisma.agent.findFirst({
    where: { id: agentId, organizationId: ctx.organization.id },
    select: { id: true, name: true, source: true, status: true, scopes: true, tokenPrefix: true },
  });
  if (!agent) {
    throw notFound('Agent not found in this organization.');
  }
  return agent;
}

function assertTransition(current: AgentStatus, target: AgentStatus, action: string): void {
  if (!canTransitionAgent(current, target)) {
    throw conflict(`Cannot ${action} an agent that is ${current}.`);
  }
}

export interface ApproveAgentResult {
  agent: AgentView;
  /** One-time credential for the approved external agent. */
  token: string;
  tokenExpiresAt: string;
}

/**
 * Approves a pending agent and issues its credential. The plaintext token is
 * returned once, here; only its hash is stored, so it cannot be recovered later.
 */
export async function approveAgent(
  ctx: TenantContext,
  agentId: string,
  input: { scopes?: AgentScopeInput[]; note?: string | null },
): Promise<ApproveAgentResult> {
  assertOwner(ctx);
  const agent = await loadAgent(ctx, agentId);

  if (agent.status === 'REVOKED') {
    throw conflict('This agent was revoked and cannot be approved again.');
  }
  if (agent.status === 'ACTIVE') {
    throw conflict('This agent is already active.');
  }

  const requested = input.scopes ?? agent.scopes;
  const rejected = requested.filter((scope) => !agent.scopes.includes(scope));
  if (rejected.length > 0) {
    throw badRequest(`Approval cannot add scopes that were not requested: ${rejected.join(', ')}.`);
  }

  const issued = issueAgentToken(agent.source);

  const updated = await prisma.$transaction(async (tx) => {
    const row = await tx.agent.update({
      where: { id: agent.id },
      data: {
        status: 'ACTIVE',
        scopes: requested,
        tokenHash: issued.hash,
        tokenPrefix: issued.prefix,
        tokenExpiresAt: issued.expiresAt,
        approvedById: ctx.user.id,
        approvedAt: new Date(),
      },
      select: AGENT_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.AGENT_APPROVED,
      outcome: 'SUCCESS',
      targetType: 'agent',
      targetId: row.id,
      summary: `Approved ${row.source} agent "${row.name}"`,
      metadata: {
        scopes: requested,
        tokenExpiresAt: issued.expiresAt.toISOString(),
        note: input.note ?? null,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return row;
  });

  return {
    agent: serializeAgent(updated),
    token: issued.token,
    tokenExpiresAt: issued.expiresAt.toISOString(),
  };
}

/** Suspending keeps the record and history but the credential stops working. */
export async function suspendAgent(
  ctx: TenantContext,
  agentId: string,
  note: string | null = null,
): Promise<AgentView> {
  assertOwner(ctx);
  const agent = await loadAgent(ctx, agentId);
  assertTransition(agent.status, 'SUSPENDED', 'suspend');

  return prisma.$transaction(async (tx) => {
    const row = await tx.agent.update({
      where: { id: agent.id },
      data: { status: 'SUSPENDED' },
      select: AGENT_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.AGENT_SUSPENDED,
      outcome: 'SUCCESS',
      targetType: 'agent',
      targetId: row.id,
      summary: `Suspended agent "${row.name}"`,
      metadata: { note },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return serializeAgent(row);
  });
}

/** Resuming re-enables the existing credential until it expires. */
export async function resumeAgent(
  ctx: TenantContext,
  agentId: string,
  note: string | null = null,
): Promise<AgentView> {
  assertOwner(ctx);
  const agent = await loadAgent(ctx, agentId);
  assertTransition(agent.status, 'ACTIVE', 'resume');

  return prisma.$transaction(async (tx) => {
    const row = await tx.agent.update({
      where: { id: agent.id },
      data: { status: 'ACTIVE' },
      select: AGENT_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.AGENT_RESUMED,
      outcome: 'SUCCESS',
      targetType: 'agent',
      targetId: row.id,
      summary: `Resumed agent "${row.name}"`,
      metadata: { note },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return serializeAgent(row);
  });
}

/**
 * Records the operator's expected reporting cadence.
 *
 * The interval is a monitoring expectation, not an access grant, so it does not
 * need owner approval. Clearing it turns offline detection off for the agent;
 * the pending outage marker is cleared too, so re-enabling an interval later
 * does not immediately alert for a window nobody was watching.
 */
export async function updateAgentHeartbeat(
  ctx: TenantContext,
  agentId: string,
  input: AgentHeartbeatInput,
): Promise<AgentView> {
  const agent = await loadAgent(ctx, agentId);
  if (agent.status === 'REVOKED') {
    throw conflict('A revoked agent cannot be reconfigured.');
  }

  return prisma.$transaction(async (tx) => {
    const previous = await tx.agent.findUniqueOrThrow({
      where: { id: agent.id },
      select: { expectedIntervalMinutes: true },
    });
    const row = await tx.agent.update({
      where: { id: agent.id },
      data: {
        expectedIntervalMinutes: input.expectedIntervalMinutes,
        ...(input.expectedIntervalMinutes === null ? { offlineNotifiedAt: null } : {}),
      },
      select: AGENT_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.AGENT_HEARTBEAT_UPDATED,
      outcome: 'SUCCESS',
      targetType: 'agent',
      targetId: row.id,
      summary:
        input.expectedIntervalMinutes === null
          ? `Disabled offline detection for agent "${row.name}"`
          : `Agent "${row.name}" expected every ${input.expectedIntervalMinutes} minutes`,
      metadata: {
        previousIntervalMinutes: previous.expectedIntervalMinutes,
        expectedIntervalMinutes: input.expectedIntervalMinutes,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return serializeAgent(row);
  });
}

/**
 * Revocation is terminal. The token hash is cleared as well as the status, so
 * the credential stops resolving even if the status were edited out of band.
 */
export async function revokeAgent(
  ctx: TenantContext,
  agentId: string,
  note: string | null = null,
): Promise<AgentView> {
  assertOwner(ctx);
  const agent = await loadAgent(ctx, agentId);
  assertTransition(agent.status, 'REVOKED', 'revoke');

  return prisma.$transaction(async (tx) => {
    const row = await tx.agent.update({
      where: { id: agent.id },
      data: { status: 'REVOKED', revokedAt: new Date(), tokenHash: null },
      select: AGENT_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.AGENT_REVOKED,
      outcome: 'SUCCESS',
      targetType: 'agent',
      targetId: row.id,
      summary: `Revoked agent "${row.name}"`,
      metadata: { note },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return serializeAgent(row);
  });
}

/**
 * Issues a replacement credential for an active agent.
 *
 * Revoking and re-registering loses the run history and the check-to-control
 * mappings, so a leaked token or an expiring lifetime had no clean answer. The
 * agent row is kept, the old hash is replaced in the same transaction, and the
 * previous prefix is recorded so an operator can tell the two credentials apart
 * in the audit trail. The plaintext token is returned once, here.
 *
 * The signing key is derived from the credential, so rotation also invalidates
 * any signature produced with the old token.
 */
export async function rotateAgentToken(
  ctx: TenantContext,
  agentId: string,
  note: string | null = null,
): Promise<ApproveAgentResult> {
  assertOwner(ctx);
  const agent = await loadAgent(ctx, agentId);

  if (agent.status !== 'ACTIVE') {
    throw conflict(
      agent.status === 'REVOKED'
        ? 'This agent was revoked and cannot be rotated.'
        : 'Only an active agent can have its token rotated.',
    );
  }

  const issued = issueAgentToken(agent.source);

  const updated = await prisma.$transaction(async (tx) => {
    const row = await tx.agent.update({
      where: { id: agent.id },
      data: {
        tokenHash: issued.hash,
        tokenPrefix: issued.prefix,
        tokenExpiresAt: issued.expiresAt,
      },
      select: AGENT_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.AGENT_TOKEN_ROTATED,
      outcome: 'SUCCESS',
      targetType: 'agent',
      targetId: row.id,
      summary: `Rotated the token for agent "${row.name}"`,
      metadata: {
        previousPrefix: agent.tokenPrefix,
        tokenPrefix: issued.prefix,
        tokenExpiresAt: issued.expiresAt.toISOString(),
        note,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return row;
  });

  return {
    agent: serializeAgent(updated),
    token: issued.token,
    tokenExpiresAt: issued.expiresAt.toISOString(),
  };
}

/**
 * Resolves a bearer token to an agent. Unknown, suspended, revoked and expired
 * credentials all fail the same way, so the endpoint cannot be used to probe
 * which tokens exist.
 */
export async function authenticateAgentToken(token: string): Promise<AgentPrincipal> {
  if (!isAgentTokenShape(token)) {
    throw unauthenticated();
  }

  const agent = await prisma.agent.findUnique({
    where: { tokenHash: hashAgentToken(token) },
    select: {
      id: true,
      organizationId: true,
      name: true,
      source: true,
      status: true,
      scopes: true,
      tokenExpiresAt: true,
      createdById: true,
    },
  });

  if (!agent || agent.status !== 'ACTIVE') {
    throw unauthenticated();
  }
  if (!agent.tokenExpiresAt || agent.tokenExpiresAt.getTime() <= Date.now()) {
    throw unauthenticated();
  }

  return {
    id: agent.id,
    organizationId: agent.organizationId,
    name: agent.name,
    source: agent.source,
    scopes: agent.scopes,
    createdById: agent.createdById,
  };
}

export interface RecordRunResult {
  run: AgentRunView;
  counts: AgentCheckCounts;
  findingsCreated: number;
  findingsRefreshed: number;
  findingsSuppressed: number;
  /** Evidence items filed against mapped controls during this run. */
  controlEvidenceAttached: number;
  /** Packages stored from the inventory snapshot (0 when none was sent). */
  inventoryCount: number;
  /** Advisory matches evaluated for this run, whether new or refreshed. */
  advisoryMatches: number;
}

/** Statuses where a still-failing check refreshes the existing finding. */
const OPEN_FINDING_STATUSES = new Set(['OPEN', 'TRIAGED', 'IN_PROGRESS']);

/**
 * Findings are titled with the faulty state, not with the pass condition the
 * check name describes. Agents that send `findingTitle` get their wording; older
 * reports fall back to the check title.
 */
function findingTitleFor(check: AgentRunReportInput['checks'][number]): string {
  return check.findingTitle?.trim() || check.title;
}

/**
 * Ingests one monitoring run.
 *
 * The agent supplies observations only. Counts, run status and findings are all
 * derived here. A FAIL check creates or refreshes a finding keyed by check id
 * and target; a finding a human already closed (resolved, accepted risk, false
 * positive) stays closed instead of being reopened by every run, because that
 * decision belongs to a person rather than to a monitor.
 */
export async function recordAgentRun(
  principal: AgentPrincipal,
  report: AgentRunReportInput,
): Promise<RecordRunResult> {
  const counts = summarizeChecks(report.checks.map((check) => check.status));
  const status = runStatusForCounts(counts);
  const defaultTarget = report.hostname ?? 'local';
  const failing = report.checks.filter((check) => check.status === 'FAIL');

  const normalized = report.checks.map((check) => ({
    id: check.id,
    title: check.title,
    status: check.status,
    severity: check.severity,
    target: check.target ?? defaultTarget,
    detail: check.detail ?? null,
    remediation: check.remediation ?? null,
  }));

  const result = await prisma.$transaction(async (tx) => {
    const created = await tx.agentRun.create({
      data: {
        organizationId: principal.organizationId,
        agentId: principal.id,
        status,
        hostname: report.hostname ?? null,
        platform: report.platform ?? null,
        startedAt: report.startedAt,
        finishedAt: report.finishedAt ?? null,
        durationMs: report.durationMs ?? null,
        checkCount: counts.checkCount,
        passCount: counts.passCount,
        failCount: counts.failCount,
        skipCount: counts.skipCount,
        checks: normalized as unknown as Prisma.InputJsonValue,
      },
      select: { id: true },
    });

    let findingsCreated = 0;
    let findingsRefreshed = 0;
    let findingsSuppressed = 0;
    let controlEvidenceAttached = 0;
    const now = new Date();

    // Loaded once: a run normally has a handful of failing checks, and the map
    // table is small, but per-finding lookups would still multiply the queries.
    const mappedByCheck = await loadMappedControls(
      tx,
      principal.organizationId,
      failing.map((check) => check.id),
    );

    for (const check of failing) {
      const checkTarget = check.target ?? defaultTarget;
      const fingerprint = agentFingerprint(principal.organizationId, check.id, checkTarget);
      const existing = await tx.finding.findFirst({
        where: { organizationId: principal.organizationId, fingerprint },
        select: { id: true, status: true },
      });

      if (!existing) {
        const createdFinding = await tx.finding.create({
          data: {
            organizationId: principal.organizationId,
            agentId: principal.id,
            title: findingTitleFor(check),
            description: check.detail ?? `Reported by agent "${principal.name}" on ${checkTarget}.`,
            severity: check.severity,
            status: 'OPEN',
            source: 'AGENT',
            fingerprint,
            remediation: check.remediation ?? null,
            // The registering operator owns the record; the agent relation keeps
            // provenance exact without inventing a non-human user row.
            createdById: principal.createdById,
            firstSeenAt: now,
            lastSeenAt: now,
          },
          select: { id: true, title: true },
        });

        // The finding detail page renders its history from the audit trail, so an
        // agent-raised finding records its own creation event or it would show
        // up with no provenance at all.
        await appendAuditEvent(tx, {
          organizationId: principal.organizationId,
          actorType: 'AGENT',
          actorId: null,
          action: AuditActions.FINDING_CREATED,
          outcome: 'SUCCESS',
          targetType: 'finding',
          targetId: createdFinding.id,
          summary: `Finding ${createdFinding.title} raised by agent "${principal.name}"`,
          metadata: {
            source: 'AGENT',
            agentId: principal.id,
            runId: created.id,
            checkId: check.id,
            target: checkTarget,
            severity: check.severity,
          },
          ipAddress: null,
          userAgent: null,
          requestId: null,
        });

        controlEvidenceAttached += await attachMappedEvidence(tx, {
          organizationId: principal.organizationId,
          agentId: principal.id,
          agentName: principal.name,
          runId: created.id,
          checkId: check.id,
          findingId: createdFinding.id,
          findingTitle: createdFinding.title,
          createdById: principal.createdById,
          controls: mappedByCheck.get(check.id) ?? [],
        });

        findingsCreated += 1;
        continue;
      }

      if (OPEN_FINDING_STATUSES.has(existing.status)) {
        // The newest observation wins, but an empty detail must not erase the
        // context an analyst already relied on.
        const refresh: Prisma.FindingUpdateInput = {
          lastSeenAt: now,
          severity: check.severity,
          agent: { connect: { id: principal.id } },
        };
        if (check.detail) {
          refresh.description = check.detail;
        }
        if (check.remediation) {
          refresh.remediation = check.remediation;
        }
        await tx.finding.update({ where: { id: existing.id }, data: refresh });

        // A control mapped after the finding was first raised still receives its
        // evidence on the next failing run; repeat runs stay idempotent.
        controlEvidenceAttached += await attachMappedEvidence(tx, {
          organizationId: principal.organizationId,
          agentId: principal.id,
          agentName: principal.name,
          runId: created.id,
          checkId: check.id,
          findingId: existing.id,
          findingTitle: findingTitleFor(check),
          createdById: principal.createdById,
          controls: mappedByCheck.get(check.id) ?? [],
        });

        findingsRefreshed += 1;
      } else {
        findingsSuppressed += 1;
      }
    }

    // Inventory is optional and additive: a report without it leaves the stored
    // snapshot untouched, while a report with it replaces the snapshot so an
    // upgraded or removed package stops matching advisories.
    let inventoryCount = 0;
    let advisoryMatches = 0;
    if (report.inventory !== undefined) {
      const inventory = await syncInventoryAndMatch(tx, {
        organizationId: principal.organizationId,
        agentId: principal.id,
        createdById: principal.createdById,
        hostname: report.hostname ?? null,
        items: report.inventory,
      });
      inventoryCount = inventory.inventoryCount;

      if (inventory.assetCreated && inventory.assetId) {
        await appendAuditEvent(tx, {
          organizationId: principal.organizationId,
          actorType: 'AGENT',
          actorId: null,
          action: AuditActions.ASSET_CREATED,
          outcome: 'SUCCESS',
          targetType: 'asset',
          targetId: inventory.assetId,
          summary: `Asset ${report.hostname} discovered by agent "${principal.name}"`,
          metadata: {
            source: 'AGENT_INVENTORY',
            agentId: principal.id,
            runId: created.id,
            hostname: report.hostname ?? null,
          },
          ipAddress: null,
          userAgent: null,
          requestId: null,
        });
      }

      for (const draft of inventory.matches) {
        advisoryMatches += 1;
        const existingAdvisory = await tx.finding.findFirst({
          where: { organizationId: principal.organizationId, fingerprint: draft.fingerprint },
          select: { id: true, status: true },
        });
        const description = `${draft.summary} ${draft.packageName} ${draft.installedVersion} installed on ${draft.target} falls inside the affected range ${draft.affectedRange}.`;
        const remediation = draft.fixedVersion
          ? `Upgrade ${draft.packageName} to ${draft.fixedVersion} or later.`
          : `Upgrade ${draft.packageName} to a release outside ${draft.affectedRange}, or remove it.`;
        const cveId = /^CVE-\d{4}-\d{4,}$/i.test(draft.identifier)
          ? draft.identifier.toUpperCase()
          : null;

        if (!existingAdvisory) {
          const createdFinding = await tx.finding.create({
            data: {
              organizationId: principal.organizationId,
              agentId: principal.id,
              assetId: draft.assetId,
              title: `${draft.packageName} ${draft.installedVersion} is affected by ${draft.identifier}`,
              description,
              severity: draft.severity,
              status: 'OPEN',
              source: 'AGENT',
              fingerprint: draft.fingerprint,
              cveId,
              cvssScore: draft.cvssScore,
              remediation,
              createdById: principal.createdById,
              firstSeenAt: now,
              lastSeenAt: now,
            },
            select: { id: true, title: true },
          });

          await appendAuditEvent(tx, {
            organizationId: principal.organizationId,
            actorType: 'AGENT',
            actorId: null,
            action: AuditActions.FINDING_CREATED,
            outcome: 'SUCCESS',
            targetType: 'finding',
            targetId: createdFinding.id,
            summary: `Finding ${createdFinding.title} raised by agent "${principal.name}"`,
            metadata: {
              source: 'AGENT',
              agentId: principal.id,
              runId: created.id,
              advisoryId: draft.advisoryId,
              advisoryIdentifier: draft.identifier,
              ecosystem: draft.ecosystem,
              packageName: draft.packageName,
              installedVersion: draft.installedVersion,
              target: draft.target,
              severity: draft.severity,
            },
            ipAddress: null,
            userAgent: null,
            requestId: null,
          });

          findingsCreated += 1;
          continue;
        }

        if (OPEN_FINDING_STATUSES.has(existingAdvisory.status)) {
          await tx.finding.update({
            where: { id: existingAdvisory.id },
            data: {
              lastSeenAt: now,
              severity: draft.severity,
              description,
              remediation,
              cvssScore: draft.cvssScore,
              ...(draft.assetId ? { asset: { connect: { id: draft.assetId } } } : {}),
              agent: { connect: { id: principal.id } },
            },
          });
          findingsRefreshed += 1;
        } else {
          findingsSuppressed += 1;
        }
      }
    }

    const run = await tx.agentRun.update({
      where: { id: created.id },
      data: { findingsCreated, findingsRefreshed },
      select: AGENT_RUN_SELECT,
    });

    await tx.agent.update({
      where: { id: principal.id },
      data: { lastSeenAt: now, lastRunAt: now, runCount: { increment: 1 } },
    });

    await appendAuditEvent(tx, {
      organizationId: principal.organizationId,
      actorType: 'AGENT',
      actorId: null,
      action: AuditActions.AGENT_RUN_RECORDED,
      outcome: 'SUCCESS',
      targetType: 'agent',
      targetId: principal.id,
      summary: `Agent "${principal.name}" reported ${counts.checkCount} checks (${counts.failCount} failing) on ${defaultTarget}`,
      metadata: {
        agentId: principal.id,
        runId: run.id,
        hostname: report.hostname ?? null,
        checkCount: counts.checkCount,
        failCount: counts.failCount,
        skipCount: counts.skipCount,
        findingsCreated,
        findingsRefreshed,
        findingsSuppressed,
        controlEvidenceAttached,
        inventoryCount,
        advisoryMatches,
      },
      ipAddress: null,
      userAgent: null,
      requestId: null,
    });

    return {
      run,
      findingsCreated,
      findingsRefreshed,
      findingsSuppressed,
      controlEvidenceAttached,
      inventoryCount,
      advisoryMatches,
    };
  });

  return {
    run: serializeRun(result.run),
    counts,
    findingsCreated: result.findingsCreated,
    findingsRefreshed: result.findingsRefreshed,
    findingsSuppressed: result.findingsSuppressed,
    controlEvidenceAttached: result.controlEvidenceAttached,
    inventoryCount: result.inventoryCount,
    advisoryMatches: result.advisoryMatches,
  };
}

/** Self-description returned to an agent so it can verify its own access. */
export async function describeAgent(principal: AgentPrincipal): Promise<{
  id: string;
  name: string;
  source: AgentSource;
  status: AgentStatus;
  scopes: string[];
  organizationId: string;
  tokenExpiresAt: string | null;
  lastSeenAt: string | null;
  lastRunAt: string | null;
  runCount: number;
}> {
  const agent = await prisma.agent.findUniqueOrThrow({
    where: { id: principal.id },
    select: {
      id: true,
      name: true,
      source: true,
      status: true,
      scopes: true,
      organizationId: true,
      tokenExpiresAt: true,
      lastSeenAt: true,
      lastRunAt: true,
      runCount: true,
    },
  });

  return {
    id: agent.id,
    name: agent.name,
    source: agent.source,
    status: agent.status,
    scopes: agent.scopes,
    organizationId: agent.organizationId,
    tokenExpiresAt: agent.tokenExpiresAt ? agent.tokenExpiresAt.toISOString() : null,
    lastSeenAt: agent.lastSeenAt ? agent.lastSeenAt.toISOString() : null,
    lastRunAt: agent.lastRunAt ? agent.lastRunAt.toISOString() : null,
    runCount: agent.runCount,
  };
}

export interface AgentRunHistory {
  runs: AgentRunView[];
  agent: { id: string; name: string; source: AgentSource; tokenExpiresAt: string | null };
}

export async function listAgentRuns(
  principal: AgentPrincipal,
  limit = 20,
): Promise<AgentRunHistory> {
  const [runs, agent] = await Promise.all([
    prisma.agentRun.findMany({
      where: { agentId: principal.id, organizationId: principal.organizationId },
      orderBy: { startedAt: 'desc' },
      take: Math.min(Math.max(limit, 1), 50),
      select: AGENT_RUN_SELECT,
    }),
    prisma.agent.findUniqueOrThrow({
      where: { id: principal.id },
      select: { id: true, name: true, source: true, tokenExpiresAt: true },
    }),
  ]);

  return {
    runs: runs.map(serializeRun),
    agent: {
      id: agent.id,
      name: agent.name,
      source: agent.source,
      tokenExpiresAt: agent.tokenExpiresAt ? agent.tokenExpiresAt.toISOString() : null,
    },
  };
}

/** Run detail with the raw checks, for the console drill-down. */
export async function getAgentRun(
  ctx: TenantContext,
  agentId: string,
  runId: string,
): Promise<{
  run: AgentRunView;
  checks: AgentRunCheckView[];
  findings: Array<{ id: string; title: string; severity: string; status: string }>;
}> {
  const run = await prisma.agentRun.findFirst({
    where: { id: runId, agentId, organizationId: ctx.organization.id },
    select: { ...AGENT_RUN_SELECT, checks: true },
  });
  if (!run) {
    throw notFound('Agent run not found in this organization.');
  }

  const checks = Array.isArray(run.checks) ? (run.checks as unknown as AgentRunCheckView[]) : [];
  // Findings are keyed by a hash, so the failing checks are resolved back to
  // their fingerprints instead of matching on titles.
  const fingerprints = checks
    .filter((check) => check.status === 'FAIL')
    .map((check) =>
      agentFingerprint(ctx.organization.id, check.id, check.target ?? run.hostname ?? 'local'),
    );

  const findings =
    fingerprints.length === 0
      ? []
      : await prisma.finding.findMany({
          where: {
            organizationId: ctx.organization.id,
            agentId,
            fingerprint: { in: fingerprints },
          },
          orderBy: { lastSeenAt: 'desc' },
          take: 50,
          select: { id: true, title: true, severity: true, status: true },
        });

  return { run: serializeRun(run), checks, findings };
}
