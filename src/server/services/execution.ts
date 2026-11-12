import { lookup } from 'node:dns/promises';
import type {
  ExecutionCapability as PrismaCapability,
  ExecutionJobStatus,
  Prisma,
} from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent, recordAuditEvent } from '@/server/audit/audit';
import { getMaxActiveExecutionJobs } from '@/server/config';
import { isAtLeast, type OrgRole } from '@/server/authz/roles';
import type { TenantContext } from '@/server/authz/context';
import {
  addressSetsDiffer,
  describeDenial,
  durationLimitExceeded,
  evaluateDispatch,
  normalizeJobLimits,
  normalizeScopeValue,
  riskForCapability,
  workerEgressAllows,
  workerEgressAllowsCidr,
  type ExecutionCapability,
  type JobLimits,
  type PartialJobLimits,
  type ScopeDenialReason,
  type ScopeRule,
  type ScopeTargetType,
} from '@/server/domain/execution';
import { AppError, badRequest, conflict, forbidden, notFound } from '@/server/errors';
import { auditDispatchDenied } from './engagements';
import { isUniqueConstraintError, paginationMeta } from './shared';

/**
 * Controlled execution.
 *
 * The platform does not run offensive tools itself; it is the control plane that
 * decides whether a request for one may leave it. A job is accepted only when
 * all of the following hold at dispatch *and* again at start:
 *
 * - the engagement is ACTIVE and inside its window;
 * - an APPROVED authorization exists and has not expired;
 * - the target matches an inclusion and no exclusion;
 * - a registered worker is isolated, has a live heartbeat, and its egress
 *   allowlist actually covers the target;
 * - for a re-check at start, the DNS answer has not changed since dispatch.
 *
 * A denial is stored as a terminal job with a reason and an audit event. That is
 * deliberate: "we refused to run this" is evidence, and dropping it would leave
 * the most interesting requests out of the record.
 */

const WORKER_HEARTBEAT_TTL_MS = 5 * 60 * 1000;
const REVIEW_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;
const QUEUE_EXPIRY_MS = 24 * 60 * 60 * 1000;

/** Jobs in one of these states still hold a slot against the tenant's cap. */
const ACTIVE_JOB_STATUSES: ExecutionJobStatus[] = ['PENDING_REVIEW', 'QUEUED', 'RUNNING'];

/** Namespace for the dispatch advisory lock; distinct from the quota namespace. */
const EXECUTION_DISPATCH_LOCK_NAMESPACE = 8_210_003;

export interface ExecutionDeps {
  /** Injectable DNS resolver so tests can simulate a rebind without owning DNS. */
  resolve?: (host: string) => Promise<string[]>;
  now?: () => Date;
}

async function defaultResolve(host: string): Promise<string[]> {
  const records = await lookup(host, { all: true, verbatim: true });
  return records.map((record) => record.address);
}

function depsWithDefaults(deps: ExecutionDeps | undefined): Required<ExecutionDeps> {
  return {
    resolve: deps?.resolve ?? defaultResolve,
    now: deps?.now ?? (() => new Date()),
  };
}

const JOB_INCLUDE = {
  requestedBy: { select: { id: true, name: true, email: true } },
  reviewedBy: { select: { id: true, name: true, email: true } },
  cancelledBy: { select: { id: true, name: true, email: true } },
  worker: { select: { id: true, name: true, isolated: true } },
  authorization: { select: { id: true, reference: true, expiresAt: true } },
} satisfies Prisma.ExecutionJobInclude;

type JobRow = Prisma.ExecutionJobGetPayload<{ include: typeof JOB_INCLUDE }>;

export interface ExecutionJobView {
  id: string;
  engagementId: string;
  capability: ExecutionCapability;
  targetType: ScopeTargetType;
  targetValue: string;
  risk: 'LOW' | 'MEDIUM' | 'HIGH';
  status: ExecutionJobStatus;
  reviewStatus: 'NOT_REQUIRED' | 'PENDING' | 'APPROVED' | 'REJECTED';
  approvedAddresses: string[];
  limits: JobLimits;
  denialReason: string | null;
  cancelRequestedAt: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
  requestedBy: { id: string; name: string; email: string };
  reviewedBy: { id: string; name: string; email: string } | null;
  cancelledBy: { id: string; name: string; email: string } | null;
  worker: { id: string; name: string; isolated: boolean } | null;
  authorization: { id: string; reference: string | null; expiresAt: string };
}

export interface ExecutionJobDetail extends ExecutionJobView {
  events: Array<{
    id: string;
    type: string;
    message: string;
    metadata: unknown;
    createdAt: string;
    actor: { id: string; name: string; email: string } | null;
  }>;
}

export interface WorkerView {
  id: string;
  name: string;
  status: 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
  isolated: boolean;
  egressAllowlist: string[];
  attestationRef: string | null;
  lastHeartbeatAt: string | null;
  heartbeatFresh: boolean;
  createdAt: string;
}

function jobLimitsFromJson(value: Prisma.JsonValue): JobLimits {
  const record = (value ?? {}) as Partial<JobLimits>;
  return {
    maxDurationSeconds: Number(record.maxDurationSeconds ?? 0),
    maxRequests: Number(record.maxRequests ?? 0),
    maxBytes: Number(record.maxBytes ?? 0),
    maxConcurrency: Number(record.maxConcurrency ?? 0),
  };
}

function toJobView(row: JobRow): ExecutionJobView {
  return {
    id: row.id,
    engagementId: row.engagementId,
    capability: row.capability as ExecutionCapability,
    targetType: row.targetType,
    targetValue: row.targetValue,
    risk: row.risk,
    status: row.status,
    reviewStatus: row.reviewStatus,
    approvedAddresses: row.approvedAddresses,
    limits: jobLimitsFromJson(row.limits),
    denialReason: row.denialReason,
    cancelRequestedAt: row.cancelRequestedAt?.toISOString() ?? null,
    startedAt: row.startedAt?.toISOString() ?? null,
    finishedAt: row.finishedAt?.toISOString() ?? null,
    createdAt: row.createdAt.toISOString(),
    requestedBy: row.requestedBy,
    reviewedBy: row.reviewedBy,
    cancelledBy: row.cancelledBy,
    worker: row.worker,
    authorization: {
      id: row.authorization.id,
      reference: row.authorization.reference,
      expiresAt: row.authorization.expiresAt.toISOString(),
    },
  };
}

function heartbeatFresh(lastHeartbeatAt: Date | null, now: Date): boolean {
  return (
    lastHeartbeatAt !== null && now.getTime() - lastHeartbeatAt.getTime() <= WORKER_HEARTBEAT_TTL_MS
  );
}

function toWorkerView(
  row: {
    id: string;
    name: string;
    status: 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
    isolated: boolean;
    egressAllowlist: string[];
    attestationRef: string | null;
    lastHeartbeatAt: Date | null;
    createdAt: Date;
  },
  now: Date,
): WorkerView {
  return {
    id: row.id,
    name: row.name,
    status: row.status,
    isolated: row.isolated,
    egressAllowlist: row.egressAllowlist,
    attestationRef: row.attestationRef,
    lastHeartbeatAt: row.lastHeartbeatAt?.toISOString() ?? null,
    heartbeatFresh: heartbeatFresh(row.lastHeartbeatAt, now),
    createdAt: row.createdAt.toISOString(),
  };
}

interface EngagementForDispatch {
  id: string;
  status: 'DRAFT' | 'ACTIVE' | 'PAUSED' | 'CLOSED';
  startsAt: Date;
  endsAt: Date;
  scopeEntries: Array<{ kind: 'INCLUDE' | 'EXCLUDE'; targetType: ScopeTargetType; value: string }>;
  authorizations: Array<{
    id: string;
    status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'REVOKED';
    expiresAt: Date;
    reference: string | null;
  }>;
}

async function loadEngagementForDispatch(
  organizationId: string,
  engagementId: string,
): Promise<EngagementForDispatch> {
  const engagement = await prisma.engagement.findFirst({
    where: { id: engagementId, organizationId },
    select: {
      id: true,
      status: true,
      startsAt: true,
      endsAt: true,
      scopeEntries: { select: { kind: true, targetType: true, value: true } },
      authorizations: {
        where: { status: 'APPROVED' },
        orderBy: { expiresAt: 'desc' },
        select: { id: true, status: true, expiresAt: true, reference: true },
      },
    },
  });
  if (!engagement) {
    throw notFound('The engagement was not found.');
  }
  return engagement;
}

function rulesOf(engagement: EngagementForDispatch): ScopeRule[] {
  return engagement.scopeEntries;
}

async function resolveTargetAddresses(
  targetType: ScopeTargetType,
  targetValue: string,
  resolve: (host: string) => Promise<string[]>,
): Promise<string[]> {
  if (targetType === 'CIDR') {
    return [];
  }
  if (targetType === 'IP_ADDRESS') {
    return [targetValue];
  }
  const host =
    targetType === 'URL' ? new URL(targetValue).hostname.replace(/^\[|\]$/g, '') : targetValue;
  return resolve(host);
}

interface WorkerRow {
  id: string;
  name: string;
  status: 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
  isolated: boolean;
  egressAllowlist: string[];
  lastHeartbeatAt: Date | null;
}

function workerEligible(
  worker: WorkerRow,
  target: { targetType: ScopeTargetType; targetValue: string; addresses: string[] },
  now: Date,
): boolean {
  if (worker.status !== 'ACTIVE' || !worker.isolated) {
    return false;
  }
  if (!heartbeatFresh(worker.lastHeartbeatAt, now)) {
    return false;
  }
  if (target.targetType === 'CIDR') {
    return workerEgressAllowsCidr(worker.egressAllowlist, target.targetValue);
  }
  const host =
    target.targetType === 'URL'
      ? new URL(target.targetValue).hostname.replace(/^\[|\]$/g, '')
      : target.targetValue;
  return workerEgressAllows(worker.egressAllowlist, { host, addresses: target.addresses });
}

async function selectWorker(
  organizationId: string,
  requestedWorkerId: string | undefined,
  target: { targetType: ScopeTargetType; targetValue: string; addresses: string[] },
  now: Date,
): Promise<WorkerRow> {
  if (requestedWorkerId) {
    const worker = await prisma.executionWorker.findFirst({
      where: { id: requestedWorkerId, organizationId },
      select: {
        id: true,
        name: true,
        status: true,
        isolated: true,
        egressAllowlist: true,
        lastHeartbeatAt: true,
      },
    });
    if (!worker) {
      throw notFound('The execution worker was not found.');
    }
    if (!workerEligible(worker, target, now)) {
      throw badRequest(
        'The selected worker is not isolated, has no recent heartbeat, or its egress allowlist does not cover the target.',
      );
    }
    return worker;
  }

  const candidates = await prisma.executionWorker.findMany({
    where: { organizationId, status: 'ACTIVE', isolated: true },
    orderBy: [{ lastHeartbeatAt: 'desc' }, { name: 'asc' }],
    select: {
      id: true,
      name: true,
      status: true,
      isolated: true,
      egressAllowlist: true,
      lastHeartbeatAt: true,
    },
  });
  const eligible = candidates.find((worker) => workerEligible(worker, target, now));
  if (!eligible) {
    throw badRequest('No eligible execution worker can reach that target.');
  }
  return eligible;
}

async function appendEvent(
  tx: Prisma.TransactionClient,
  input: {
    organizationId: string;
    jobId: string;
    type:
      | 'REQUESTED'
      | 'REVIEW_REQUESTED'
      | 'REVIEW_APPROVED'
      | 'REVIEW_REJECTED'
      | 'DISPATCH_DENIED'
      | 'EXECUTION_DENIED'
      | 'QUEUED'
      | 'STARTED'
      | 'COMPLETED'
      | 'FAILED'
      | 'CANCELLED';
    message: string;
    metadata?: Prisma.InputJsonValue;
    actorId?: string | null;
  },
): Promise<void> {
  await tx.executionJobEvent.create({
    data: {
      organizationId: input.organizationId,
      jobId: input.jobId,
      type: input.type,
      message: input.message,
      ...(input.metadata !== undefined ? { metadata: input.metadata } : {}),
      actorId: input.actorId ?? null,
    },
  });
}

export interface RequestExecutionInput {
  capability: ExecutionCapability;
  targetType: ScopeTargetType;
  targetValue: string;
  workerId?: string;
  limits?: PartialJobLimits;
}

/**
 * Dispatch-time enforcement. Creates the job record first, then evaluates; a
 * failed evaluation leaves a DENIED job instead of an untraceable 403.
 */
export async function requestExecutionJob(
  ctx: TenantContext,
  engagementId: string,
  input: RequestExecutionInput,
  deps?: ExecutionDeps,
): Promise<ExecutionJobView> {
  const { resolve, now } = depsWithDefaults(deps);
  const at = now();

  const engagement = await loadEngagementForDispatch(ctx.organization.id, engagementId);
  const authorization = engagement.authorizations[0] ?? null;

  if (!authorization) {
    const reason: ScopeDenialReason = 'no_authorization';
    await auditDispatchDenied(ctx, engagementId, reason, {
      targetType: input.targetType,
      targetValue: input.targetValue,
    });
    throw forbidden('No approved authorization covers this engagement.');
  }

  let normalizedTarget: string;
  try {
    normalizedTarget = normalizeScopeValue(input.targetType, input.targetValue);
  } catch (error) {
    await auditDispatchDenied(ctx, engagementId, 'invalid_target', {
      targetType: input.targetType,
      targetValue: input.targetValue.slice(0, 200),
    });
    throw badRequest(error instanceof Error ? error.message : 'The target is invalid.');
  }

  const decision = evaluateDispatch({
    now: at,
    engagement: {
      status: engagement.status,
      startsAt: engagement.startsAt,
      endsAt: engagement.endsAt,
    },
    authorization: { status: authorization.status, expiresAt: authorization.expiresAt },
    rules: rulesOf(engagement),
    candidate: { targetType: input.targetType, value: normalizedTarget },
  });

  if (!decision.allowed) {
    const denial = await prisma.$transaction(async (tx) => {
      const job = await tx.executionJob.create({
        data: {
          organizationId: ctx.organization.id,
          engagementId,
          authorizationId: authorization.id,
          capability: input.capability as PrismaCapability,
          targetType: input.targetType,
          targetValue: normalizedTarget,
          requestedById: ctx.user.id,
          risk: riskForCapability(input.capability),
          reviewStatus: 'NOT_REQUIRED',
          status: 'DENIED',
          approvedAddresses: [],
          limits: {},
          denialReason: decision.reason,
          finishedAt: at,
        },
        include: JOB_INCLUDE,
      });
      await appendEvent(tx, {
        organizationId: ctx.organization.id,
        jobId: job.id,
        type: 'DISPATCH_DENIED',
        message: `Dispatch denied: ${decision.reason}`,
        metadata: {
          reason: decision.reason,
          matchedRule: decision.matchedRule,
          targetType: input.targetType,
          targetValue: normalizedTarget,
        },
        actorId: ctx.user.id,
      });
      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.EXECUTION_DISPATCH_DENIED,
        outcome: 'DENIED',
        targetType: 'execution_job',
        targetId: job.id,
        summary: `Denied execution request: ${decision.reason}`,
        metadata: {
          engagementId,
          reason: decision.reason,
          matchedRule: decision.matchedRule,
          targetType: input.targetType,
          targetValue: normalizedTarget,
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });
      return job;
    });
    return toJobView(denial);
  }

  const risk = riskForCapability(input.capability);
  let limits: JobLimits;
  try {
    limits = normalizeJobLimits(risk, input.limits);
  } catch (error) {
    throw badRequest(error instanceof Error ? error.message : 'The job limits are invalid.');
  }

  let addresses: string[];
  try {
    addresses = await resolveTargetAddresses(input.targetType, normalizedTarget, resolve);
  } catch {
    const denial = await createDeniedJob({
      ctx,
      engagementId,
      authorizationId: authorization.id,
      input,
      normalizedTarget,
      normalizedAddresses: [],
      limits,
      reason: 'dns_resolution_failed',
    });
    return denial;
  }

  let worker: WorkerRow;
  try {
    worker = await selectWorker(
      ctx.organization.id,
      input.workerId,
      { targetType: input.targetType, targetValue: normalizedTarget, addresses },
      at,
    );
  } catch (error) {
    // A caller-supplied worker id that does not exist is a request error, not a
    // policy denial. An ineligible worker is a denial and is recorded as one.
    if (error instanceof AppError && error.statusCode === 404) {
      throw error;
    }
    return createDeniedJob({
      ctx,
      engagementId,
      authorizationId: authorization.id,
      input,
      normalizedTarget,
      normalizedAddresses: addresses,
      limits,
      reason: 'no_eligible_worker',
    });
  }

  const reviewRequired = risk === 'HIGH';
  const maxActiveJobs = getMaxActiveExecutionJobs();
  const job = await prisma.$transaction(async (tx) => {
    // The cap is checked under an advisory lock so two concurrent dispatches
    // cannot both read the same free slot and push the tenant over the limit.
    // The lock is transaction-scoped, so it is released when this job is
    // committed (or rolls back).
    await tx.$queryRaw`SELECT 1::int AS locked FROM (SELECT pg_advisory_xact_lock(hashtextextended(${`execution-jobs:${ctx.organization.id}`}, ${EXECUTION_DISPATCH_LOCK_NAMESPACE}))) AS dispatch_lock`;
    const activeJobs = await tx.executionJob.count({
      where: {
        organizationId: ctx.organization.id,
        status: { in: ACTIVE_JOB_STATUSES },
      },
    });
    if (activeJobs >= maxActiveJobs) {
      // A booking error, not a policy denial: nothing is wrong with the target,
      // the tenant is simply at its ceiling. No job row is written for it.
      throw new AppError(
        429,
        'RATE_LIMITED',
        `This organization already has ${activeJobs} execution jobs in flight (limit ${maxActiveJobs}). Wait for one to finish, or cancel one, before dispatching another.`,
        { headers: { 'Retry-After': '60' } },
      );
    }

    const created = await tx.executionJob.create({
      data: {
        organizationId: ctx.organization.id,
        engagementId,
        authorizationId: authorization.id,
        workerId: reviewRequired ? null : worker.id,
        capability: input.capability as PrismaCapability,
        targetType: input.targetType,
        targetValue: normalizedTarget,
        requestedById: ctx.user.id,
        risk,
        reviewStatus: reviewRequired ? 'PENDING' : 'NOT_REQUIRED',
        status: reviewRequired ? 'PENDING_REVIEW' : 'QUEUED',
        approvedAddresses: addresses,
        limits: { ...limits } as Prisma.InputJsonValue,
      },
      include: JOB_INCLUDE,
    });
    await appendEvent(tx, {
      organizationId: ctx.organization.id,
      jobId: created.id,
      type: 'REQUESTED',
      message: `Requested ${input.capability} against ${normalizedTarget}`,
      metadata: {
        targetType: input.targetType,
        targetValue: normalizedTarget,
        risk,
        limits: { ...limits },
      },
      actorId: ctx.user.id,
    });
    if (reviewRequired) {
      await appendEvent(tx, {
        organizationId: ctx.organization.id,
        jobId: created.id,
        type: 'REVIEW_REQUESTED',
        message: 'High-risk capability requires human review before dispatch',
        actorId: ctx.user.id,
      });
    } else {
      await appendEvent(tx, {
        organizationId: ctx.organization.id,
        jobId: created.id,
        type: 'QUEUED',
        message: `Queued on worker ${worker.name} with ${addresses.length} approved address(es)`,
        metadata: { workerId: worker.id, addresses },
        actorId: ctx.user.id,
      });
    }
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: reviewRequired ? AuditActions.EXECUTION_REQUESTED : AuditActions.EXECUTION_QUEUED,
      outcome: 'SUCCESS',
      targetType: 'execution_job',
      targetId: created.id,
      summary: reviewRequired
        ? `Requested review for ${input.capability} against ${normalizedTarget}`
        : `Queued ${input.capability} against ${normalizedTarget}`,
      metadata: {
        engagementId,
        capability: input.capability,
        risk,
        targetType: input.targetType,
        targetValue: normalizedTarget,
        workerId: reviewRequired ? null : worker.id,
        matchedRule: decision.matchedRule,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
    return created;
  });

  return toJobView(job);
}

async function createDeniedJob(input: {
  ctx: TenantContext;
  engagementId: string;
  authorizationId: string;
  input: RequestExecutionInput;
  normalizedTarget: string;
  normalizedAddresses: string[];
  limits: JobLimits;
  reason: ScopeDenialReason;
}): Promise<ExecutionJobView> {
  const { ctx } = input;
  const job = await prisma.$transaction(async (tx) => {
    const created = await tx.executionJob.create({
      data: {
        organizationId: ctx.organization.id,
        engagementId: input.engagementId,
        authorizationId: input.authorizationId,
        capability: input.input.capability as PrismaCapability,
        targetType: input.input.targetType,
        targetValue: input.normalizedTarget,
        requestedById: ctx.user.id,
        risk: riskForCapability(input.input.capability),
        reviewStatus: 'NOT_REQUIRED',
        status: 'DENIED',
        approvedAddresses: input.normalizedAddresses,
        limits: { ...input.limits } as Prisma.InputJsonValue,
        denialReason: input.reason,
        finishedAt: new Date(),
      },
      include: JOB_INCLUDE,
    });
    await appendEvent(tx, {
      organizationId: ctx.organization.id,
      jobId: created.id,
      type: 'DISPATCH_DENIED',
      message: `Dispatch denied: ${input.reason}`,
      metadata: {
        reason: input.reason,
        targetType: input.input.targetType,
        targetValue: input.normalizedTarget,
      },
      actorId: ctx.user.id,
    });
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.EXECUTION_DISPATCH_DENIED,
      outcome: 'DENIED',
      targetType: 'execution_job',
      targetId: created.id,
      summary: `Denied execution request: ${input.reason}`,
      metadata: {
        engagementId: input.engagementId,
        reason: input.reason,
        targetType: input.input.targetType,
        targetValue: input.normalizedTarget,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
    return created;
  });
  return toJobView(job);
}

async function loadJob(organizationId: string, jobId: string): Promise<JobRow> {
  const job = await prisma.executionJob.findFirst({
    where: { id: jobId, organizationId },
    include: JOB_INCLUDE,
  });
  if (!job) {
    throw notFound('The execution job was not found.');
  }
  return job;
}

export async function getExecutionJob(
  organizationId: string,
  jobId: string,
): Promise<ExecutionJobDetail> {
  const job = await loadJob(organizationId, jobId);
  const events = await prisma.executionJobEvent.findMany({
    where: { jobId, organizationId },
    orderBy: { createdAt: 'asc' },
    select: {
      id: true,
      type: true,
      message: true,
      metadata: true,
      createdAt: true,
      actor: { select: { id: true, name: true, email: true } },
    },
  });
  return {
    ...toJobView(job),
    events: events.map((event) => ({
      id: event.id,
      type: event.type,
      message: event.message,
      metadata: event.metadata,
      createdAt: event.createdAt.toISOString(),
      actor: event.actor,
    })),
  };
}

export async function listExecutionJobs(
  organizationId: string,
  query: { engagementId?: string; status?: ExecutionJobStatus; page: number; pageSize: number },
): Promise<{ items: ExecutionJobView[]; pagination: ReturnType<typeof paginationMeta> }> {
  const where: Prisma.ExecutionJobWhereInput = {
    organizationId,
    ...(query.engagementId ? { engagementId: query.engagementId } : {}),
    ...(query.status ? { status: query.status } : {}),
  };
  const [rows, total] = await prisma.$transaction([
    prisma.executionJob.findMany({
      where,
      include: JOB_INCLUDE,
      orderBy: { createdAt: 'desc' },
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
    prisma.executionJob.count({ where }),
  ]);
  return {
    items: rows.map(toJobView),
    pagination: paginationMeta(query.page, query.pageSize, total),
  };
}

/**
 * Human review. The reviewer cannot be the requester, and approval re-runs the
 * full dispatch check because an authorization may have expired while the job
 * waited.
 */
export async function reviewExecutionJob(
  ctx: TenantContext,
  jobId: string,
  input: { decision: 'APPROVED' | 'REJECTED'; note?: string | null },
  deps?: ExecutionDeps,
): Promise<ExecutionJobView> {
  const { resolve, now } = depsWithDefaults(deps);
  const at = now();
  const job = await loadJob(ctx.organization.id, jobId);

  if (job.status !== 'PENDING_REVIEW' || job.reviewStatus !== 'PENDING') {
    throw conflict('This job is not awaiting review.');
  }
  if (job.requestedById === ctx.user.id) {
    throw forbidden('The person who requested a job cannot review it.');
  }

  if (input.decision === 'REJECTED') {
    const rejected = await prisma.$transaction(async (tx) => {
      const updated = await tx.executionJob.update({
        where: { id: jobId },
        data: {
          status: 'DENIED',
          reviewStatus: 'REJECTED',
          reviewedById: ctx.user.id,
          reviewedAt: at,
          denialReason: 'review_rejected',
          finishedAt: at,
        },
        include: JOB_INCLUDE,
      });
      await appendEvent(tx, {
        organizationId: ctx.organization.id,
        jobId,
        type: 'REVIEW_REJECTED',
        message: 'Human review rejected the request',
        metadata: { note: input.note ?? null },
        actorId: ctx.user.id,
      });
      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.EXECUTION_REVIEW_REJECTED,
        outcome: 'DENIED',
        targetType: 'execution_job',
        targetId: jobId,
        summary: 'Rejected a high-risk execution request',
        metadata: { note: input.note ?? null },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });
      return updated;
    });
    return toJobView(rejected);
  }

  const engagement = await loadEngagementForDispatch(ctx.organization.id, job.engagementId);
  const authorization =
    engagement.authorizations.find((entry) => entry.id === job.authorizationId) ??
    engagement.authorizations[0] ??
    null;
  const decision = evaluateDispatch({
    now: at,
    engagement: {
      status: engagement.status,
      startsAt: engagement.startsAt,
      endsAt: engagement.endsAt,
    },
    authorization: authorization
      ? { status: authorization.status, expiresAt: authorization.expiresAt }
      : null,
    rules: rulesOf(engagement),
    candidate: { targetType: job.targetType, value: job.targetValue },
  });
  if (!decision.allowed) {
    const denied = await prisma.$transaction(async (tx) => {
      const updated = await tx.executionJob.update({
        where: { id: jobId },
        data: {
          status: 'DENIED',
          reviewStatus: 'APPROVED',
          reviewedById: ctx.user.id,
          reviewedAt: at,
          denialReason: decision.reason,
          finishedAt: at,
        },
        include: JOB_INCLUDE,
      });
      await appendEvent(tx, {
        organizationId: ctx.organization.id,
        jobId,
        type: 'EXECUTION_DENIED',
        message: `Review approved, but dispatch re-check failed: ${decision.reason}`,
        metadata: { reason: decision.reason, matchedRule: decision.matchedRule },
        actorId: ctx.user.id,
      });
      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.EXECUTION_EXECUTION_DENIED,
        outcome: 'DENIED',
        targetType: 'execution_job',
        targetId: jobId,
        summary: `Denied reviewed execution request: ${decision.reason}`,
        metadata: { reason: decision.reason },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });
      return updated;
    });
    return toJobView(denied);
  }

  let addresses: string[];
  try {
    addresses = await resolveTargetAddresses(job.targetType, job.targetValue, resolve);
  } catch {
    const denied = await prisma.$transaction(async (tx) => {
      const updated = await tx.executionJob.update({
        where: { id: jobId },
        data: {
          status: 'DENIED',
          reviewStatus: 'APPROVED',
          reviewedById: ctx.user.id,
          reviewedAt: at,
          denialReason: 'dns_resolution_failed',
          finishedAt: at,
        },
        include: JOB_INCLUDE,
      });
      await appendEvent(tx, {
        organizationId: ctx.organization.id,
        jobId,
        type: 'EXECUTION_DENIED',
        message: 'Review approved, but DNS resolution failed',
        actorId: ctx.user.id,
      });
      return updated;
    });
    return toJobView(denied);
  }

  if (addressSetsDiffer(job.approvedAddresses, addresses) && job.targetType !== 'CIDR') {
    const denied = await prisma.$transaction(async (tx) => {
      const updated = await tx.executionJob.update({
        where: { id: jobId },
        data: {
          status: 'DENIED',
          reviewStatus: 'APPROVED',
          reviewedById: ctx.user.id,
          reviewedAt: at,
          denialReason: 'address_changed',
          finishedAt: at,
        },
        include: JOB_INCLUDE,
      });
      await appendEvent(tx, {
        organizationId: ctx.organization.id,
        jobId,
        type: 'EXECUTION_DENIED',
        message: 'Review approved, but the DNS answer changed since dispatch',
        metadata: { approved: job.approvedAddresses, observed: addresses },
        actorId: ctx.user.id,
      });
      return updated;
    });
    return toJobView(denied);
  }

  const worker = await selectWorker(
    ctx.organization.id,
    job.workerId ?? undefined,
    { targetType: job.targetType, targetValue: job.targetValue, addresses },
    at,
  );

  const queued = await prisma.$transaction(async (tx) => {
    const updated = await tx.executionJob.update({
      where: { id: jobId },
      data: {
        status: 'QUEUED',
        reviewStatus: 'APPROVED',
        reviewedById: ctx.user.id,
        reviewedAt: at,
        workerId: worker.id,
        approvedAddresses: addresses,
      },
      include: JOB_INCLUDE,
    });
    await appendEvent(tx, {
      organizationId: ctx.organization.id,
      jobId,
      type: 'REVIEW_APPROVED',
      message: 'Human review approved the request',
      metadata: { note: input.note ?? null },
      actorId: ctx.user.id,
    });
    await appendEvent(tx, {
      organizationId: ctx.organization.id,
      jobId,
      type: 'QUEUED',
      message: `Queued on worker ${worker.name}`,
      metadata: { workerId: worker.id, addresses },
      actorId: ctx.user.id,
    });
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.EXECUTION_REVIEW_APPROVED,
      outcome: 'SUCCESS',
      targetType: 'execution_job',
      targetId: jobId,
      summary: 'Approved a high-risk execution request',
      metadata: { note: input.note ?? null, workerId: worker.id },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
    return updated;
  });

  return toJobView(queued);
}

/**
 * Execution-time enforcement. Everything checked at dispatch is checked again,
 * and the DNS answer must still match the approved set. A mismatch is a denial,
 * not a warning: a rebind between approval and connect is the exact attack this
 * control exists to stop.
 */
export async function startExecutionJob(
  ctx: TenantContext,
  jobId: string,
  deps?: ExecutionDeps,
): Promise<ExecutionJobView> {
  const { resolve, now } = depsWithDefaults(deps);
  const at = now();
  const job = await loadJob(ctx.organization.id, jobId);

  if (job.status === 'CANCELLED') {
    return toJobView(job);
  }
  if (job.status !== 'QUEUED') {
    throw conflict('Only a queued job can start.');
  }
  if (job.cancelRequestedAt) {
    const cancelled = await prisma.$transaction(async (tx) => {
      const updated = await tx.executionJob.update({
        where: { id: jobId },
        data: { status: 'CANCELLED', finishedAt: at },
        include: JOB_INCLUDE,
      });
      await appendEvent(tx, {
        organizationId: ctx.organization.id,
        jobId,
        type: 'CANCELLED',
        message: 'Cancelled before start',
        actorId: ctx.user.id,
      });
      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.EXECUTION_CANCELLED,
        outcome: 'SUCCESS',
        targetType: 'execution_job',
        targetId: jobId,
        summary: 'Cancelled a queued job before execution started',
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });
      return updated;
    });
    return toJobView(cancelled);
  }

  const engagement = await loadEngagementForDispatch(ctx.organization.id, job.engagementId);
  const authorization =
    engagement.authorizations.find((entry) => entry.id === job.authorizationId) ?? null;
  const decision = evaluateDispatch({
    now: at,
    engagement: {
      status: engagement.status,
      startsAt: engagement.startsAt,
      endsAt: engagement.endsAt,
    },
    authorization: authorization
      ? { status: authorization.status, expiresAt: authorization.expiresAt }
      : null,
    rules: rulesOf(engagement),
    candidate: { targetType: job.targetType, value: job.targetValue },
  });
  if (!decision.allowed) {
    return denyQueuedJob(ctx, job, decision.reason, decision.matchedRule, at);
  }

  let addresses: string[];
  try {
    addresses = await resolveTargetAddresses(job.targetType, job.targetValue, resolve);
  } catch {
    return denyQueuedJob(ctx, job, 'dns_resolution_failed', null, at);
  }

  if (job.targetType !== 'CIDR' && addressSetsDiffer(job.approvedAddresses, addresses)) {
    return denyQueuedJob(ctx, job, 'address_changed', null, at, {
      approved: job.approvedAddresses,
      observed: addresses,
    });
  }

  const worker = job.workerId
    ? await prisma.executionWorker.findFirst({ where: { id: job.workerId } })
    : null;
  if (
    !worker ||
    !workerEligible(
      worker,
      { targetType: job.targetType, targetValue: job.targetValue, addresses },
      at,
    )
  ) {
    return denyQueuedJob(ctx, job, 'no_eligible_worker', null, at);
  }

  const started = await prisma.$transaction(async (tx) => {
    const updated = await tx.executionJob.update({
      where: { id: jobId },
      data: { status: 'RUNNING', startedAt: at },
      include: JOB_INCLUDE,
    });
    await appendEvent(tx, {
      organizationId: ctx.organization.id,
      jobId,
      type: 'STARTED',
      message: `Started with ${addresses.length} verified address(es)`,
      metadata: { addresses, workerId: worker.id },
      actorId: ctx.user.id,
    });
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.EXECUTION_STARTED,
      outcome: 'SUCCESS',
      targetType: 'execution_job',
      targetId: jobId,
      summary: `Started ${job.capability} against ${job.targetValue}`,
      metadata: {
        engagementId: job.engagementId,
        addresses,
        workerId: worker.id,
        matchedRule: decision.matchedRule,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
    return updated;
  });
  return toJobView(started);
}

async function denyQueuedJob(
  ctx: TenantContext,
  job: JobRow,
  reason: ScopeDenialReason,
  matchedRule: string | null,
  at: Date,
  extra?: Record<string, unknown>,
): Promise<ExecutionJobView> {
  const denied = await prisma.$transaction(async (tx) => {
    const updated = await tx.executionJob.update({
      where: { id: job.id },
      data: { status: 'DENIED', denialReason: reason, finishedAt: at },
      include: JOB_INCLUDE,
    });
    await appendEvent(tx, {
      organizationId: ctx.organization.id,
      jobId: job.id,
      type: 'EXECUTION_DENIED',
      message: describeDenial(reason),
      metadata: { reason, matchedRule, ...(extra ?? {}) },
      actorId: ctx.user.id,
    });
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.EXECUTION_EXECUTION_DENIED,
      outcome: 'DENIED',
      targetType: 'execution_job',
      targetId: job.id,
      summary: `Denied execution start: ${describeDenial(reason)}`,
      metadata: {
        engagementId: job.engagementId,
        reason,
        matchedRule,
        targetType: job.targetType,
        targetValue: job.targetValue,
        ...(extra ?? {}),
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
    return updated;
  });
  return toJobView(denied);
}

/**
 * Completion. A cancellation requested while the job was running wins over a
 * successful report, and a job that outlived its duration limit is a failure
 * even if the worker called it a success.
 */
export async function completeExecutionJob(
  ctx: TenantContext,
  jobId: string,
  input: { outcome: 'SUCCEEDED' | 'FAILED'; summary?: string | null },
  deps?: ExecutionDeps,
): Promise<ExecutionJobView> {
  const { now } = depsWithDefaults(deps);
  const at = now();
  const job = await loadJob(ctx.organization.id, jobId);

  if (job.status === 'CANCELLED') {
    return toJobView(job);
  }
  if (job.status !== 'RUNNING') {
    throw conflict('Only a running job can be completed.');
  }

  const limits = jobLimitsFromJson(job.limits);
  const cancelled = job.cancelRequestedAt !== null;
  const overLimit = job.startedAt !== null && durationLimitExceeded(job.startedAt, at, limits);
  const finalStatus = cancelled ? 'CANCELLED' : overLimit ? 'FAILED' : input.outcome;
  const reason = cancelled ? 'cancelled' : overLimit ? 'duration_limit_exceeded' : null;

  const completed = await prisma.$transaction(async (tx) => {
    const updated = await tx.executionJob.update({
      where: { id: jobId },
      data: {
        status: finalStatus,
        finishedAt: at,
        ...(reason ? { denialReason: reason } : {}),
      },
      include: JOB_INCLUDE,
    });
    await appendEvent(tx, {
      organizationId: ctx.organization.id,
      jobId,
      type:
        finalStatus === 'SUCCEEDED'
          ? 'COMPLETED'
          : finalStatus === 'FAILED'
            ? 'FAILED'
            : 'CANCELLED',
      message:
        finalStatus === 'CANCELLED'
          ? 'Job stopped after a cancellation request'
          : finalStatus === 'FAILED'
            ? overLimit
              ? 'Job failed: duration limit exceeded'
              : 'Job failed'
            : 'Job completed',
      metadata: {
        reportedOutcome: input.outcome,
        summary: input.summary ?? null,
        ...(overLimit ? { maxDurationSeconds: limits.maxDurationSeconds } : {}),
      },
      actorId: ctx.user.id,
    });
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action:
        finalStatus === 'SUCCEEDED'
          ? AuditActions.EXECUTION_COMPLETED
          : finalStatus === 'FAILED'
            ? AuditActions.EXECUTION_FAILED
            : AuditActions.EXECUTION_CANCELLED,
      outcome:
        finalStatus === 'SUCCEEDED' ? 'SUCCESS' : finalStatus === 'FAILED' ? 'FAILURE' : 'SUCCESS',
      targetType: 'execution_job',
      targetId: jobId,
      summary: `Job finished as ${finalStatus}`,
      metadata: {
        reportedOutcome: input.outcome,
        reason,
        durationMs: job.startedAt ? at.getTime() - job.startedAt.getTime() : null,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
    return updated;
  });

  return toJobView(completed);
}

export async function cancelExecutionJob(
  ctx: TenantContext,
  jobId: string,
  input: { reason: string },
  deps?: ExecutionDeps,
): Promise<ExecutionJobView> {
  const { now } = depsWithDefaults(deps);
  const at = now();
  const job = await loadJob(ctx.organization.id, jobId);

  const role: OrgRole = ctx.membership.role;
  if (!isAtLeast(role, 'ADMIN') && job.requestedById !== ctx.user.id) {
    throw forbidden('Only an administrator can cancel another member’s job.');
  }

  if (job.status === 'CANCELLED') {
    return toJobView(job);
  }
  if (['SUCCEEDED', 'FAILED', 'DENIED'].includes(job.status)) {
    throw conflict('A finished job cannot be cancelled.');
  }
  // A second request while the first is still pending is a retry, not a new
  // decision. Returning the existing request keeps the original timestamp and
  // avoids a second audit entry that would imply two separate stop orders.
  if (job.cancelRequestedAt !== null) {
    return toJobView(job);
  }

  const running = job.status === 'RUNNING';
  const finalStatus = running ? job.status : 'CANCELLED';

  const cancelled = await prisma.$transaction(async (tx) => {
    const updated = await tx.executionJob.update({
      where: { id: jobId },
      data: {
        status: finalStatus,
        cancelRequestedAt: at,
        cancelledById: ctx.user.id,
        ...(running ? {} : { finishedAt: at, denialReason: 'cancelled' }),
      },
      include: JOB_INCLUDE,
    });
    await appendEvent(tx, {
      organizationId: ctx.organization.id,
      jobId,
      type: 'CANCELLED',
      message: running
        ? 'Cancellation requested; the worker must stop and report'
        : 'Job cancelled before execution',
      metadata: { reason: input.reason },
      actorId: ctx.user.id,
    });
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.EXECUTION_CANCELLED,
      outcome: 'SUCCESS',
      targetType: 'execution_job',
      targetId: jobId,
      summary: running ? 'Requested cancellation of a running job' : 'Cancelled a queued job',
      metadata: { reason: input.reason, previousStatus: job.status },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
    return updated;
  });

  return toJobView(cancelled);
}

export interface ExecutionCleanupSummary {
  expiredReviews: number;
  staleQueues: number;
  abandonedRuns: number;
}

/**
 * Cleanup for jobs that can no longer make progress: a review that sat undecided
 * for a week, a queued job older than a day, and a running job that never
 * reported back after twice its duration limit. Each is closed with a reason so
 * it cannot be mistaken for a job that is still live.
 */
export async function cleanupExecutionJobs(
  organizationId: string,
  now = new Date(),
): Promise<ExecutionCleanupSummary> {
  const reviewCutoff = new Date(now.getTime() - REVIEW_EXPIRY_MS);
  const queueCutoff = new Date(now.getTime() - QUEUE_EXPIRY_MS);

  const expiredReviews = await prisma.executionJob.updateMany({
    where: { organizationId, status: 'PENDING_REVIEW', createdAt: { lt: reviewCutoff } },
    data: { status: 'DENIED', denialReason: 'review_expired', finishedAt: now },
  });
  const staleQueues = await prisma.executionJob.updateMany({
    where: { organizationId, status: 'QUEUED', createdAt: { lt: queueCutoff } },
    data: { status: 'CANCELLED', denialReason: 'lease_expired', finishedAt: now },
  });

  const running = await prisma.executionJob.findMany({
    where: { organizationId, status: 'RUNNING' },
    select: { id: true, startedAt: true, limits: true },
  });
  let abandonedRuns = 0;
  for (const job of running) {
    const limits = jobLimitsFromJson(job.limits);
    if (
      job.startedAt &&
      now.getTime() - job.startedAt.getTime() > limits.maxDurationSeconds * 2 * 1000
    ) {
      await prisma.executionJob.update({
        where: { id: job.id },
        data: { status: 'FAILED', denialReason: 'lease_expired', finishedAt: now },
      });
      abandonedRuns += 1;
    }
  }

  if (expiredReviews.count + staleQueues.count + abandonedRuns > 0) {
    await recordAuditEvent({
      organizationId,
      actorType: 'SYSTEM',
      actorId: null,
      action: AuditActions.EXECUTION_CANCELLED,
      outcome: 'SUCCESS',
      targetType: 'organization',
      targetId: organizationId,
      summary: 'Closed execution jobs that could no longer make progress',
      metadata: {
        expiredReviews: expiredReviews.count,
        staleQueues: staleQueues.count,
        abandonedRuns,
      },
    });
  }

  return {
    expiredReviews: expiredReviews.count,
    staleQueues: staleQueues.count,
    abandonedRuns,
  };
}

export async function listExecutionWorkers(
  organizationId: string,
  query: { status?: 'ACTIVE' | 'SUSPENDED' | 'RETIRED'; page: number; pageSize: number },
  now = new Date(),
): Promise<{ items: WorkerView[]; pagination: ReturnType<typeof paginationMeta> }> {
  const where: Prisma.ExecutionWorkerWhereInput = {
    organizationId,
    ...(query.status ? { status: query.status } : {}),
  };
  const [rows, total] = await prisma.$transaction([
    prisma.executionWorker.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
    prisma.executionWorker.count({ where }),
  ]);
  return {
    items: rows.map((row) => toWorkerView(row, now)),
    pagination: paginationMeta(query.page, query.pageSize, total),
  };
}

export async function registerExecutionWorker(
  ctx: TenantContext,
  input: {
    name: string;
    isolated: boolean;
    egressAllowlist: string[];
    attestationRef?: string | null;
  },
): Promise<WorkerView> {
  // Registration is only useful with an isolation claim and a non-empty
  // allowlist; accepting either as optional would create a worker that cannot
  // legally be selected, or worse, one that could reach everything.
  if (!input.isolated) {
    throw badRequest('A worker must be isolated before it can be registered.');
  }
  if (input.egressAllowlist.length === 0) {
    throw badRequest('A worker must declare a non-empty egress allowlist.');
  }

  try {
    const worker = await prisma.$transaction(async (tx) => {
      const created = await tx.executionWorker.create({
        data: {
          organizationId: ctx.organization.id,
          name: input.name,
          isolated: input.isolated,
          egressAllowlist: input.egressAllowlist,
          attestationRef: input.attestationRef ?? null,
          createdById: ctx.user.id,
        },
      });
      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.EXECUTION_WORKER_REGISTERED,
        outcome: 'SUCCESS',
        targetType: 'execution_worker',
        targetId: created.id,
        summary: `Registered execution worker "${created.name}"`,
        metadata: {
          isolated: created.isolated,
          egressEntries: created.egressAllowlist.length,
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });
      return created;
    });
    return toWorkerView(worker, new Date());
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict('A worker with that name already exists.');
    }
    throw error;
  }
}

export async function updateExecutionWorker(
  ctx: TenantContext,
  workerId: string,
  input: {
    status?: 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
    isolated?: boolean;
    egressAllowlist?: string[];
    attestationRef?: string | null;
    heartbeat?: boolean;
  },
): Promise<WorkerView> {
  const worker = await prisma.executionWorker.findFirst({
    where: { id: workerId, organizationId: ctx.organization.id },
  });
  if (!worker) {
    throw notFound('The execution worker was not found.');
  }
  if (worker.status === 'RETIRED') {
    throw conflict('A retired worker cannot be changed.');
  }
  if (input.isolated === false) {
    throw badRequest('A registered worker cannot be made non-isolated.');
  }
  if (input.egressAllowlist !== undefined && input.egressAllowlist.length === 0) {
    throw badRequest('A worker must keep at least one egress destination.');
  }

  const now = new Date();
  const updated = await prisma.$transaction(async (tx) => {
    const row = await tx.executionWorker.update({
      where: { id: workerId },
      data: {
        ...(input.status !== undefined ? { status: input.status } : {}),
        ...(input.isolated !== undefined ? { isolated: input.isolated } : {}),
        ...(input.egressAllowlist !== undefined ? { egressAllowlist: input.egressAllowlist } : {}),
        ...(input.attestationRef !== undefined ? { attestationRef: input.attestationRef } : {}),
        ...(input.heartbeat ? { lastHeartbeatAt: now } : {}),
      },
    });
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.EXECUTION_WORKER_UPDATED,
      outcome: 'SUCCESS',
      targetType: 'execution_worker',
      targetId: workerId,
      summary: input.heartbeat
        ? 'Recorded a worker heartbeat'
        : `Updated execution worker "${row.name}"`,
      metadata: {
        status: input.status ?? null,
        heartbeat: input.heartbeat === true,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
    return row;
  });

  return toWorkerView(updated, now);
}
