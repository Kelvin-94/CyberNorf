import { Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import { can, type OrgRole } from '@/server/authz/roles';
import { badRequest, forbidden } from '@/server/errors';
import type { RequestMeta } from '@/server/http/request-meta';

/**
 * Data lifecycle for one organization.
 *
 * Retention is deliberately limited to derived operational history: agent runs,
 * delivered or failed alert deliveries, and software inventory reported by agents that
 * stopped reporting. Findings, incidents, assets and compliance evidence are
 * business records with their own decision to keep or close, so they are never
 * removed by a timer — an operator closes them, and the export script takes
 * them out of the platform when that is the right call.
 *
 * Audit events are append-only by database trigger and have no retention here:
 * shortening that history would defeat the point of the chain, so it is a
 * database-level decision with its own backup story, not a scheduled job.
 *
 * Every purge writes `retention.purged` with the cutoff and the exact counts it
 * removed, so a later question about missing runs has an answer in the chain.
 */

export interface RetentionOptions {
  /** Age in days after which derived history is removed. */
  days: number;
  /** Injectable clock for tests. */
  now?: Date;
}

export interface RetentionSummary {
  cutoff: string;
  runs: number;
  notificationEvents: number;
  softwareItems: number;
}

const TERMINAL_NOTIFICATION_STATUSES = ['SENT', 'FAILED'] as const;

export function retentionCutoff(options: RetentionOptions): Date {
  const now = options.now ?? new Date();
  if (!Number.isFinite(options.days) || options.days < 1) {
    throw new Error('Retention days must be a positive integer.');
  }
  return new Date(now.getTime() - options.days * 24 * 60 * 60 * 1000);
}

/** Counts what a purge would remove, without touching anything. */
export async function planRetention(
  organizationId: string,
  options: RetentionOptions,
): Promise<RetentionSummary> {
  const cutoff = retentionCutoff(options);
  const [runs, notificationEvents, softwareItems] = await Promise.all([
    prisma.agentRun.count({ where: { organizationId, startedAt: { lt: cutoff } } }),
    prisma.notificationEvent.count({
      where: {
        organizationId,
        status: { in: [...TERMINAL_NOTIFICATION_STATUSES] },
        createdAt: { lt: cutoff },
      },
    }),
    prisma.softwareItem.count({ where: { organizationId, lastSeenAt: { lt: cutoff } } }),
  ]);

  return { cutoff: cutoff.toISOString(), runs, notificationEvents, softwareItems };
}

/** Removes the derivable history older than the cutoff and records the purge. */
export async function purgeRetention(
  organizationId: string,
  options: RetentionOptions,
  meta: RequestMeta,
): Promise<RetentionSummary> {
  const cutoff = retentionCutoff(options);

  return prisma.$transaction(async (tx) => {
    const removedRuns = await tx.agentRun.deleteMany({
      where: { organizationId, startedAt: { lt: cutoff } },
    });
    const removedNotifications = await tx.notificationEvent.deleteMany({
      where: {
        organizationId,
        status: { in: [...TERMINAL_NOTIFICATION_STATUSES] },
        createdAt: { lt: cutoff },
      },
    });
    // A software inventory row is only stale when its agent stopped reporting; an
    // agent that keeps reporting refreshes `lastSeenAt` on every run.
    const removedItems = await tx.softwareItem.deleteMany({
      where: { organizationId, lastSeenAt: { lt: cutoff } },
    });

    const summary: RetentionSummary = {
      cutoff: cutoff.toISOString(),
      runs: removedRuns.count,
      notificationEvents: removedNotifications.count,
      softwareItems: removedItems.count,
    };

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'SYSTEM',
      actorId: null,
      action: AuditActions.RETENTION_PURGED,
      outcome: 'SUCCESS',
      targetType: 'organization',
      targetId: organizationId,
      summary: `Purged history older than ${cutoff.toISOString().slice(0, 10)} (${summary.runs} runs, ${summary.notificationEvents} alert deliveries, ${summary.softwareItems} software inventory rows)`,
      metadata: { days: options.days, ...summary },
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      requestId: meta.requestId,
    });

    return summary;
  });
}

/** Removes rate-limit windows that can no longer be counted; safe to run at any time. */
export async function pruneRateLimitWindows(olderThanHours = 24): Promise<number> {
  const cutoff = new Date(Date.now() - olderThanHours * 60 * 60 * 1000);
  const result =
    await prisma.$executeRaw`DELETE FROM api_rate_limits WHERE "updatedAt" < ${cutoff}`;
  return Number(result);
}

// ---------------------------------------------------------------------------
// Tenant-configurable retention policy (Phase 5)
// ---------------------------------------------------------------------------

/**
 * The single-window `planRetention`/`purgeRetention` calls above are what the
 * scheduled script uses. Enterprises need per-category windows instead: alert
 * deliveries are cheap to lose, software inventory describes the estate and is
 * kept longer, and execution history is evidence of what the platform ran. Each
 * category therefore gets its own window, stored per tenant.
 *
 * Two invariants keep this honest:
 *
 * 1. Every window has a floor. A tenant may keep data longer than the default,
 *    but cannot set "delete in one day" and then claim the platform kept the
 *    record. The floor is a product decision, not a per-tenant one.
 * 2. Only derived operational history is in scope. Audit events stay
 *    append-only and are never deleted here; the chain is the record of the
 *    purge itself.
 */

export const RETENTION_CATEGORIES = [
  'agentRunDays',
  'notificationEventDays',
  'softwareItemDays',
  'executionJobDays',
] as const;

export type RetentionCategory = (typeof RETENTION_CATEGORIES)[number];

export interface RetentionPolicy {
  agentRunDays: number;
  notificationEventDays: number;
  softwareItemDays: number;
  executionJobDays: number;
}

export const RETENTION_POLICY_BOUNDS = {
  minDays: 7,
  maxDays: 2555,
} as const;

export const DEFAULT_RETENTION_POLICY: Readonly<RetentionPolicy> = {
  agentRunDays: 90,
  notificationEventDays: 90,
  softwareItemDays: 180,
  executionJobDays: 180,
};

export interface EffectiveRetentionPolicy {
  policy: RetentionPolicy;
  /** False when the tenant has never changed the defaults. */
  customised: boolean;
  updatedAt: string | null;
  updatedBy: { id: string; name: string } | null;
}

export interface RetentionPolicyPlan {
  policy: RetentionPolicy;
  cutoffs: Record<RetentionCategory, string>;
  counts: {
    runs: number;
    notificationEvents: number;
    softwareItems: number;
    executionJobs: number;
  };
}

const TERMINAL_JOB_STATUSES = ['SUCCEEDED', 'FAILED', 'DENIED', 'CANCELLED'] as const;

function assertPolicyValue(category: RetentionCategory, days: number): void {
  if (!Number.isInteger(days)) {
    throw badRequest(`${category} must be a whole number of days.`);
  }
  if (days < RETENTION_POLICY_BOUNDS.minDays || days > RETENTION_POLICY_BOUNDS.maxDays) {
    throw badRequest(
      `${category} must be between ${RETENTION_POLICY_BOUNDS.minDays} and ${RETENTION_POLICY_BOUNDS.maxDays} days.`,
    );
  }
}

/** Throws when any window is outside the supported range. */
export function normaliseRetentionPolicy(input: Partial<RetentionPolicy>): RetentionPolicy {
  const policy: RetentionPolicy = { ...DEFAULT_RETENTION_POLICY, ...input };
  for (const category of RETENTION_CATEGORIES) {
    assertPolicyValue(category, policy[category]);
  }
  return policy;
}

export async function getRetentionPolicy(
  organizationId: string,
): Promise<EffectiveRetentionPolicy> {
  const stored = await prisma.organizationRetentionPolicy.findUnique({
    where: { organizationId },
    include: { updatedBy: { select: { id: true, name: true } } },
  });
  if (!stored) {
    return {
      policy: { ...DEFAULT_RETENTION_POLICY },
      customised: false,
      updatedAt: null,
      updatedBy: null,
    };
  }
  return {
    policy: {
      agentRunDays: stored.agentRunDays,
      notificationEventDays: stored.notificationEventDays,
      softwareItemDays: stored.softwareItemDays,
      executionJobDays: stored.executionJobDays,
    },
    customised: true,
    updatedAt: stored.updatedAt.toISOString(),
    updatedBy: stored.updatedBy ? { id: stored.updatedBy.id, name: stored.updatedBy.name } : null,
  };
}

export async function updateRetentionPolicy(
  ctx: { organization: { id: string }; user: { id: string }; meta: RequestMeta },
  input: RetentionPolicy,
): Promise<EffectiveRetentionPolicy> {
  const policy = normaliseRetentionPolicy(input);
  const organizationId = ctx.organization.id;
  const before = await getRetentionPolicy(organizationId);

  await prisma.$transaction(async (tx) => {
    await tx.organizationRetentionPolicy.upsert({
      where: { organizationId },
      create: {
        organizationId,
        agentRunDays: policy.agentRunDays,
        notificationEventDays: policy.notificationEventDays,
        softwareItemDays: policy.softwareItemDays,
        executionJobDays: policy.executionJobDays,
        updatedById: ctx.user.id,
      },
      update: {
        agentRunDays: policy.agentRunDays,
        notificationEventDays: policy.notificationEventDays,
        softwareItemDays: policy.softwareItemDays,
        executionJobDays: policy.executionJobDays,
        updatedById: ctx.user.id,
      },
    });

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.RETENTION_POLICY_UPDATED,
      outcome: 'SUCCESS',
      targetType: 'organization',
      targetId: organizationId,
      summary: 'Updated the tenant retention policy',
      metadata: {
        before: before.policy,
        after: policy,
      } as unknown as Prisma.InputJsonValue,
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });

  return getRetentionPolicy(organizationId);
}

function policyCutoffs(policy: RetentionPolicy, now: Date): Record<RetentionCategory, Date> {
  const cutoff = (days: number) => new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
  return {
    agentRunDays: cutoff(policy.agentRunDays),
    notificationEventDays: cutoff(policy.notificationEventDays),
    softwareItemDays: cutoff(policy.softwareItemDays),
    executionJobDays: cutoff(policy.executionJobDays),
  };
}

export async function planRetentionPolicy(
  organizationId: string,
  options: { policy?: RetentionPolicy; now?: Date } = {},
): Promise<RetentionPolicyPlan> {
  const now = options.now ?? new Date();
  const policy = options.policy
    ? normaliseRetentionPolicy(options.policy)
    : (await getRetentionPolicy(organizationId)).policy;
  const cutoffs = policyCutoffs(policy, now);

  const [runs, notificationEvents, softwareItems, executionJobs] = await Promise.all([
    prisma.agentRun.count({
      where: { organizationId, startedAt: { lt: cutoffs.agentRunDays } },
    }),
    prisma.notificationEvent.count({
      where: {
        organizationId,
        status: { in: [...TERMINAL_NOTIFICATION_STATUSES] },
        createdAt: { lt: cutoffs.notificationEventDays },
      },
    }),
    prisma.softwareItem.count({
      where: { organizationId, lastSeenAt: { lt: cutoffs.softwareItemDays } },
    }),
    prisma.executionJob.count({
      where: {
        organizationId,
        status: { in: [...TERMINAL_JOB_STATUSES] },
        OR: [
          { finishedAt: { lt: cutoffs.executionJobDays } },
          { finishedAt: null, createdAt: { lt: cutoffs.executionJobDays } },
        ],
      },
    }),
  ]);

  return {
    policy,
    cutoffs: {
      agentRunDays: cutoffs.agentRunDays.toISOString(),
      notificationEventDays: cutoffs.notificationEventDays.toISOString(),
      softwareItemDays: cutoffs.softwareItemDays.toISOString(),
      executionJobDays: cutoffs.executionJobDays.toISOString(),
    },
    counts: { runs, notificationEvents, softwareItems, executionJobs },
  };
}

/**
 * The deletion itself, shared by the operator purge and the scheduled sweep so
 * both enforce the same predicates. Running jobs are never deleted: a worker
 * still holds a lease, and the job is the operator's only handle to stop it.
 */
async function deletePastWindow(
  tx: Prisma.TransactionClient,
  organizationId: string,
  cutoffs: Record<RetentionCategory, Date>,
): Promise<RetentionPolicyPlan['counts']> {
  const removedRuns = await tx.agentRun.deleteMany({
    where: { organizationId, startedAt: { lt: cutoffs.agentRunDays } },
  });
  const removedNotifications = await tx.notificationEvent.deleteMany({
    where: {
      organizationId,
      status: { in: [...TERMINAL_NOTIFICATION_STATUSES] },
      createdAt: { lt: cutoffs.notificationEventDays },
    },
  });
  const removedItems = await tx.softwareItem.deleteMany({
    where: { organizationId, lastSeenAt: { lt: cutoffs.softwareItemDays } },
  });
  const removedJobs = await tx.executionJob.deleteMany({
    where: {
      organizationId,
      status: { in: [...TERMINAL_JOB_STATUSES] },
      OR: [
        { finishedAt: { lt: cutoffs.executionJobDays } },
        { finishedAt: null, createdAt: { lt: cutoffs.executionJobDays } },
      ],
    },
  });

  return {
    runs: removedRuns.count,
    notificationEvents: removedNotifications.count,
    softwareItems: removedItems.count,
    executionJobs: removedJobs.count,
  };
}

/**
 * Deletes the categories that are past their window. The retention.purge
 * capability is owner-only: an administrator can change the policy, but only an
 * owner can make the platform forget records, which is the irreversible half of
 * retention.
 */
export async function purgeRetentionPolicy(
  ctx: {
    organization: { id: string };
    user: { id: string };
    membership: { role: OrgRole };
    meta: RequestMeta;
  },
  options: { policy?: RetentionPolicy; now?: Date } = {},
): Promise<RetentionPolicyPlan> {
  if (!can(ctx.membership.role, 'retention.purge')) {
    throw forbidden('Only an owner can purge retained history.');
  }
  const now = options.now ?? new Date();
  const plan = await planRetentionPolicy(ctx.organization.id, {
    ...(options.policy ? { policy: options.policy } : {}),
    now,
  });
  const cutoffs = policyCutoffs(plan.policy, now);
  const organizationId = ctx.organization.id;

  return prisma.$transaction(async (tx) => {
    // The delete counts are authoritative; the preview may have raced with new
    // records and is only shown to the operator before they confirm.
    const counts = await deletePastWindow(tx, organizationId, cutoffs);

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.RETENTION_PURGED,
      outcome: 'SUCCESS',
      targetType: 'organization',
      targetId: organizationId,
      summary: `Purged retained history (${counts.runs} runs, ${counts.notificationEvents} alert deliveries, ${counts.softwareItems} software inventory rows, ${counts.executionJobs} execution jobs)`,
      metadata: {
        policy: plan.policy,
        cutoffs: plan.cutoffs,
        counts,
      } as unknown as Prisma.InputJsonValue,
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return { ...plan, counts };
  });
}

export interface RetentionEnforcementResult {
  organizationsChecked: number;
  organizationsPurged: number;
  counts: RetentionPolicyPlan['counts'];
  errors: Array<{ organizationId: string; message: string }>;
}

/**
 * Applies the stored policy for every organization that configured one.
 *
 * Only organizations with an explicit policy are touched. A tenant that never
 * opened the retention screen keeps its history, because deleting records on a
 * default nobody confirmed is not something a timer should decide. Each tenant
 * is purged in its own transaction with a SYSTEM audit entry, so one failure
 * cannot roll back another tenant's sweep, and the actor in the chain is the
 * schedule rather than a person.
 */
export async function enforceRetentionSchedules(
  options: { now?: Date } = {},
): Promise<RetentionEnforcementResult> {
  const now = options.now ?? new Date();
  const policies = await prisma.organizationRetentionPolicy.findMany({
    select: {
      organizationId: true,
      agentRunDays: true,
      notificationEventDays: true,
      softwareItemDays: true,
      executionJobDays: true,
    },
  });

  const result: RetentionEnforcementResult = {
    organizationsChecked: policies.length,
    organizationsPurged: 0,
    counts: { runs: 0, notificationEvents: 0, softwareItems: 0, executionJobs: 0 },
    errors: [],
  };

  for (const stored of policies) {
    const policy: RetentionPolicy = {
      agentRunDays: stored.agentRunDays,
      notificationEventDays: stored.notificationEventDays,
      softwareItemDays: stored.softwareItemDays,
      executionJobDays: stored.executionJobDays,
    };
    try {
      const cutoffs = policyCutoffs(policy, now);
      const removed = await prisma.$transaction(async (tx) => {
        const counts = await deletePastWindow(tx, stored.organizationId, cutoffs);
        if (Object.values(counts).some((count) => count > 0)) {
          await appendAuditEvent(tx, {
            organizationId: stored.organizationId,
            actorType: 'SYSTEM',
            action: AuditActions.RETENTION_PURGED,
            outcome: 'SUCCESS',
            targetType: 'organization',
            targetId: stored.organizationId,
            summary: `Scheduled retention purged ${counts.runs} runs, ${counts.notificationEvents} alert deliveries, ${counts.softwareItems} software inventory rows and ${counts.executionJobs} execution jobs`,
            metadata: {
              policy,
              cutoffs: {
                agentRunDays: cutoffs.agentRunDays.toISOString(),
                notificationEventDays: cutoffs.notificationEventDays.toISOString(),
                softwareItemDays: cutoffs.softwareItemDays.toISOString(),
                executionJobDays: cutoffs.executionJobDays.toISOString(),
              },
              counts,
              trigger: 'schedule',
            } as unknown as Prisma.InputJsonValue,
          });
        }
        return counts;
      });
      if (Object.values(removed).some((count) => count > 0)) {
        result.organizationsPurged += 1;
        result.counts.runs += removed.runs;
        result.counts.notificationEvents += removed.notificationEvents;
        result.counts.softwareItems += removed.softwareItems;
        result.counts.executionJobs += removed.executionJobs;
      }
    } catch (error) {
      result.errors.push({
        organizationId: stored.organizationId,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return result;
}
