import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { RequestMeta } from '@/server/http/request-meta';

/**
 * Data lifecycle for one organization.
 *
 * Retention is deliberately limited to derived operational history: agent runs,
 * delivered or failed alert deliveries, and package snapshots from agents that
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
    // A package snapshot is only stale when its agent stopped reporting; an
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
      summary: `Purged history older than ${cutoff.toISOString().slice(0, 10)} (${summary.runs} runs, ${summary.notificationEvents} alert deliveries, ${summary.softwareItems} package snapshots)`,
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
