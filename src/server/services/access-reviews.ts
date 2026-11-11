import { Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import { conflict, forbidden, notFound } from '@/server/errors';
import type {
  AccessReviewListQuery,
  DecideAccessReviewItemInput,
} from '@/server/validation/identities';
import { paginationMeta } from './shared';

/**
 * Access recertification.
 *
 * Creating a review snapshots every active membership, so access added after
 * the campaign started is not silently retained. Decisions are explicit: an
 * undecided item keeps the review open, and `RETAIN` is recorded as an
 * affirmative decision. Finalization revokes the memberships marked `REVOKE`
 * through the same rules the member-removal path uses: the last owner is
 * protected, sessions are dropped only when no active membership remains, and
 * linked human identities are suspended with the console access.
 */

const REVIEW_LOCK_NAMESPACE = 0x43595256; // "CYRV"

const REVIEW_INCLUDE = {
  createdBy: { select: { id: true, name: true, email: true } },
  items: {
    orderBy: [{ decision: 'asc' }, { roleAtReview: 'desc' }, { userName: 'asc' }],
    select: {
      id: true,
      membershipId: true,
      userId: true,
      userName: true,
      userEmail: true,
      roleAtReview: true,
      decision: true,
      decidedById: true,
      decidedAt: true,
      note: true,
      membership: { select: { role: true, status: true } },
      decidedBy: { select: { id: true, name: true, email: true } },
    },
  },
} satisfies Prisma.AccessReviewInclude;

type ReviewRow = Prisma.AccessReviewGetPayload<{ include: typeof REVIEW_INCLUDE }>;

type Db = Prisma.TransactionClient | typeof prisma;

export interface ReviewProgress {
  total: number;
  decided: number;
  pending: number;
  retain: number;
  revoke: number;
}

export interface AccessReviewItemView {
  id: string;
  membershipId: string;
  userId: string;
  userName: string;
  userEmail: string;
  roleAtReview: string;
  decision: 'PENDING' | 'RETAIN' | 'REVOKE';
  decidedAt: string | null;
  decidedBy: { id: string; name: string; email: string } | null;
  note: string | null;
  membershipStatus: string;
  currentRole: string;
}

export interface AccessReviewSummary {
  id: string;
  title: string;
  description: string | null;
  status: 'ACTIVE' | 'COMPLETED' | 'CANCELLED';
  dueAt: string;
  createdAt: string;
  completedAt: string | null;
  cancelledAt: string | null;
  createdBy: { id: string; name: string; email: string };
  progress: ReviewProgress;
  overdue: boolean;
}

export interface AccessReviewDetail extends AccessReviewSummary {
  items: AccessReviewItemView[];
}

export interface AccessReviewPage {
  items: AccessReviewSummary[];
  pagination: ReturnType<typeof paginationMeta>;
}

function progressFromItems(
  items: Array<{ decision: 'PENDING' | 'RETAIN' | 'REVOKE' }>,
): ReviewProgress {
  const progress: ReviewProgress = {
    total: items.length,
    decided: 0,
    pending: 0,
    retain: 0,
    revoke: 0,
  };
  for (const item of items) {
    if (item.decision === 'PENDING') {
      progress.pending += 1;
    } else {
      progress.decided += 1;
      if (item.decision === 'RETAIN') progress.retain += 1;
      if (item.decision === 'REVOKE') progress.revoke += 1;
    }
  }
  return progress;
}

function toSummary(
  row: Omit<ReviewRow, 'items'> & {
    items: Array<{ decision: 'PENDING' | 'RETAIN' | 'REVOKE' }>;
  },
  now: Date,
): AccessReviewSummary {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    status: row.status,
    dueAt: row.dueAt.toISOString(),
    createdAt: row.createdAt.toISOString(),
    completedAt: row.completedAt?.toISOString() ?? null,
    cancelledAt: row.cancelledAt?.toISOString() ?? null,
    createdBy: row.createdBy,
    progress: progressFromItems(row.items),
    overdue: row.status === 'ACTIVE' && row.dueAt.getTime() < now.getTime(),
  };
}

function toDetail(row: ReviewRow, now: Date): AccessReviewDetail {
  return {
    ...toSummary(row, now),
    items: row.items.map((item) => ({
      id: item.id,
      membershipId: item.membershipId,
      userId: item.userId,
      userName: item.userName,
      userEmail: item.userEmail,
      roleAtReview: item.roleAtReview,
      decision: item.decision,
      decidedAt: item.decidedAt?.toISOString() ?? null,
      decidedBy: item.decidedBy,
      note: item.note,
      membershipStatus: item.membership.status,
      currentRole: item.membership.role,
    })),
  };
}

async function loadReview(
  db: Db,
  organizationId: string,
  reviewId: string,
): Promise<ReviewRow | null> {
  return db.accessReview.findFirst({
    where: { id: reviewId, organizationId },
    include: REVIEW_INCLUDE,
  });
}

export interface AccessReviewOverview {
  active: number;
  overdue: number;
  completed: number;
  cancelled: number;
}

export async function getAccessReviewOverview(
  organizationId: string,
): Promise<AccessReviewOverview> {
  const now = new Date();
  const [active, overdue, completed, cancelled] = await Promise.all([
    prisma.accessReview.count({ where: { organizationId, status: 'ACTIVE' } }),
    prisma.accessReview.count({
      where: { organizationId, status: 'ACTIVE', dueAt: { lt: now } },
    }),
    prisma.accessReview.count({ where: { organizationId, status: 'COMPLETED' } }),
    prisma.accessReview.count({ where: { organizationId, status: 'CANCELLED' } }),
  ]);
  return { active, overdue, completed, cancelled };
}

export async function listAccessReviews(
  organizationId: string,
  query: AccessReviewListQuery,
): Promise<AccessReviewPage> {
  const now = new Date();
  const where: Prisma.AccessReviewWhereInput = {
    organizationId,
    ...(query.status ? { status: query.status } : {}),
    ...(query.search ? { title: { contains: query.search, mode: 'insensitive' } } : {}),
  };

  const [total, rows] = await Promise.all([
    prisma.accessReview.count({ where }),
    prisma.accessReview.findMany({
      where,
      include: {
        createdBy: { select: { id: true, name: true, email: true } },
        items: { select: { decision: true } },
      },
      orderBy: [{ status: 'asc' }, { dueAt: 'asc' }, { createdAt: 'desc' }],
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
  ]);

  return {
    items: rows.map((row) => toSummary(row, now)),
    pagination: paginationMeta(query.page, query.pageSize, total),
  };
}

export async function getAccessReviewDetail(
  organizationId: string,
  reviewId: string,
): Promise<AccessReviewDetail> {
  const row = await loadReview(prisma, organizationId, reviewId);
  if (!row) {
    throw notFound('Access review not found.');
  }
  return toDetail(row, new Date());
}

export async function createAccessReview(
  ctx: TenantContext,
  input: { title: string; description?: string | null | undefined; dueAt: Date },
): Promise<AccessReviewDetail> {
  const organizationId = ctx.organization.id;
  const memberships = await prisma.membership.findMany({
    where: { organizationId, status: 'ACTIVE' },
    select: {
      id: true,
      userId: true,
      role: true,
      user: { select: { name: true, email: true } },
    },
    orderBy: [{ role: 'asc' }, { createdAt: 'asc' }],
    take: 500,
  });

  if (memberships.length === 0) {
    throw conflict('There are no active members to review.');
  }

  const now = new Date();
  const review = await prisma.$transaction(async (tx) => {
    const created = await tx.accessReview.create({
      data: {
        organizationId,
        title: input.title,
        dueAt: input.dueAt,
        createdById: ctx.user.id,
        ...(input.description !== undefined ? { description: input.description } : {}),
        items: {
          create: memberships.map((membership) => ({
            organizationId,
            membershipId: membership.id,
            userId: membership.userId,
            userName: membership.user.name,
            userEmail: membership.user.email,
            roleAtReview: membership.role,
          })),
        },
      },
      select: { id: true },
    });

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ACCESS_REVIEW_CREATED,
      outcome: 'SUCCESS',
      targetType: 'access_review',
      targetId: created.id,
      summary: `Opened access review "${input.title}" with ${memberships.length} member(s)`,
      metadata: {
        dueAt: input.dueAt.toISOString(),
        itemCount: memberships.length,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return created;
  });

  const detail = await loadReview(prisma, organizationId, review.id);
  if (!detail) {
    throw new Error('Access review disappeared immediately after creation.');
  }
  return toDetail(detail, now);
}

export async function decideAccessReviewItem(
  ctx: TenantContext,
  reviewId: string,
  itemId: string,
  input: DecideAccessReviewItemInput,
): Promise<AccessReviewDetail> {
  const organizationId = ctx.organization.id;
  const now = new Date();

  const result = await prisma.$transaction(async (tx) => {
    const review = await tx.accessReview.findFirst({
      where: { id: reviewId, organizationId },
      select: { id: true, status: true, title: true },
    });
    if (!review) {
      throw notFound('Access review not found.');
    }
    if (review.status !== 'ACTIVE') {
      throw conflict('This review is closed and can no longer record decisions.');
    }

    const item = await tx.accessReviewItem.findFirst({
      where: { id: itemId, reviewId, organizationId },
      select: {
        id: true,
        userId: true,
        userName: true,
        decision: true,
        roleAtReview: true,
      },
    });
    if (!item) {
      throw notFound('Review item not found.');
    }
    if (item.userId === ctx.user.id) {
      throw forbidden('Reviewers cannot decide their own access.');
    }
    if (item.decision !== 'PENDING') {
      throw conflict('This item already has a decision.');
    }

    // The conditional update makes a concurrent duplicate decision fail instead
    // of overwriting the first reviewer's record.
    const updated = await tx.accessReviewItem.updateMany({
      where: { id: item.id, decision: 'PENDING' },
      data: {
        decision: input.decision,
        decidedById: ctx.user.id,
        decidedAt: now,
        note: input.note ?? null,
      },
    });
    if (updated.count !== 1) {
      throw conflict('This item already has a decision.');
    }

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ACCESS_REVIEW_DECISION_RECORDED,
      outcome: 'SUCCESS',
      targetType: 'access_review_item',
      targetId: item.id,
      summary: `${input.decision} recorded for ${item.userName} in "${review.title}"`,
      metadata: {
        reviewId,
        decision: input.decision,
        roleAtReview: item.roleAtReview,
        hasNote: Boolean(input.note),
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return { reviewId };
  });

  const detail = await loadReview(prisma, organizationId, result.reviewId);
  if (!detail) {
    throw new Error('Access review disappeared while recording a decision.');
  }
  return toDetail(detail, now);
}

export async function finalizeAccessReview(
  ctx: TenantContext,
  reviewId: string,
): Promise<AccessReviewDetail> {
  const organizationId = ctx.organization.id;
  const now = new Date();

  const completed = await prisma.$transaction(async (tx) => {
    // One finalizer at a time per review. A concurrent decision still runs in
    // its own transaction and is serialized against this lock at commit.
    await tx.$queryRaw`SELECT 1::int AS locked FROM (SELECT pg_advisory_xact_lock(hashtextextended(${reviewId}, ${REVIEW_LOCK_NAMESPACE}))) AS review_lock`;

    const review = await loadReview(tx, organizationId, reviewId);
    if (!review) {
      throw notFound('Access review not found.');
    }
    if (review.status !== 'ACTIVE') {
      throw conflict('This review is already closed.');
    }

    const pending = review.items.filter((item) => item.decision === 'PENDING');
    if (pending.length > 0) {
      throw conflict(
        `${pending.length} member(s) still need a decision before the review can be completed.`,
      );
    }

    const revokes = review.items.filter(
      (item) => item.decision === 'REVOKE' && item.membership.status === 'ACTIVE',
    );

    let sessionsDeleted = 0;

    if (revokes.length > 0) {
      const owners = await tx.membership.findMany({
        where: { organizationId, role: 'OWNER', status: 'ACTIVE' },
        select: { id: true, user: { select: { email: true } } },
      });
      const revokedMembershipIds = new Set(revokes.map((item) => item.membershipId));
      const remainingOwners = owners.filter((owner) => !revokedMembershipIds.has(owner.id));
      if (remainingOwners.length === 0) {
        throw conflict(
          'The review revokes every active owner. Keep at least one owner before completing it.',
        );
      }
    }

    for (const item of revokes) {
      const membership = await tx.membership.findFirst({
        where: { id: item.membershipId, organizationId },
        select: { id: true, userId: true, role: true, status: true },
      });
      if (!membership || membership.status !== 'ACTIVE') {
        // The member was removed between snapshoting and finalization; the
        // review outcome is already satisfied.
        continue;
      }

      await tx.membership.update({
        where: { id: membership.id },
        data: { status: 'DISABLED' },
      });

      const remainingMemberships = await tx.membership.count({
        where: { userId: membership.userId, status: 'ACTIVE' },
      });
      if (remainingMemberships === 0) {
        const deletedSessions = await tx.session.deleteMany({
          where: { userId: membership.userId },
        });
        sessionsDeleted += deletedSessions.count;
      }

      const linkedIdentities = await tx.identity.findMany({
        where: {
          organizationId,
          linkedUserId: membership.userId,
          status: { not: 'DEPROVISIONED' },
        },
        select: { id: true, displayName: true, status: true },
      });
      for (const identity of linkedIdentities) {
        await tx.identity.update({
          where: { id: identity.id },
          data: { status: 'SUSPENDED', suspendedAt: now },
        });
        await tx.identityEvent.create({
          data: {
            organizationId,
            identityId: identity.id,
            type: 'SUSPENDED',
            actorId: ctx.user.id,
            summary: `Suspended because access review "${review.title}" revoked console access`,
            metadata: { accessReviewId: reviewId, reason: 'access_revoked' },
          },
        });
        await appendAuditEvent(tx, {
          organizationId,
          actorType: 'USER',
          actorId: ctx.user.id,
          action: AuditActions.IDENTITY_SUSPENDED,
          outcome: 'SUCCESS',
          targetType: 'identity',
          targetId: identity.id,
          summary: `Suspended ${identity.displayName} after an access review revocation`,
          metadata: { accessReviewId: reviewId, reason: 'access_revoked' },
          ipAddress: ctx.meta.ipAddress,
          userAgent: ctx.meta.userAgent,
          requestId: ctx.meta.requestId,
        });
      }

      await appendAuditEvent(tx, {
        organizationId,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.MEMBER_REMOVED,
        outcome: 'SUCCESS',
        targetType: 'membership',
        targetId: membership.id,
        summary: `${item.userEmail} removed through access review "${review.title}"`,
        metadata: {
          userId: membership.userId,
          role: membership.role,
          accessReviewId: reviewId,
          reason: 'access_review',
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });
    }

    await tx.accessReview.update({
      where: { id: review.id },
      data: { status: 'COMPLETED', completedAt: now },
    });

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ACCESS_REVIEW_COMPLETED,
      outcome: 'SUCCESS',
      targetType: 'access_review',
      targetId: review.id,
      summary: `Completed access review "${review.title}"`,
      metadata: {
        itemCount: review.items.length,
        retained: review.items.filter((item) => item.decision === 'RETAIN').length,
        revoked: revokes.length,
        sessionsDeleted,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    const detail = await loadReview(tx, organizationId, review.id);
    if (!detail) {
      throw new Error('Access review disappeared during finalization.');
    }
    return detail;
  });

  return toDetail(completed, now);
}

export async function cancelAccessReview(
  ctx: TenantContext,
  reviewId: string,
): Promise<AccessReviewDetail> {
  const organizationId = ctx.organization.id;
  const now = new Date();

  const result = await prisma.$transaction(async (tx) => {
    const review = await tx.accessReview.findFirst({
      where: { id: reviewId, organizationId },
      select: { id: true, status: true, title: true },
    });
    if (!review) {
      throw notFound('Access review not found.');
    }
    if (review.status !== 'ACTIVE') {
      throw conflict('This review is already closed.');
    }

    const updated = await tx.accessReview.updateMany({
      where: { id: review.id, status: 'ACTIVE' },
      data: { status: 'CANCELLED', cancelledAt: now },
    });
    if (updated.count !== 1) {
      throw conflict('This review is already closed.');
    }

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ACCESS_REVIEW_CANCELLED,
      outcome: 'SUCCESS',
      targetType: 'access_review',
      targetId: review.id,
      summary: `Cancelled access review "${review.title}"`,
      metadata: {},
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return review.id;
  });

  const detail = await loadReview(prisma, organizationId, result);
  if (!detail) {
    throw new Error('Access review disappeared while being cancelled.');
  }
  return toDetail(detail, now);
}
