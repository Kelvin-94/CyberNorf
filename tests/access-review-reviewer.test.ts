import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import { verifyAuditChain } from '@/server/audit/audit';
import type { OrgRole } from '@/server/authz/roles';
import {
  assignAccessReviewReviewer,
  cancelAccessReview,
  createAccessReview,
  decideAccessReviewItem,
} from '@/server/services/access-reviews';
import {
  assertTestDatabase,
  createTenant,
  createUser,
  expectAppError,
  prisma,
  resetDatabase,
  type TestTenant,
} from './helpers/database.ts';

function dueIn(days: number): Date {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
}

async function addMember(organizationId: string, role: OrgRole) {
  const user = await createUser({ twoFactorEnabled: true });
  const membership = await prisma.membership.create({
    data: { organizationId, userId: user.id, role, status: 'ACTIVE' },
    select: { id: true, role: true },
  });
  return { user, membership };
}

function memberContext(
  tenant: TestTenant,
  member: Awaited<ReturnType<typeof addMember>>,
): TestTenant['ctx'] {
  return { ...tenant.ctx, user: member.user, membership: member.membership };
}

function itemFor(review: Awaited<ReturnType<typeof createAccessReview>>, userId: string) {
  const item = review.items.find((row) => row.userId === userId);
  assert.ok(item, `expected a review item for ${userId}`);
  return item;
}

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

test('an assigned reviewer is the only account that can decide, and assignment is audited', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const reviewer = await addMember(tenant.organization.id, 'ADMIN');
  const bystander = await addMember(tenant.organization.id, 'ADMIN');

  const review = await createAccessReview(tenant.ctx, {
    title: 'Assigned recertification',
    dueAt: dueIn(7),
    reviewerId: reviewer.user.id,
  });
  assert.equal(review.reviewer?.id, reviewer.user.id);

  const ownerItem = itemFor(review, tenant.user.id);
  const reviewerItem = itemFor(review, reviewer.user.id);

  await expectAppError(
    decideAccessReviewItem(memberContext(tenant, bystander), review.id, reviewerItem.id, {
      decision: 'REVOKE',
    }),
    { statusCode: 403, code: 'FORBIDDEN' },
  );

  const decided = await decideAccessReviewItem(
    memberContext(tenant, reviewer),
    review.id,
    ownerItem.id,
    { decision: 'RETAIN', note: 'Assigned reviewer decision' },
  );
  const ownerRow = itemFor(decided, tenant.user.id);
  assert.equal(ownerRow.decision, 'RETAIN');
  assert.equal(ownerRow.decidedBy?.id, reviewer.user.id);
  assert.equal(decided.progress.pending, review.items.length - 1);

  const assignments = await prisma.auditEvent.findMany({
    where: {
      organizationId: tenant.organization.id,
      action: 'access_review.reviewer_assigned',
    },
    orderBy: { sequence: 'asc' },
  });
  assert.equal(assignments.length, 1);
  const metadata = assignments[0]?.metadata as {
    previousReviewerId?: string | null;
    reviewerId?: string;
  } | null;
  assert.equal(metadata?.reviewerId, reviewer.user.id);
  assert.equal(metadata?.previousReviewerId, null);
  assert.equal((await verifyAuditChain(tenant.organization.id)).valid, true);
});

test('reviewers who are not eligible administrators are rejected at creation', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const viewer = await addMember(tenant.organization.id, 'VIEWER');
  const outsider = await createUser({ twoFactorEnabled: true });

  await expectAppError(
    createAccessReview(tenant.ctx, {
      title: 'Creator as reviewer',
      dueAt: dueIn(7),
      reviewerId: tenant.user.id,
    }),
    { statusCode: 400, code: 'BAD_REQUEST' },
  );

  await expectAppError(
    createAccessReview(tenant.ctx, {
      title: 'Viewer as reviewer',
      dueAt: dueIn(7),
      reviewerId: viewer.user.id,
    }),
    { statusCode: 400, code: 'BAD_REQUEST' },
  );

  await expectAppError(
    createAccessReview(tenant.ctx, {
      title: 'Outsider as reviewer',
      dueAt: dueIn(7),
      reviewerId: outsider.id,
    }),
    { statusCode: 404, code: 'NOT_FOUND' },
  );

  assert.equal(
    await prisma.accessReview.count({ where: { organizationId: tenant.organization.id } }),
    0,
    'a rejected reviewer leaves no partial campaign behind',
  );
});

test('reassignment moves the decision right and clearing it returns the review to any admin', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const first = await addMember(tenant.organization.id, 'ADMIN');
  const second = await addMember(tenant.organization.id, 'ADMIN');

  const review = await createAccessReview(tenant.ctx, {
    title: 'Reassigned recertification',
    dueAt: dueIn(7),
    reviewerId: first.user.id,
  });

  const reassigned = await assignAccessReviewReviewer(tenant.ctx, review.id, second.user.id);
  assert.equal(reassigned.reviewer?.id, second.user.id);

  await expectAppError(
    decideAccessReviewItem(memberContext(tenant, first), review.id, itemFor(review, tenant.user.id).id, {
      decision: 'RETAIN',
    }),
    { statusCode: 403, code: 'FORBIDDEN' },
  );

  const afterSecond = await decideAccessReviewItem(
    memberContext(tenant, second),
    review.id,
    itemFor(review, tenant.user.id).id,
    { decision: 'REVOKE' },
  );
  assert.equal(itemFor(afterSecond, tenant.user.id).decidedBy?.id, second.user.id);

  const cleared = await assignAccessReviewReviewer(tenant.ctx, review.id, null);
  assert.equal(cleared.reviewer, null);

  const afterClear = await decideAccessReviewItem(
    memberContext(tenant, first),
    review.id,
    itemFor(review, second.user.id).id,
    { decision: 'RETAIN' },
  );
  assert.equal(itemFor(afterClear, second.user.id).decidedBy?.id, first.user.id);

  const assignments = await prisma.auditEvent.findMany({
    where: {
      organizationId: tenant.organization.id,
      action: 'access_review.reviewer_assigned',
    },
    orderBy: { sequence: 'asc' },
  });
  assert.equal(
    assignments.length,
    3,
    'creation, reassignment and clearing are each recorded',
  );
  const creationEvent = assignments[0]?.metadata as {
    reviewerId?: string | null;
  } | null;
  assert.equal(creationEvent?.reviewerId, first.user.id);
  const clearedEvent = assignments[2]?.metadata as {
    previousReviewerId?: string | null;
    reviewerId?: string | null;
  } | null;
  assert.equal(clearedEvent?.previousReviewerId, second.user.id);
  assert.equal(clearedEvent?.reviewerId, null);
});

test('a closed review cannot be reassigned and unknown reviews are not found', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const reviewer = await addMember(tenant.organization.id, 'ADMIN');

  const review = await createAccessReview(tenant.ctx, {
    title: 'Closing recertification',
    dueAt: dueIn(7),
  });
  await cancelAccessReview(tenant.ctx, review.id);

  await expectAppError(assignAccessReviewReviewer(tenant.ctx, review.id, reviewer.user.id), {
    statusCode: 409,
    code: 'CONFLICT',
  });

  await expectAppError(
    assignAccessReviewReviewer(tenant.ctx, 'review-does-not-exist', reviewer.user.id),
    { statusCode: 404, code: 'NOT_FOUND' },
  );
});
