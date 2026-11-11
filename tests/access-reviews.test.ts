import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { before, test } from 'node:test';
import { verifyAuditChain } from '@/server/audit/audit';
import type { OrgRole } from '@/server/authz/roles';
import {
  cancelAccessReview,
  createAccessReview,
  decideAccessReviewItem,
  finalizeAccessReview,
  getAccessReviewDetail,
  getAccessReviewOverview,
  listAccessReviews,
} from '@/server/services/access-reviews';
import { createIdentity } from '@/server/services/identities';
import {
  assertTestDatabase,
  createTenant,
  createUser,
  expectAppError,
  prisma,
  resetDatabase,
  testMeta,
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

test('a review snapshots active members and reviewers cannot decide their own access', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const admin = await addMember(tenant.organization.id, 'ADMIN');

  const disabledUser = await createUser({ twoFactorEnabled: true });
  await prisma.membership.create({
    data: {
      organizationId: tenant.organization.id,
      userId: disabledUser.id,
      role: 'VIEWER',
      status: 'DISABLED',
    },
  });

  const review = await createAccessReview(tenant.ctx, {
    title: 'Quarterly recertification',
    description: 'Review console access for the quarter.',
    dueAt: dueIn(14),
  });

  assert.equal(review.status, 'ACTIVE');
  assert.equal(review.items.length, 2, 'disabled memberships are not part of the campaign');
  assert.deepEqual(
    review.items.map((item) => item.userId).sort(),
    [tenant.user.id, admin.user.id].sort(),
  );
  assert.ok(review.items.every((item) => item.decision === 'PENDING'));
  assert.equal(review.progress.pending, 2);
  assert.equal(review.overdue, false);

  const ownerItem = itemFor(review, tenant.user.id);
  const adminItem = itemFor(review, admin.user.id);

  await expectAppError(
    decideAccessReviewItem(tenant.ctx, review.id, ownerItem.id, {
      decision: 'RETAIN',
    }),
    { statusCode: 403, code: 'FORBIDDEN' },
  );

  const afterOwnerDecision = await decideAccessReviewItem(tenant.ctx, review.id, adminItem.id, {
    decision: 'RETAIN',
    note: 'Still on the on-call rotation',
  });
  const decidedAdminItem = itemFor(afterOwnerDecision, admin.user.id);
  assert.equal(decidedAdminItem.decision, 'RETAIN');
  assert.equal(decidedAdminItem.note, 'Still on the on-call rotation');
  assert.equal(decidedAdminItem.decidedBy?.id, tenant.user.id);
  assert.equal(afterOwnerDecision.progress.retain, 1);
  assert.equal(afterOwnerDecision.progress.pending, 1);

  await expectAppError(
    decideAccessReviewItem(tenant.ctx, review.id, adminItem.id, { decision: 'REVOKE' }),
    { statusCode: 409, code: 'CONFLICT' },
  );

  const afterAdminDecision = await decideAccessReviewItem(
    memberContext(tenant, admin),
    review.id,
    ownerItem.id,
    { decision: 'RETAIN' },
  );
  assert.equal(afterAdminDecision.progress.decided, 2);
  assert.equal(afterAdminDecision.progress.pending, 0);

  const decisions = await prisma.auditEvent.count({
    where: {
      organizationId: tenant.organization.id,
      action: 'access_review.decision_recorded',
    },
  });
  assert.equal(decisions, 2);
});

test('finalization applies revocations, drops sessions and suspends linked identities', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const admin = await addMember(tenant.organization.id, 'ADMIN');

  const session = await prisma.session.create({
    data: {
      id: `ses_${randomUUID()}`,
      token: `tok_${randomUUID()}`,
      expiresAt: dueIn(1),
      userId: admin.user.id,
    },
    select: { id: true },
  });

  const linked = await createIdentity(tenant.ctx, {
    kind: 'HUMAN',
    type: 'USER',
    displayName: 'Admin person',
    identifier: admin.user.email,
    criticality: 'HIGH',
    source: 'MANUAL',
    credentialTtlDays: 90,
  });
  assert.equal(linked.linkedUser?.id, admin.user.id);

  const review = await createAccessReview(tenant.ctx, {
    title: 'Contractor cleanup',
    dueAt: dueIn(10),
  });
  const ownerItem = itemFor(review, tenant.user.id);
  const adminItem = itemFor(review, admin.user.id);

  await decideAccessReviewItem(tenant.ctx, review.id, adminItem.id, {
    decision: 'REVOKE',
    note: 'Contract ended',
  });
  await decideAccessReviewItem(memberContext(tenant, admin), review.id, ownerItem.id, {
    decision: 'RETAIN',
  });

  const completed = await finalizeAccessReview(tenant.ctx, review.id);
  assert.equal(completed.status, 'COMPLETED');
  assert.ok(completed.completedAt);
  assert.equal(completed.progress.revoke, 1);
  assert.equal(completed.progress.retain, 1);

  const membership = await prisma.membership.findUniqueOrThrow({
    where: { id: admin.membership.id },
    select: { status: true },
  });
  assert.equal(membership.status, 'DISABLED');

  assert.equal(await prisma.session.count({ where: { userId: admin.user.id } }), 0);
  assert.ok(session.id);

  const linkedAfter = await prisma.identity.findUniqueOrThrow({
    where: { id: linked.id },
    select: { status: true },
  });
  assert.equal(linkedAfter.status, 'SUSPENDED');

  const identityEvent = await prisma.identityEvent.findFirstOrThrow({
    where: { identityId: linked.id, type: 'SUSPENDED' },
    select: { metadata: true },
  });
  assert.equal(
    (identityEvent.metadata as Record<string, unknown>).accessReviewId,
    review.id,
  );

  const memberRemoved = await prisma.auditEvent.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, action: 'member.removed' },
    select: { targetId: true, metadata: true },
  });
  assert.equal(memberRemoved.targetId, admin.membership.id);
  assert.equal(
    (memberRemoved.metadata as Record<string, unknown>).accessReviewId,
    review.id,
  );

  const completion = await prisma.auditEvent.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, action: 'access_review.completed' },
    select: { metadata: true },
  });
  assert.equal((completion.metadata as Record<string, unknown>).revoked, 1);
  assert.equal((completion.metadata as Record<string, unknown>).sessionsDeleted, 1);

  const chain = await verifyAuditChain(tenant.organization.id);
  assert.equal(chain.valid, true);
  assert.ok(chain.checked > 0);

  await expectAppError(finalizeAccessReview(tenant.ctx, review.id), {
    statusCode: 409,
    code: 'CONFLICT',
  });
});

test('finalization refuses to revoke every active owner', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const admin = await addMember(tenant.organization.id, 'ADMIN');

  const review = await createAccessReview(tenant.ctx, {
    title: 'Owner review',
    dueAt: dueIn(7),
  });
  await decideAccessReviewItem(memberContext(tenant, admin), review.id, itemFor(review, tenant.user.id).id, {
    decision: 'REVOKE',
  });
  await decideAccessReviewItem(tenant.ctx, review.id, itemFor(review, admin.user.id).id, {
    decision: 'RETAIN',
  });

  await expectAppError(finalizeAccessReview(tenant.ctx, review.id), {
    statusCode: 409,
    code: 'CONFLICT',
  });

  const ownerMembership = await prisma.membership.findUniqueOrThrow({
    where: { id: tenant.membership.id },
    select: { status: true },
  });
  assert.equal(ownerMembership.status, 'ACTIVE');

  const stillActive = await getAccessReviewDetail(tenant.organization.id, review.id);
  assert.equal(stillActive.status, 'ACTIVE');
  assert.equal(stillActive.progress.pending, 0);
});

test('finalization waits for every decision and cancellation closes the campaign', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const admin = await addMember(tenant.organization.id, 'ADMIN');

  const review = await createAccessReview(tenant.ctx, {
    title: 'Incomplete review',
    dueAt: dueIn(21),
  });
  await decideAccessReviewItem(tenant.ctx, review.id, itemFor(review, admin.user.id).id, {
    decision: 'RETAIN',
  });

  await expectAppError(finalizeAccessReview(tenant.ctx, review.id), {
    statusCode: 409,
    code: 'CONFLICT',
  });

  const cancelled = await cancelAccessReview(tenant.ctx, review.id);
  assert.equal(cancelled.status, 'CANCELLED');
  assert.ok(cancelled.cancelledAt);

  await expectAppError(
    decideAccessReviewItem(tenant.ctx, review.id, itemFor(review, tenant.user.id).id, {
      decision: 'RETAIN',
    }),
    { statusCode: 409, code: 'CONFLICT' },
  );
  await expectAppError(cancelAccessReview(tenant.ctx, review.id), {
    statusCode: 409,
    code: 'CONFLICT',
  });
  await expectAppError(finalizeAccessReview(tenant.ctx, review.id), {
    statusCode: 409,
    code: 'CONFLICT',
  });
});

test('reviews are listed per tenant and cannot be read or decided across tenants', async () => {
  const tenantA = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  await addMember(tenantA.organization.id, 'ADMIN');
  const tenantB = await createTenant({ role: 'OWNER', twoFactorEnabled: true });

  const active = await createAccessReview(tenantA.ctx, {
    title: 'Active campaign',
    dueAt: dueIn(30),
  });
  const cancelled = await createAccessReview(tenantA.ctx, {
    title: 'Abandoned campaign',
    dueAt: dueIn(30),
  });
  await cancelAccessReview(tenantA.ctx, cancelled.id);

  const overview = await getAccessReviewOverview(tenantA.organization.id);
  assert.deepEqual(overview, { active: 1, overdue: 0, completed: 0, cancelled: 1 });

  const all = await listAccessReviews(tenantA.organization.id, {
    page: 1,
    pageSize: 20,
    search: undefined,
  });
  assert.equal(all.pagination.total, 2);

  const activeOnly = await listAccessReviews(tenantA.organization.id, {
    page: 1,
    pageSize: 20,
    status: 'ACTIVE',
    search: undefined,
  });
  assert.equal(activeOnly.pagination.total, 1);
  const [activeItem] = activeOnly.items;
  assert.ok(activeItem);
  assert.equal(activeItem.id, active.id);

  const searched = await listAccessReviews(tenantA.organization.id, {
    page: 1,
    pageSize: 20,
    search: 'Abandoned',
  });
  assert.equal(searched.pagination.total, 1);
  const [cancelledItem] = searched.items;
  assert.ok(cancelledItem);
  assert.equal(cancelledItem.id, cancelled.id);

  await expectAppError(getAccessReviewDetail(tenantB.organization.id, active.id), {
    statusCode: 404,
    code: 'NOT_FOUND',
  });
  await expectAppError(
    decideAccessReviewItem(
      tenantB.ctx,
      active.id,
      itemFor(active, tenantA.user.id).id,
      { decision: 'REVOKE' },
    ),
    { statusCode: 404, code: 'NOT_FOUND' },
  );
  await expectAppError(cancelAccessReview(tenantB.ctx, active.id), {
    statusCode: 404,
    code: 'NOT_FOUND',
  });

  const tenantBReviews = await listAccessReviews(tenantB.organization.id, {
    page: 1,
    pageSize: 20,
    search: undefined,
  });
  assert.equal(tenantBReviews.pagination.total, 0);
  assert.deepEqual(await getAccessReviewOverview(tenantB.organization.id), {
    active: 0,
    overdue: 0,
    completed: 0,
    cancelled: 0,
  });
});

test('creating a review requires an active membership', async () => {
  const user = await createUser({ twoFactorEnabled: true });
  const organization = await prisma.organization.create({
    data: { name: 'Empty org', slug: `empty-${randomUUID().slice(0, 8)}` },
    select: { id: true, name: true, slug: true, tier: true },
  });
  const ctx: TestTenant['ctx'] = {
    user,
    organization,
    membership: { id: 'none', role: 'OWNER' },
    meta: testMeta(),
  };

  await expectAppError(
    createAccessReview(ctx, { title: 'Nothing to review', dueAt: dueIn(5) }),
    { statusCode: 409, code: 'CONFLICT' },
  );
});
