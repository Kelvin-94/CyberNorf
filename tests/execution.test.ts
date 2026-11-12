import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import { verifyAuditChain } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import {
  addScopeEntry,
  createEngagement,
  decideAuthorization,
  getEngagement,
  removeScopeEntry,
  requestAuthorization,
  updateEngagement,
} from '@/server/services/engagements';
import {
  cancelExecutionJob,
  cleanupExecutionJobs,
  completeExecutionJob,
  getExecutionJob,
  registerExecutionWorker,
  requestExecutionJob,
  reviewExecutionJob,
  startExecutionJob,
  updateExecutionWorker,
} from '@/server/services/execution';
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

/**
 * These tests cover the Phase 4 exit criterion directly: execution outside the
 * authorized scope is denied, and the denial is repeatable. They also cover the
 * three ways scope can go stale between approval and connect — an expiring
 * authorization, a changed DNS answer, and a scope entry removed after dispatch
 * — plus cancellation and human review.
 */

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

const resolveTo = (address: string) => async () => [address];

function future(hours = 2): Date {
  return new Date(Date.now() + hours * HOUR);
}

async function addMember(
  tenant: TestTenant,
  role: 'OWNER' | 'ADMIN' | 'ANALYST' | 'VIEWER',
): Promise<TenantContext> {
  const user = await createUser();
  const membership = await prisma.membership.create({
    data: { userId: user.id, organizationId: tenant.organization.id, role, status: 'ACTIVE' },
    select: { id: true, role: true },
  });
  return { user, organization: tenant.organization, membership, meta: testMeta() };
}

async function activeEngagement(
  ctx: TenantContext,
  options: { target?: string; exclude?: string } = {},
): Promise<string> {
  const engagement = await createEngagement(ctx, {
    name: `Engagement ${Math.random().toString(36).slice(2, 10)}`,
    startsAt: new Date(Date.now() - HOUR),
    endsAt: future(24),
  });
  await addScopeEntry(ctx, engagement.id, {
    kind: 'INCLUDE',
    targetType: 'DOMAIN',
    value: options.target ?? 'example.com',
  });
  if (options.exclude) {
    await addScopeEntry(ctx, engagement.id, {
      kind: 'EXCLUDE',
      targetType: 'DOMAIN',
      value: options.exclude,
    });
  }
  await updateEngagement(ctx, engagement.id, { status: 'ACTIVE' });
  return engagement.id;
}

async function approverFor(ctx: TenantContext): Promise<TenantContext> {
  const user = await createUser();
  const membership = await prisma.membership.create({
    data: { userId: user.id, organizationId: ctx.organization.id, role: 'OWNER', status: 'ACTIVE' },
    select: { id: true, role: true },
  });
  return { user, organization: ctx.organization, membership, meta: testMeta() };
}

async function approvedAuthorization(
  requester: TenantContext,
  engagementId: string,
  expiresAt = future(),
): Promise<string> {
  // Approval always comes from a second owner: the requester can never decide
  // their own authorization, which is the control this helper must not bypass.
  const approver = await approverFor(requester);
  const authorization = await requestAuthorization(requester, engagementId, {
    expiresAt,
    reference: 'SOW-2026-014',
  });
  await decideAuthorization(approver, engagementId, authorization.id, { decision: 'APPROVED' });
  return authorization.id;
}

async function worker(ctx: TenantContext, allowlist = ['example.com']): Promise<string> {
  const created = await registerExecutionWorker(ctx, {
    name: `worker-${Math.random().toString(36).slice(2, 10)}`,
    isolated: true,
    egressAllowlist: allowlist,
  });
  // A newly registered worker is not eligible until it reports a heartbeat; the
  // control-plane treats "registered but unheard from" as "cannot be trusted to
  // run yet", so the test has to bring it live before dispatch can select it.
  await updateExecutionWorker(ctx, created.id, { heartbeat: true });
  return created.id;
}

async function queuedJob(
  ctx: TenantContext,
  engagementId: string,
  target = 'example.com',
  address = '203.0.113.10',
): Promise<string> {
  const job = await requestExecutionJob(
    ctx,
    engagementId,
    { capability: 'HTTP_PROBE', targetType: 'DOMAIN', targetValue: target },
    { resolve: resolveTo(address) },
  );
  assert.equal(job.status, 'QUEUED');
  return job.id;
}

test('a target outside every inclusion is denied at dispatch and recorded', async () => {
  const tenant = await createTenant({ role: 'OWNER' });
  const engagementId = await activeEngagement(tenant.ctx);
  await approvedAuthorization(tenant.ctx, engagementId);
  await worker(tenant.ctx);

  const job = await requestExecutionJob(
    tenant.ctx,
    engagementId,
    { capability: 'HTTP_PROBE', targetType: 'DOMAIN', targetValue: 'outside.example' },
    { resolve: resolveTo('203.0.113.10') },
  );

  assert.equal(job.status, 'DENIED');
  assert.equal(job.denialReason, 'out_of_scope');

  const detail = await getExecutionJob(tenant.organization.id, job.id);
  assert.equal(detail.events.some((event) => event.type === 'DISPATCH_DENIED'), true);
  assert.equal(
    await prisma.auditEvent.count({
      where: { organizationId: tenant.organization.id, action: 'execution.dispatch_denied' },
    }),
    1,
  );
  assert.equal((await verifyAuditChain(tenant.organization.id)).valid, true);
});

test('an excluded host is denied even though a broader inclusion matches', async () => {
  const tenant = await createTenant({ role: 'OWNER' });
  const engagementId = await activeEngagement(tenant.ctx, { exclude: 'admin.example.com' });
  await approvedAuthorization(tenant.ctx, engagementId);
  await worker(tenant.ctx);

  const job = await requestExecutionJob(
    tenant.ctx,
    engagementId,
    { capability: 'HTTP_PROBE', targetType: 'DOMAIN', targetValue: 'admin.example.com' },
    { resolve: resolveTo('203.0.113.10') },
  );

  assert.equal(job.status, 'DENIED');
  assert.equal(job.denialReason, 'excluded');
});

test('a dispatch with no approved authorization is refused and audited', async () => {
  const tenant = await createTenant({ role: 'OWNER' });
  const engagementId = await activeEngagement(tenant.ctx);
  await worker(tenant.ctx);

  await expectAppError(
    requestExecutionJob(
      tenant.ctx,
      engagementId,
      { capability: 'HTTP_PROBE', targetType: 'DOMAIN', targetValue: 'example.com' },
      { resolve: resolveTo('203.0.113.10') },
    ),
    { statusCode: 403, code: 'FORBIDDEN' },
  );

  assert.equal(
    await prisma.auditEvent.count({
      where: { organizationId: tenant.organization.id, action: 'execution.dispatch_denied' },
    }),
    1,
  );
  assert.equal((await verifyAuditChain(tenant.organization.id)).valid, true);
});

test('an authorization that expired after approval denies dispatch', async () => {
  const tenant = await createTenant({ role: 'OWNER' });
  const engagementId = await activeEngagement(tenant.ctx);
  const expiresAt = future(1);
  await approvedAuthorization(tenant.ctx, engagementId, expiresAt);
  await worker(tenant.ctx);

  const job = await requestExecutionJob(
    tenant.ctx,
    engagementId,
    { capability: 'HTTP_PROBE', targetType: 'DOMAIN', targetValue: 'example.com' },
    {
      resolve: resolveTo('203.0.113.10'),
      now: () => new Date(expiresAt.getTime() + 1000),
    },
  );

  assert.equal(job.status, 'DENIED');
  assert.equal(job.denialReason, 'authorization_expired');
});

test('a DNS answer that changed between dispatch and start denies execution', async () => {
  const tenant = await createTenant({ role: 'OWNER' });
  const engagementId = await activeEngagement(tenant.ctx);
  await approvedAuthorization(tenant.ctx, engagementId);
  await worker(tenant.ctx, ['203.0.113.0/24']);

  const jobId = await queuedJob(tenant.ctx, engagementId, 'example.com', '203.0.113.10');

  const started = await startExecutionJob(tenant.ctx, jobId, {
    resolve: resolveTo('203.0.113.99'),
  });

  assert.equal(started.status, 'DENIED');
  assert.equal(started.denialReason, 'address_changed');

  const detail = await getExecutionJob(tenant.organization.id, jobId);
  const denial = detail.events.find((event) => event.type === 'EXECUTION_DENIED');
  assert.ok(denial);
  assert.match(denial.message, /DNS answer changed/i);
  assert.equal((await verifyAuditChain(tenant.organization.id)).valid, true);
});

test('an unchanged answer still starts, and a removed scope entry denies the start', async () => {
  const tenant = await createTenant({ role: 'OWNER' });
  const engagementId = await activeEngagement(tenant.ctx);
  await approvedAuthorization(tenant.ctx, engagementId);
  await worker(tenant.ctx, ['203.0.113.0/24']);

  const jobId = await queuedJob(tenant.ctx, engagementId, 'example.com', '203.0.113.10');
  const running = await startExecutionJob(tenant.ctx, jobId, {
    resolve: resolveTo('203.0.113.10'),
  });
  assert.equal(running.status, 'RUNNING');

  // Dispatch the second job while the scope still covers the target, then pull
  // the inclusion out from under it. Dispatch alone cannot catch this: the job
  // was authorized when it was created, and only the start-time re-check sees
  // that the rule it depended on is gone.
  const secondJob = await queuedJob(tenant.ctx, engagementId, 'example.com', '203.0.113.10');

  const engagement = await getEngagement(tenant.organization.id, engagementId);
  const include = engagement.scopeEntries.find((entry) => entry.kind === 'INCLUDE');
  assert.ok(include);
  await removeScopeEntry(tenant.ctx, engagementId, include.id);
  const denied = await startExecutionJob(tenant.ctx, secondJob, {
    resolve: resolveTo('203.0.113.10'),
  });
  assert.equal(denied.status, 'DENIED');
  assert.equal(denied.denialReason, 'out_of_scope');
});

test('a worker whose egress allowlist does not cover the target is never selected', async () => {
  const tenant = await createTenant({ role: 'OWNER' });
  const engagementId = await activeEngagement(tenant.ctx);
  await approvedAuthorization(tenant.ctx, engagementId);
  await worker(tenant.ctx, ['198.51.100.0/24']);

  const job = await requestExecutionJob(
    tenant.ctx,
    engagementId,
    { capability: 'HTTP_PROBE', targetType: 'DOMAIN', targetValue: 'example.com' },
    { resolve: resolveTo('203.0.113.10') },
  );

  assert.equal(job.status, 'DENIED');
  assert.equal(job.denialReason, 'no_eligible_worker');
});

test('cancellation of a running job wins over a later success report', async () => {
  const tenant = await createTenant({ role: 'OWNER' });
  const engagementId = await activeEngagement(tenant.ctx);
  await approvedAuthorization(tenant.ctx, engagementId);
  await worker(tenant.ctx, ['203.0.113.0/24']);

  const jobId = await queuedJob(tenant.ctx, engagementId);
  await startExecutionJob(tenant.ctx, jobId, { resolve: resolveTo('203.0.113.10') });

  const cancelled = await cancelExecutionJob(tenant.ctx, jobId, { reason: 'Operator stopped it' });
  assert.equal(cancelled.status, 'RUNNING');
  assert.ok(cancelled.cancelRequestedAt);

  // Asking twice must not move the request time or add a second audit event;
  // the first request is the one the worker has to honour.
  const repeated = await cancelExecutionJob(tenant.ctx, jobId, { reason: 'Again' });
  assert.equal(repeated.status, 'RUNNING');
  assert.equal(repeated.cancelRequestedAt, cancelled.cancelRequestedAt);

  const completed = await completeExecutionJob(tenant.ctx, jobId, { outcome: 'SUCCEEDED' });
  assert.equal(completed.status, 'CANCELLED');
  assert.equal(completed.denialReason, 'cancelled');
});

test('a high-risk job cannot be reviewed by its requester', async () => {
  const tenant = await createTenant({ role: 'OWNER' });
  const admin = await addMember(tenant, 'ADMIN');
  const engagementId = await activeEngagement(tenant.ctx);
  await approvedAuthorization(admin, engagementId);
  await worker(tenant.ctx, ['203.0.113.0/24']);

  const requested = await requestExecutionJob(
    admin,
    engagementId,
    { capability: 'PORT_SCAN', targetType: 'DOMAIN', targetValue: 'example.com' },
    { resolve: resolveTo('203.0.113.10') },
  );
  assert.equal(requested.risk, 'HIGH');
  assert.equal(requested.status, 'PENDING_REVIEW');
  assert.equal(requested.reviewStatus, 'PENDING');

  await expectAppError(
    reviewExecutionJob(admin, requested.id, { decision: 'APPROVED' }),
    { statusCode: 403, code: 'FORBIDDEN' },
  );

  const approved = await reviewExecutionJob(
    tenant.ctx,
    requested.id,
    { decision: 'APPROVED' },
    { resolve: resolveTo('203.0.113.10') },
  );
  assert.equal(approved.status, 'QUEUED');
  assert.equal(approved.reviewStatus, 'APPROVED');
  assert.ok(approved.reviewedBy);
  assert.equal((await verifyAuditChain(tenant.organization.id)).valid, true);
});

test('a rejected high-risk job is denied and never queued', async () => {
  const tenant = await createTenant({ role: 'OWNER' });
  const admin = await addMember(tenant, 'ADMIN');
  const engagementId = await activeEngagement(tenant.ctx);
  await approvedAuthorization(admin, engagementId);
  await worker(tenant.ctx, ['203.0.113.0/24']);

  const requested = await requestExecutionJob(
    admin,
    engagementId,
    { capability: 'PORT_SCAN', targetType: 'DOMAIN', targetValue: 'example.com' },
    { resolve: resolveTo('203.0.113.10') },
  );

  const rejected = await reviewExecutionJob(tenant.ctx, requested.id, {
    decision: 'REJECTED',
    note: 'Too broad for this window',
  });
  assert.equal(rejected.status, 'DENIED');
  assert.equal(rejected.reviewStatus, 'REJECTED');
  assert.equal(rejected.denialReason, 'review_rejected');
});

test('an authorization cannot be approved by its requester or superseded silently', async () => {
  const tenant = await createTenant({ role: 'OWNER' });
  const secondOwner = await addMember(tenant, 'OWNER');
  const engagementId = await activeEngagement(tenant.ctx);

  const first = await requestAuthorization(tenant.ctx, engagementId, {
    expiresAt: future(),
    reference: 'SOW-1',
  });

  await expectAppError(
    decideAuthorization(tenant.ctx, engagementId, first.id, { decision: 'APPROVED' }),
    { statusCode: 403, code: 'FORBIDDEN' },
  );

  await decideAuthorization(secondOwner, engagementId, first.id, { decision: 'APPROVED' });

  const second = await requestAuthorization(tenant.ctx, engagementId, {
    expiresAt: future(),
    reference: 'SOW-2',
  });
  await expectAppError(
    decideAuthorization(secondOwner, engagementId, second.id, { decision: 'APPROVED' }),
    { statusCode: 409, code: 'CONFLICT' },
  );
});

test('a job from another tenant is not readable', async () => {
  const first = await createTenant({ role: 'OWNER' });
  const second = await createTenant({ role: 'OWNER' });
  const engagementId = await activeEngagement(first.ctx);
  await approvedAuthorization(first.ctx, engagementId);
  await worker(first.ctx, ['203.0.113.0/24']);
  const jobId = await queuedJob(first.ctx, engagementId);

  await expectAppError(getExecutionJob(second.organization.id, jobId), { statusCode: 404 });
  await expectAppError(
    requestExecutionJob(
      second.ctx,
      engagementId,
      { capability: 'HTTP_PROBE', targetType: 'DOMAIN', targetValue: 'example.com' },
      { resolve: resolveTo('203.0.113.10') },
    ),
    { statusCode: 404 },
  );
});

test('cleanup closes reviews and queues that can no longer progress', async () => {
  const tenant = await createTenant({ role: 'OWNER' });
  const engagementId = await activeEngagement(tenant.ctx);
  await approvedAuthorization(tenant.ctx, engagementId);
  await worker(tenant.ctx, ['203.0.113.0/24']);

  const jobId = await queuedJob(tenant.ctx, engagementId);
  await prisma.executionJob.update({
    where: { id: jobId },
    data: { createdAt: new Date(Date.now() - 2 * DAY) },
  });

  const summary = await cleanupExecutionJobs(tenant.organization.id);
  assert.equal(summary.staleQueues, 1);

  const job = await getExecutionJob(tenant.organization.id, jobId);
  assert.equal(job.status, 'CANCELLED');
  assert.equal(job.denialReason, 'lease_expired');
  assert.equal((await verifyAuditChain(tenant.organization.id)).valid, true);
});
