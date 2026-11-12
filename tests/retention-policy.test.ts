import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { before, test } from 'node:test';
import { verifyAuditChain } from '@/server/audit/audit';
import {
  DEFAULT_RETENTION_POLICY,
  RETENTION_POLICY_BOUNDS,
  enforceRetentionSchedules,
  getRetentionPolicy,
  planRetentionPolicy,
  purgeRetentionPolicy,
  updateRetentionPolicy,
  type RetentionPolicy,
} from '@/server/services/retention';
import {
  assertTestDatabase,
  createTenant,
  expectAppError,
  prisma,
  resetDatabase,
} from './helpers/database.ts';

const DAY = 24 * 60 * 60 * 1000;

function daysAgo(days: number): Date {
  return new Date(Date.now() - days * DAY);
}

/**
 * Seeds a job in a chosen state. Retention only deletes terminal jobs, so the
 * tests need rows that differ in exactly one dimension: status and finish time.
 */
async function seedJob(options: {
  organizationId: string;
  userId: string;
  status: 'SUCCEEDED' | 'FAILED' | 'RUNNING';
  finishedAt: Date | null;
}): Promise<string> {
  const engagement = await prisma.engagement.create({
    data: {
      organizationId: options.organizationId,
      name: `retention-${randomUUID()}`,
      status: 'ACTIVE',
      startsAt: daysAgo(30),
      endsAt: new Date(Date.now() + 30 * DAY),
      createdById: options.userId,
    },
    select: { id: true },
  });
  const authorization = await prisma.engagementAuthorization.create({
    data: {
      organizationId: options.organizationId,
      engagementId: engagement.id,
      status: 'APPROVED',
      requestedById: options.userId,
      expiresAt: new Date(Date.now() + 30 * DAY),
    },
    select: { id: true },
  });
  const job = await prisma.executionJob.create({
    data: {
      organizationId: options.organizationId,
      engagementId: engagement.id,
      authorizationId: authorization.id,
      capability: 'DNS_LOOKUP',
      targetType: 'DOMAIN',
      targetValue: 'example.com',
      requestedById: options.userId,
      risk: 'LOW',
      status: options.status,
      approvedAddresses: [],
      limits: {},
      ...(options.finishedAt ? { finishedAt: options.finishedAt } : {}),
    },
    select: { id: true },
  });
  return job.id;
}

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

test('a tenant starts on the defaults and saving a policy is audited', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });

  const initial = await getRetentionPolicy(tenant.organization.id);
  assert.equal(initial.customised, false);
  assert.deepEqual(initial.policy, DEFAULT_RETENTION_POLICY);
  assert.equal(initial.updatedBy, null);

  const policy: RetentionPolicy = {
    agentRunDays: 30,
    notificationEventDays: 45,
    softwareItemDays: 365,
    executionJobDays: 400,
  };
  const saved = await updateRetentionPolicy(tenant.ctx, policy);
  assert.equal(saved.customised, true);
  assert.deepEqual(saved.policy, policy);
  assert.equal(saved.updatedBy?.id, tenant.user.id);
  assert.ok(saved.updatedAt);

  const reread = await getRetentionPolicy(tenant.organization.id);
  assert.deepEqual(reread.policy, policy, 'the policy survives a second read');

  const chain = await verifyAuditChain(tenant.organization.id);
  assert.equal(chain.valid, true);

  const audit = await prisma.auditEvent.findFirst({
    where: { organizationId: tenant.organization.id, action: 'retention.policy_updated' },
    orderBy: { sequence: 'desc' },
  });
  assert.ok(audit, 'policy changes are part of the chain');
  assert.equal(audit.outcome, 'SUCCESS');
});

test('windows outside the supported range are rejected', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });

  await expectAppError(
    updateRetentionPolicy(tenant.ctx, {
      ...DEFAULT_RETENTION_POLICY,
      agentRunDays: RETENTION_POLICY_BOUNDS.minDays - 1,
    }),
    { statusCode: 400 },
  );

  await expectAppError(
    updateRetentionPolicy(tenant.ctx, {
      ...DEFAULT_RETENTION_POLICY,
      executionJobDays: RETENTION_POLICY_BOUNDS.maxDays + 1,
    }),
    { statusCode: 400 },
  );

  const unchanged = await getRetentionPolicy(tenant.organization.id);
  assert.equal(unchanged.customised, false, 'a rejected update writes nothing');
});

test('the preview counts only terminal jobs past the window and purge keeps live work', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const { organization, user } = tenant;

  const expired = await seedJob({
    organizationId: organization.id,
    userId: user.id,
    status: 'SUCCEEDED',
    finishedAt: daysAgo(400),
  });
  const recent = await seedJob({
    organizationId: organization.id,
    userId: user.id,
    status: 'FAILED',
    finishedAt: daysAgo(1),
  });
  const running = await seedJob({
    organizationId: organization.id,
    userId: user.id,
    status: 'RUNNING',
    finishedAt: null,
  });

  const policy: RetentionPolicy = { ...DEFAULT_RETENTION_POLICY, executionJobDays: 365 };
  const preview = await planRetentionPolicy(organization.id, { policy });
  assert.equal(preview.counts.executionJobs, 1, 'only the terminal job past the window counts');

  const result = await purgeRetentionPolicy(tenant.ctx, { policy });
  assert.equal(result.counts.executionJobs, 1);

  const remaining = await prisma.executionJob.findMany({
    where: { organizationId: organization.id },
    select: { id: true },
  });
  const ids = remaining.map((row) => row.id);
  assert.equal(ids.includes(expired), false, 'the expired job is gone');
  assert.equal(ids.includes(recent), true, 'a job inside its window is kept');
  assert.equal(ids.includes(running), true, 'a running job is never deleted');

  const after = await planRetentionPolicy(organization.id, { policy });
  assert.equal(after.counts.executionJobs, 0);

  const audit = await prisma.auditEvent.findFirst({
    where: { organizationId: organization.id, action: 'retention.purged' },
    orderBy: { sequence: 'desc' },
  });
  assert.ok(audit);
  assert.match(audit.summary ?? '', /1 execution jobs/);
  assert.equal((await verifyAuditChain(organization.id)).valid, true);
});

test('the scheduled sweep enforces saved policies only and audits itself', async () => {
  const configured = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const untouched = await createTenant({ role: 'OWNER', twoFactorEnabled: true });

  const seedRun = async (tenant: typeof configured, name: string): Promise<void> => {
    const agent = await prisma.agent.create({
      data: {
        organizationId: tenant.organization.id,
        name,
        source: 'BUILTIN',
        status: 'ACTIVE',
        createdById: tenant.user.id,
      },
      select: { id: true },
    });
    await prisma.agentRun.create({
      data: {
        organizationId: tenant.organization.id,
        agentId: agent.id,
        status: 'COMPLETED',
        startedAt: daysAgo(120),
        finishedAt: daysAgo(120),
        checks: [],
        checkCount: 1,
        passCount: 1,
      },
    });
  };

  await seedRun(configured, 'sweep-configured');
  await seedRun(untouched, 'sweep-untouched');

  await updateRetentionPolicy(configured.ctx, {
    ...DEFAULT_RETENTION_POLICY,
    agentRunDays: 30,
  });

  const first = await enforceRetentionSchedules();
  assert.equal(first.errors.length, 0);
  assert.ok(first.organizationsChecked >= 1);
  assert.equal(first.counts.runs, 1, 'only the configured tenant had a run past its window');

  assert.equal(
    await prisma.agentRun.count({ where: { organizationId: configured.organization.id } }),
    0,
  );
  assert.equal(
    await prisma.agentRun.count({ where: { organizationId: untouched.organization.id } }),
    1,
    'a tenant that never saved a policy keeps its history',
  );

  const audit = await prisma.auditEvent.findFirst({
    where: { organizationId: configured.organization.id, action: 'retention.purged' },
    orderBy: { sequence: 'desc' },
  });
  assert.ok(audit);
  assert.equal(audit.actorType, 'SYSTEM');
  assert.equal(audit.actorId, null);
  assert.equal((audit.metadata as { trigger?: string }).trigger, 'schedule');
  assert.equal((await verifyAuditChain(configured.organization.id)).valid, true);

  // Nothing is due on the next pass, and silence is the correct outcome: no
  // second audit entry to page anyone about.
  const eventsBefore = await prisma.auditEvent.count({
    where: { organizationId: configured.organization.id },
  });
  const second = await enforceRetentionSchedules();
  assert.equal(second.counts.runs, 0);
  assert.equal(
    await prisma.auditEvent.count({ where: { organizationId: configured.organization.id } }),
    eventsBefore,
  );
});

test('an administrator can change the policy but cannot purge history', async () => {
  const tenant = await createTenant({ role: 'ADMIN', twoFactorEnabled: true });

  const saved = await updateRetentionPolicy(tenant.ctx, {
    ...DEFAULT_RETENTION_POLICY,
    softwareItemDays: 120,
  });
  assert.equal(saved.policy.softwareItemDays, 120);

  await expectAppError(purgeRetentionPolicy(tenant.ctx), { statusCode: 403 });
});
