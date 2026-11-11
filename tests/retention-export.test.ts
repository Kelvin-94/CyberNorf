import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { before, test } from 'node:test';
import { AuditActions, recordAuditEvent } from '@/server/audit/audit';
import { exportOrganization } from '@/server/services/export';
import { planRetention, purgeRetention } from '@/server/services/retention';
import {
  assertTestDatabase,
  createTenant,
  prisma,
  resetDatabase,
  testMeta,
  type TestTenant,
} from './helpers/database.ts';

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

const NOW = new Date('2026-06-01T00:00:00.000Z');
const RETENTION_DAYS = 30;
const OLD = new Date(NOW.getTime() - 40 * 24 * 60 * 60 * 1000);
const RECENT = new Date(NOW.getTime() - 2 * 24 * 60 * 60 * 1000);

interface Seeded {
  tenant: TestTenant;
  agentId: string;
  oldRunId: string;
  recentRunId: string;
  sentEventId: string;
  pendingEventId: string;
  staleItemId: string;
  freshItemId: string;
}

/**
 * Seeds one tenant with exactly one record on each side of the cutoff: old and
 * recent runs, a terminal and a pending alert, and a stale and a fresh package
 * snapshot. A purge that touches anything on the "keep" side fails the test.
 */
async function seedTenant(): Promise<Seeded> {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const organizationId = tenant.organization.id;

  const agent = await prisma.agent.create({
    data: {
      organizationId,
      name: `builtin-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      source: 'BUILTIN',
      status: 'ACTIVE',
      scopes: ['checks:write'],
      // The database enforces both shapes: a SHA-256 hex digest and a six-character prefix.
      tokenHash: randomBytes(32).toString('hex'),
      tokenPrefix: `cna_${randomBytes(4).toString('base64url').slice(0, 6)}`,
      createdById: tenant.user.id,
    },
    select: { id: true },
  });

  const checks = [
    { id: 'auth.mfa', title: 'Multi-factor authentication', status: 'PASS', severity: 'HIGH' },
  ];

  const oldRun = await prisma.agentRun.create({
    data: {
      organizationId,
      agentId: agent.id,
      status: 'COMPLETED',
      startedAt: OLD,
      checkCount: 1,
      passCount: 1,
      checks,
    },
    select: { id: true },
  });

  const recentRun = await prisma.agentRun.create({
    data: {
      organizationId,
      agentId: agent.id,
      status: 'COMPLETED',
      startedAt: RECENT,
      checkCount: 1,
      passCount: 1,
      checks,
    },
    select: { id: true },
  });

  const channel = await prisma.notificationChannel.create({
    data: {
      organizationId,
      name: `hooks-${Date.now()}`,
      kind: 'WEBHOOK',
      url: 'https://hooks.example.com/cybernorf',
      secretSealed: 'sealed-v1:not-a-real-secret',
      createdById: tenant.user.id,
    },
    select: { id: true },
  });

  const sentEvent = await prisma.notificationEvent.create({
    data: {
      organizationId,
      channelId: channel.id,
      type: 'AGENT_OFFLINE',
      payload: { agentId: agent.id },
      status: 'SENT',
      deliveredAt: OLD,
      createdAt: OLD,
      dedupeKey: `old-${agent.id}`,
    },
    select: { id: true },
  });

  const pendingEvent = await prisma.notificationEvent.create({
    data: {
      organizationId,
      channelId: channel.id,
      type: 'AGENT_OFFLINE',
      payload: { agentId: agent.id },
      status: 'PENDING',
      createdAt: OLD,
      dedupeKey: `pending-${agent.id}`,
    },
    select: { id: true },
  });

  const staleItem = await prisma.softwareItem.create({
    data: {
      organizationId,
      agentId: agent.id,
      ecosystem: 'NPM',
      name: 'cross-spawn',
      version: '7.0.1',
      firstSeenAt: OLD,
      lastSeenAt: OLD,
    },
    select: { id: true },
  });

  const freshItem = await prisma.softwareItem.create({
    data: {
      organizationId,
      agentId: agent.id,
      ecosystem: 'NPM',
      name: 'left-pad',
      version: '1.3.0',
      firstSeenAt: RECENT,
      lastSeenAt: RECENT,
    },
    select: { id: true },
  });

  return {
    tenant,
    agentId: agent.id,
    oldRunId: oldRun.id,
    recentRunId: recentRun.id,
    sentEventId: sentEvent.id,
    pendingEventId: pendingEvent.id,
    staleItemId: staleItem.id,
    freshItemId: freshItem.id,
  };
}

test('retention plan counts expiring rows without deleting anything', async () => {
  const seeded = await seedTenant();
  const organizationId = seeded.tenant.organization.id;

  const plan = await planRetention(organizationId, { days: RETENTION_DAYS, now: NOW });
  assert.deepEqual(
    {
      runs: plan.runs,
      notificationEvents: plan.notificationEvents,
      softwareItems: plan.softwareItems,
    },
    { runs: 1, notificationEvents: 1, softwareItems: 1 },
  );
  assert.equal(
    await prisma.agentRun.count({ where: { organizationId } }),
    2,
    'a dry run must not delete runs',
  );

  const purged = await purgeRetention(
    organizationId,
    { days: RETENTION_DAYS, now: NOW },
    testMeta(),
  );
  assert.deepEqual(purged, plan);

  const runs = await prisma.agentRun.findMany({ where: { organizationId }, select: { id: true } });
  assert.deepEqual(
    runs.map((run) => run.id),
    [seeded.recentRunId],
    'only the run older than the cutoff is removed',
  );

  const events = await prisma.notificationEvent.findMany({
    where: { organizationId },
    select: { id: true, status: true },
  });
  assert.deepEqual(
    events.map((event) => event.id),
    [seeded.pendingEventId],
    'a queued delivery still waiting to be sent is never purged',
  );

  const items = await prisma.softwareItem.findMany({
    where: { organizationId },
    select: { id: true },
  });
  assert.deepEqual(
    items.map((item) => item.id),
    [seeded.freshItemId],
    'a refreshed package snapshot is kept',
  );
});

test('a purge appends retention.purged with the cutoff and the removed counts', async () => {
  const seeded = await seedTenant();
  const organizationId = seeded.tenant.organization.id;

  await purgeRetention(organizationId, { days: RETENTION_DAYS, now: NOW }, testMeta());

  const audit = await prisma.auditEvent.findFirst({
    where: { organizationId, action: AuditActions.RETENTION_PURGED },
    orderBy: { sequence: 'desc' },
  });
  assert.ok(audit, 'the purge must be recorded in the audit chain');
  assert.equal(audit.actorType, 'SYSTEM');
  assert.equal(audit.outcome, 'SUCCESS');
  assert.deepEqual(audit.metadata, {
    days: RETENTION_DAYS,
    cutoff: new Date(NOW.getTime() - RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString(),
    runs: 1,
    notificationEvents: 1,
    softwareItems: 1,
  });
});

test('findings, incidents and audit history survive a purge', async () => {
  const seeded = await seedTenant();
  const organizationId = seeded.tenant.organization.id;

  const finding = await prisma.finding.create({
    data: {
      organizationId,
      title: 'Password authentication is enabled',
      severity: 'HIGH',
      source: 'AGENT',
      fingerprint: `retention-${organizationId}`,
      createdById: seeded.tenant.user.id,
      createdAt: OLD,
      updatedAt: OLD,
    },
    select: { id: true },
  });
  await recordAuditEvent({
    organizationId,
    actorType: 'USER',
    actorId: seeded.tenant.user.id,
    action: AuditActions.FINDING_CREATED,
    outcome: 'SUCCESS',
    targetType: 'finding',
    targetId: finding.id,
    summary: 'Created before the cutoff',
  });

  const auditBefore = await prisma.auditEvent.count({ where: { organizationId } });
  await purgeRetention(organizationId, { days: RETENTION_DAYS, now: NOW }, testMeta());

  assert.equal(await prisma.finding.count({ where: { organizationId, id: finding.id } }), 1);
  assert.equal(
    await prisma.auditEvent.count({ where: { organizationId } }),
    auditBefore + 1,
    'the chain only grows: the purge adds one event and removes none',
  );
});

test('the export carries business records and no credentials', async () => {
  const seeded = await seedTenant();
  const other = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const organizationId = seeded.tenant.organization.id;

  const finding = await prisma.finding.create({
    data: {
      organizationId,
      title: 'Built-in firewall is disabled',
      severity: 'MEDIUM',
      source: 'AGENT',
      fingerprint: `export-${organizationId}`,
      createdById: seeded.tenant.user.id,
    },
    select: { id: true },
  });
  const foreignFinding = await prisma.finding.create({
    data: {
      organizationId: other.organization.id,
      title: 'Another tenant finding',
      severity: 'LOW',
      source: 'MANUAL',
      fingerprint: `export-${other.organization.id}`,
      createdById: other.user.id,
    },
    select: { id: true },
  });

  const payload = await exportOrganization(organizationId);

  assert.equal(payload.meta.format, 'cybernorf.export');
  assert.equal(payload.meta.organization.slug, seeded.tenant.organization.slug);
  assert.equal(payload.meta.counts.findings, 1);
  assert.deepEqual(
    payload.findings.map((row) => (row as { id: string }).id),
    [finding.id],
  );

  const serialized = JSON.stringify(payload);
  assert.ok(
    !serialized.includes(foreignFinding.id),
    'another tenant must not leak into the export',
  );
  // Field names, not words: the meta block explains what is excluded in prose.
  for (const forbidden of [
    'tokenHash',
    'tokenPrefix',
    'secretSealed',
    'passwordHash',
    'twoFactorSecret',
  ]) {
    assert.ok(!serialized.includes(forbidden), `the export must not contain ${forbidden}`);
  }

  const agent = payload.agents[0] as { id: string; scopes: string[] };
  assert.equal(agent.id, seeded.agentId);
  assert.deepEqual(agent.scopes, ['checks:write']);

  const channel = payload.notificationChannels[0] as { url: string };
  assert.equal(channel.url, 'https://hooks.example.com/cybernorf');

  const recorded = await recordAuditEvent({
    organizationId,
    actorType: 'USER',
    actorId: seeded.tenant.user.id,
    action: AuditActions.FINDING_CREATED,
    outcome: 'SUCCESS',
    targetType: 'finding',
    targetId: finding.id,
    summary: 'Created by hand in the export test',
  }).then(() =>
    prisma.auditEvent.findFirstOrThrow({
      where: { organizationId, targetId: finding.id },
      select: { sequence: true, action: true, hash: true },
    }),
  );

  const exportedAgain = await exportOrganization(organizationId);
  const exportedAudit = exportedAgain.auditEvents[0] as {
    sequence: number;
    action: string;
    hash: string;
  };
  assert.deepEqual(
    { sequence: exportedAudit.sequence, action: exportedAudit.action, hash: exportedAudit.hash },
    recorded,
    'the chain leaves the platform with its hashes',
  );
});
