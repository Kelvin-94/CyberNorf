import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import { verifyAuditChain } from '@/server/audit/audit';
import { createAsset } from '@/server/services/assets';
import { changeFindingStatus, createFinding } from '@/server/services/findings';
import { assertTestDatabase, createTenant, prisma, resetDatabase } from './helpers/database.ts';

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

async function expectDatabaseRejection(statement: Promise<unknown>): Promise<string> {
  try {
    await statement;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error('Expected the database to reject this statement, but it succeeded.');
}

test('every mutation appends a linked, verifiable audit event', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });

  const asset = await createAsset(tenant.ctx, {
    name: 'Acme customer portal',
    type: 'WEB_APPLICATION',
    identifier: 'portal.acme.example',
    description: null,
    criticality: 'HIGH',
    status: 'ACTIVE',
  });
  const finding = await createFinding(tenant.ctx, {
    title: 'Stored XSS in profile bio',
    severity: 'HIGH',
    assetId: asset.id,
  });
  await changeFindingStatus(tenant.ctx, finding.id, 'TRIAGED', 'Confirmed by manual review');

  const events = await prisma.auditEvent.findMany({
    where: { organizationId: tenant.organization.id },
    orderBy: { sequence: 'asc' },
    select: {
      sequence: true,
      action: true,
      outcome: true,
      prevHash: true,
      hash: true,
      actorId: true,
      requestId: true,
    },
  });

  assert.deepEqual(
    events.map((event) => event.action),
    ['asset.created', 'finding.created', 'finding.status_changed'],
  );
  assert.deepEqual(
    events.map((event) => event.sequence),
    [1, 2, 3],
  );
  assert.equal(events[0]?.prevHash, null);

  for (const [index, event] of events.entries()) {
    if (index > 0) {
      assert.equal(
        event.prevHash,
        events[index - 1]?.hash,
        `sequence ${event.sequence} must link to its predecessor`,
      );
    }
    assert.equal(event.outcome, 'SUCCESS');
    assert.equal(event.actorId, tenant.user.id);
    assert.equal(typeof event.hash, 'string');
    assert.equal(event.hash?.length, 64);
  }

  const verification = await verifyAuditChain(tenant.organization.id);
  assert.equal(verification.valid, true);
  assert.equal(verification.checked, 3);
});

test('audit rows cannot be updated through the application database role', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  await createAsset(tenant.ctx, {
    name: 'Immutable audit target',
    type: 'DOMAIN',
    identifier: 'immutable.example',
    description: null,
    criticality: 'LOW',
    status: 'ACTIVE',
  });

  const message = await expectDatabaseRejection(
    prisma.$executeRaw`UPDATE "audit_events" SET "summary" = 'tampered' WHERE "organizationId" = ${tenant.organization.id}`,
  );
  assert.match(message, /append-only/);

  const summaries = await prisma.auditEvent.findMany({
    where: { organizationId: tenant.organization.id },
    select: { summary: true },
  });
  assert.equal(summaries.length, 1);
  assert.notEqual(summaries[0]?.summary, 'tampered');
});

test('audit rows cannot be deleted through the application database role', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  await createAsset(tenant.ctx, {
    name: 'Deletion target',
    type: 'DOMAIN',
    identifier: 'deletion.example',
    description: null,
    criticality: 'LOW',
    status: 'ACTIVE',
  });

  const message = await expectDatabaseRejection(
    prisma.$executeRaw`DELETE FROM "audit_events" WHERE "organizationId" = ${tenant.organization.id}`,
  );
  assert.match(message, /append-only/);
  assert.equal(
    await prisma.auditEvent.count({ where: { organizationId: tenant.organization.id } }),
    1,
  );
});

test('chains are independent per organization and stay valid after rejected tampering', async () => {
  const first = await createTenant({ role: 'ANALYST' });
  const second = await createTenant({ role: 'ANALYST' });

  for (const tenant of [first, second]) {
    await createAsset(tenant.ctx, {
      name: `Asset for ${tenant.organization.slug}`,
      type: 'DOMAIN',
      identifier: `${tenant.organization.slug}.example`,
      description: null,
      criticality: 'MEDIUM',
      status: 'ACTIVE',
    });
  }

  await expectDatabaseRejection(
    prisma.$executeRaw`UPDATE "audit_events" SET "hash" = 'deadbeef' WHERE "organizationId" = ${first.organization.id}`,
  );

  for (const tenant of [first, second]) {
    const verification = await verifyAuditChain(tenant.organization.id);
    assert.equal(verification.valid, true, `${tenant.organization.slug} chain should remain valid`);
    assert.equal(verification.checked, 1);
  }

  const sequences = await prisma.auditEvent.findMany({
    where: { organizationId: { in: [first.organization.id, second.organization.id] } },
    select: { organizationId: true, sequence: true },
  });
  for (const organizationId of [first.organization.id, second.organization.id]) {
    assert.deepEqual(
      sequences.filter((row) => row.organizationId === organizationId).map((row) => row.sequence),
      [1],
    );
  }
});
