import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import { createAsset } from '@/server/services/assets';
import {
  changeFindingStatus,
  createFinding,
  getFindingDetail,
  importFindings,
  listFindings,
} from '@/server/services/findings';
import {
  assertTestDatabase,
  createTenant,
  expectAppError,
  prisma,
  resetDatabase,
} from './helpers/database.ts';

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

async function seedAsset(tenant: Awaited<ReturnType<typeof createTenant>>, identifier: string) {
  return createAsset(tenant.ctx, {
    name: `Asset ${identifier}`,
    type: 'WEB_APPLICATION',
    identifier,
    description: null,
    criticality: 'HIGH',
    status: 'ACTIVE',
  });
}

test('an analyst registers an asset, records a finding, investigates it, and closes it', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  const asset = await seedAsset(tenant, 'shop.example');

  const finding = await createFinding(tenant.ctx, {
    title: 'Insecure direct object reference in order history',
    severity: 'CRITICAL',
    assetId: asset.id,
    cveId: 'CVE-2026-10001',
    cvssScore: 9.1,
    description: 'Any authenticated user can read other customers orders by changing the order id.',
    remediation: 'Authorize every order lookup against the session subject.',
  });

  await changeFindingStatus(tenant.ctx, finding.id, 'TRIAGED', 'Reproduced with two test accounts');
  await changeFindingStatus(tenant.ctx, finding.id, 'IN_PROGRESS');
  const closed = await changeFindingStatus(
    tenant.ctx,
    finding.id,
    'RESOLVED',
    'Authorization check deployed and verified',
  );
  assert.equal(closed.changed, true);

  const detail = await getFindingDetail(tenant.ctx, finding.id);
  assert.equal(detail.status, 'RESOLVED');
  assert.notEqual(detail.resolvedAt, null);
  assert.equal(detail.description?.startsWith('Any authenticated user'), true);

  const resolved = await listFindings(tenant.organization.id, {
    status: 'RESOLVED',
    page: 1,
    pageSize: 20,
    sort: 'createdAt',
    direction: 'desc',
  });
  assert.equal(resolved.total, 1);

  const history = detail.history.map((event) => event.action);
  assert.deepEqual(history, [
    'finding.created',
    'finding.status_changed',
    'finding.status_changed',
    'finding.status_changed',
  ]);
  const resolvedEvent = detail.history.at(-1);
  assert.equal(resolvedEvent?.actor?.name, tenant.user.name);
});

test('invalid lifecycle moves are rejected with a conflict', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  const asset = await seedAsset(tenant, 'conflict.example');
  const finding = await createFinding(tenant.ctx, {
    title: 'Missing security headers',
    severity: 'LOW',
    assetId: asset.id,
  });

  await changeFindingStatus(
    tenant.ctx,
    finding.id,
    'FALSE_POSITIVE',
    'Reported by an unauthenticated scanner',
  );
  await expectAppError(changeFindingStatus(tenant.ctx, finding.id, 'IN_PROGRESS'), {
    statusCode: 409,
    code: 'CONFLICT',
  });
});

test('a manual finding cannot be duplicated inside one organization', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  const asset = await seedAsset(tenant, 'duplicate.example');

  await createFinding(tenant.ctx, {
    title: 'Weak TLS configuration',
    severity: 'MEDIUM',
    assetId: asset.id,
  });

  await expectAppError(
    createFinding(tenant.ctx, {
      title: 'weak tls configuration',
      severity: 'MEDIUM',
      assetId: asset.id,
    }),
    { statusCode: 409, code: 'CONFLICT' },
  );
});

test('imports deduplicate by fingerprint and report unresolved assets per item', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  const asset = await seedAsset(tenant, 'import.example');

  const first = await importFindings(tenant.ctx, [
    {
      title: 'Reflected cross-site scripting in search',
      severity: 'HIGH',
      assetIdentifier: asset.identifier,
    },
    {
      title: 'Publicly readable storage bucket',
      severity: 'MEDIUM',
      assetIdentifier: 'unknown.example',
    },
  ]);
  assert.equal(first.created, 1);
  assert.equal(first.updated, 0);
  assert.equal(first.skipped.length, 1);
  assert.equal(first.skipped[0]?.reason, 'asset_identifier_not_found');

  const second = await importFindings(tenant.ctx, [
    {
      title: 'Reflected cross-site scripting in search',
      severity: 'HIGH',
      assetIdentifier: asset.identifier,
    },
  ]);
  assert.equal(second.created, 0);
  assert.equal(second.updated, 1);

  assert.equal(
    await prisma.finding.count({
      where: { organizationId: tenant.organization.id, source: 'IMPORT' },
    }),
    1,
  );

  const imported = await prisma.finding.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, source: 'IMPORT' },
    select: { assetId: true, status: true, id: true },
  });
  assert.equal(imported.assetId, asset.id);
  assert.equal(imported.status, 'OPEN');

  const importEvents = await prisma.auditEvent.count({
    where: { organizationId: tenant.organization.id, targetId: imported.id },
  });
  assert.ok(importEvents >= 1, 'imported findings must appear in the audit trail');
});

test('imports cannot reference assets from another organization', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  const other = await createTenant({ role: 'ANALYST' });
  const foreignAsset = await seedAsset(other, 'foreign.example');

  const result = await importFindings(tenant.ctx, [
    { title: 'Cross tenant import attempt', severity: 'HIGH', assetId: foreignAsset.id },
  ]);
  assert.equal(result.created, 0);
  assert.equal(result.skipped[0]?.reason, 'asset_not_found');
  assert.equal(
    await prisma.finding.count({ where: { organizationId: tenant.organization.id } }),
    0,
  );
});
