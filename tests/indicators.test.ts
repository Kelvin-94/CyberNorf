import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import { verifyAuditChain } from '@/server/audit/audit';
import {
  createIndicator,
  getIndicatorDetail,
  importIndicators,
  linkIndicator,
  listIndicators,
} from '@/server/services/indicators';
import {
  assertTestDatabase,
  createTenant,
  expectAppError,
  prisma,
  resetDatabase,
} from './helpers/database.ts';

/**
 * Indicators are only useful if the same value from two sources stays one row,
 * if provenance survives a refresh, and if a link can never cross a tenant
 * boundary. These tests exercise those three properties against the database.
 */

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

const DAY = 24 * 60 * 60 * 1000;

test('creating an indicator normalises the value and keeps the published spelling', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });

  const indicator = await createIndicator(tenant.ctx, {
    value: 'Evil.Example.',
    sourceName: 'Phishing report 42',
    confidence: 85,
  });

  assert.equal(indicator.type, 'DOMAIN');
  assert.equal(indicator.value, 'evil.example', 'stored value is normalised for matching');
  assert.equal(indicator.displayValue, 'Evil.Example', 'the published casing is preserved');
  assert.equal(indicator.sourceName, 'Phishing report 42');
  assert.equal(indicator.confidence, 85);

  const detail = await getIndicatorDetail(tenant.ctx, indicator.id);
  assert.equal(detail.indicator.id, indicator.id);
  assert.equal(detail.indicator.linkCount, 0);

  const chain = await verifyAuditChain(tenant.organization.id);
  assert.equal(chain.valid, true, 'recording an indicator leaves a verifiable audit chain');
});

test('a duplicate indicator is a conflict rather than a silent overwrite', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  const first = await createIndicator(tenant.ctx, {
    value: 'duplicate.example',
    sourceName: 'First source',
  });

  await expectAppError(
    createIndicator(tenant.ctx, { value: 'DUPLICATE.example', sourceName: 'Second source' }),
    { statusCode: 409 },
  );

  const stored = await prisma.indicator.findMany({
    where: { organizationId: tenant.organization.id },
  });
  assert.equal(stored.length, 1);
  assert.equal(stored[0]?.id, first.id, 'the existing row is untouched');
  assert.equal(stored[0]?.sourceName, 'First source');
});

test('a malformed value is rejected with 400 and nothing is written', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });

  await expectAppError(
    createIndicator(tenant.ctx, { value: 'this is not an indicator', sourceName: 'Bad feed' }),
    { statusCode: 400 },
  );

  assert.equal(await prisma.indicator.count({ where: { organizationId: tenant.organization.id } }), 0);
});

test('an import creates new values, refreshes seen ones and reports bad lines', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  const firstSeen = new Date(Date.now() - 30 * DAY);
  const existing = await createIndicator(tenant.ctx, {
    value: 'seen-before.example',
    sourceName: 'Original report',
    firstSeenAt: firstSeen,
    lastSeenAt: firstSeen,
  });

  const result = await importIndicators(tenant.ctx, {
    sourceName: 'Weekly feed',
    sourceKind: 'IMPORT',
    indicators: [
      { value: 'seen-before.example' },
      { value: '203.0.113.7' },
      { value: 'not a value' },
    ],
  });

  assert.deepEqual(
    { created: result.created, refreshed: result.refreshed, rejected: result.rejected.length },
    { created: 1, refreshed: 1, rejected: 1 },
  );
  assert.equal(result.rejected[0]?.index, 2, 'the rejected line keeps its input position');

  const refreshed = await prisma.indicator.findUniqueOrThrow({ where: { id: existing.id } });
  assert.equal(refreshed.sourceName, 'Weekly feed', 'the most recent source wins');
  assert.equal(refreshed.sourceKind, 'IMPORT');
  assert.ok(refreshed.lastSeenAt.getTime() > firstSeen.getTime(), 'last seen moves forward');
  assert.equal(
    refreshed.firstSeenAt.getTime(),
    firstSeen.getTime(),
    'first seen is never rewritten by a later import',
  );

  const page = await listIndicators(tenant.organization.id, {
    page: 1,
    pageSize: 10,
    sort: 'lastSeenAt',
    direction: 'desc',
  });
  assert.equal(page.total, 2);
});

test('a link cannot attach an indicator to another tenant record', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  const other = await createTenant({ role: 'ADMIN' });
  const indicator = await createIndicator(tenant.ctx, {
    value: 'linked.example',
    sourceName: 'Case notes',
  });
  const finding = await prisma.finding.create({
    data: {
      organizationId: tenant.organization.id,
      title: 'Beacon observed in proxy logs',
      severity: 'HIGH',
      source: 'AGENT',
      fingerprint: `indicator-link-${tenant.organization.id}`,
      createdById: tenant.user.id,
    },
    select: { id: true },
  });
  const foreignFinding = await prisma.finding.create({
    data: {
      organizationId: other.organization.id,
      title: 'Another tenant finding',
      severity: 'LOW',
      source: 'MANUAL',
      fingerprint: `indicator-link-${other.organization.id}`,
      createdById: other.user.id,
    },
    select: { id: true },
  });

  await expectAppError(
    linkIndicator(tenant.ctx, indicator.id, { findingId: foreignFinding.id }),
    { statusCode: 404 },
  );
  assert.equal(
    await prisma.indicatorLink.count({ where: { organizationId: tenant.organization.id } }),
    0,
  );

  const link = await linkIndicator(tenant.ctx, indicator.id, {
    findingId: finding.id,
    relation: 'OBSERVED',
    note: 'Same session id',
  });
  assert.equal(link.relation, 'OBSERVED');

  await expectAppError(linkIndicator(tenant.ctx, indicator.id, { findingId: finding.id }), {
    statusCode: 409,
  });

  await expectAppError(getIndicatorDetail(other.ctx, indicator.id), { statusCode: 404 });
});

test('an indicator quota override is enforced on create and on import', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  await prisma.organizationQuota.create({
    data: { organizationId: tenant.organization.id, indicators: 1 },
  });

  await createIndicator(tenant.ctx, { value: 'first.example', sourceName: 'Feed' });

  await expectAppError(
    createIndicator(tenant.ctx, { value: 'second.example', sourceName: 'Feed' }),
    { statusCode: 409 },
  );
  await expectAppError(
    importIndicators(tenant.ctx, {
      sourceName: 'Bulk feed',
      indicators: [{ value: 'third.example' }, { value: 'fourth.example' }],
    }),
    { statusCode: 409 },
  );

  assert.equal(
    await prisma.indicator.count({ where: { organizationId: tenant.organization.id } }),
    1,
    'a rejected import writes nothing',
  );
});
