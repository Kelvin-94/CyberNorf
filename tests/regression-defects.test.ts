import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { before, test } from 'node:test';
import { createAsset, deleteAsset } from '@/server/services/assets';
import { importFindings, updateFinding } from '@/server/services/findings';
import { addMember, removeMember } from '@/server/services/members';
import { createOrganization, listUserOrganizations } from '@/server/services/organizations';
import {
  assertTestDatabase,
  createTenant,
  createUser,
  prisma,
  resetDatabase,
  testMeta,
} from './helpers/database.ts';

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

async function seedSession(userId: string): Promise<string> {
  const id = `ses_${randomUUID()}`;
  await prisma.session.create({
    data: {
      id,
      token: `tok_${randomUUID()}`,
      userId,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    },
  });
  return id;
}

test('repeating a finding inside one import payload is skipped, not fatal', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  await createAsset(tenant.ctx, {
    name: 'API gateway',
    type: 'WEB_APPLICATION',
    identifier: 'api.example',
    description: null,
    criticality: 'MEDIUM',
    status: 'ACTIVE',
  });

  const result = await importFindings(tenant.ctx, [
    { title: 'Missing rate limiting', severity: 'MEDIUM', assetIdentifier: 'api.example' },
    { title: '  missing   RATE limiting ', severity: 'HIGH', assetIdentifier: 'api.example' },
  ]);

  assert.equal(result.created, 1);
  assert.deepEqual(
    result.skipped.map((entry) => entry.reason),
    ['duplicate_in_payload'],
  );
  assert.equal(
    await prisma.finding.count({ where: { organizationId: tenant.organization.id } }),
    1,
  );
});

test('concurrent imports of the same batch both succeed', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  const items = [
    { title: 'Expired TLS certificate', severity: 'HIGH' as const },
    { title: 'Directory listing enabled', severity: 'LOW' as const },
  ];

  const [first, second] = await Promise.all([
    importFindings(tenant.ctx, items),
    importFindings(tenant.ctx, items),
  ]);

  assert.equal(first.created + second.created, 2);
  assert.equal(first.updated + second.updated, 2);
  assert.equal(
    await prisma.finding.count({ where: { organizationId: tenant.organization.id } }),
    2,
  );
});

test('renaming a finding keeps re-imports deduplicated', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  const asset = await createAsset(tenant.ctx, {
    name: 'Storefront',
    type: 'WEB_APPLICATION',
    identifier: 'store.example',
    description: null,
    criticality: 'HIGH',
    status: 'ACTIVE',
  });

  const first = await importFindings(tenant.ctx, [
    { title: 'Beta title', severity: 'HIGH', assetId: asset.id },
  ]);
  assert.equal(first.created, 1);

  const finding = await prisma.finding.findFirstOrThrow({
    where: { organizationId: tenant.organization.id },
    select: { id: true, fingerprint: true },
  });

  await updateFinding(tenant.ctx, finding.id, { title: 'Alpha title' });

  const reimport = await importFindings(tenant.ctx, [
    { title: 'Alpha title', severity: 'HIGH', assetId: asset.id },
  ]);

  assert.equal(reimport.created, 0);
  assert.equal(reimport.updated, 1);
  const refreshed = await prisma.finding.findUniqueOrThrow({
    where: { id: finding.id },
    select: { lastSeenAt: true, title: true },
  });
  assert.equal(refreshed.title, 'Alpha title');
  assert.ok(
    refreshed.lastSeenAt.getTime() >= new Date(Date.now() - 60_000).getTime(),
    'the re-import should have refreshed lastSeenAt instead of inserting a duplicate',
  );
});

test('findings survive asset deletion and stay matched by imports', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });
  const asset = await createAsset(tenant.ctx, {
    name: 'Legacy host',
    type: 'HOSTNAME',
    identifier: 'legacy.example',
    description: null,
    criticality: 'LOW',
    status: 'ACTIVE',
  });

  const imported = await importFindings(tenant.ctx, [
    { title: 'Unpatched kernel', severity: 'HIGH', assetId: asset.id },
  ]);
  assert.equal(imported.created, 1);

  await deleteAsset(tenant.ctx, asset.id);

  const survivor = await prisma.finding.findFirstOrThrow({
    where: { organizationId: tenant.organization.id },
    select: { id: true, assetId: true },
  });
  assert.equal(survivor.assetId, null, 'deleting an asset must detach, not delete, its findings');

  const reimport = await importFindings(tenant.ctx, [
    { title: 'Unpatched kernel', severity: 'HIGH' },
  ]);
  assert.equal(reimport.created, 0, 'the orphaned finding should still match by fingerprint');
  assert.equal(reimport.updated, 1);
});

test('removing a member from one organization does not sign them out elsewhere', async () => {
  const owner = await createTenant({ role: 'OWNER' });
  const shared = await createTenant({ role: 'ANALYST' });

  await prisma.membership.create({
    data: { userId: shared.user.id, organizationId: owner.organization.id, role: 'ANALYST' },
  });

  const sessionId = await seedSession(shared.user.id);
  const membership = await prisma.membership.findUniqueOrThrow({
    where: {
      userId_organizationId: { userId: shared.user.id, organizationId: owner.organization.id },
    },
    select: { id: true },
  });

  await removeMember(owner.ctx, membership.id);

  const remaining = await prisma.session.findUnique({
    where: { id: sessionId },
    select: { id: true },
  });
  assert.ok(remaining, 'the user still belongs to another organization and must stay signed in');

  const memberships = await listUserOrganizations(shared.user.id);
  assert.deepEqual(
    memberships.map((organization) => organization.slug),
    [shared.organization.slug],
  );
});

test('removing the last membership revokes every session', async () => {
  const owner = await createTenant({ role: 'OWNER' });
  const outsider = await createTenant({ role: 'VIEWER' });

  await prisma.membership.create({
    data: { userId: outsider.user.id, organizationId: owner.organization.id, role: 'VIEWER' },
  });
  await prisma.membership.updateMany({
    where: { userId: outsider.user.id, organizationId: outsider.organization.id },
    data: { status: 'DISABLED' },
  });

  const sessionId = await seedSession(outsider.user.id);
  const membership = await prisma.membership.findUniqueOrThrow({
    where: {
      userId_organizationId: { userId: outsider.user.id, organizationId: owner.organization.id },
    },
    select: { id: true },
  });

  await removeMember(owner.ctx, membership.id);

  const remaining = await prisma.session.findUnique({
    where: { id: sessionId },
    select: { id: true },
  });
  assert.equal(remaining, null, 'a user with no remaining membership must be signed out');
});

test('organization member counts ignore disabled memberships', async () => {
  const owner = await createTenant({ role: 'OWNER' });
  const guest = await createUser();

  await prisma.membership.create({
    data: {
      userId: guest.id,
      organizationId: owner.organization.id,
      role: 'VIEWER',
      status: 'DISABLED',
    },
  });

  const summary = (await listUserOrganizations(owner.user.id)).find(
    (organization) => organization.id === owner.organization.id,
  );
  assert.ok(summary);
  assert.equal(summary.memberCount, 1);
});

test('organization slugs stay unique when names collide', async () => {
  const user = await createUser();
  const first = await createOrganization(user, { name: 'Acme Security' }, testMeta());
  const second = await createOrganization(user, { name: 'Acme Security' }, testMeta());

  assert.equal(first.slug, 'acme-security');
  assert.equal(second.slug, 'acme-security-2');
  assert.notEqual(first.id, second.id);
});

test('updating a scored finding succeeds and audits a JSON-safe snapshot', async () => {
  // Regression: the audit snapshot of a finding used to carry Prisma's Decimal
  // for cvssScore. Decimal is a class instance, so redaction copied an
  // enumerable `constructor` function into the metadata and Prisma refused to
  // serialise it, turning every severity change into a 500.
  const tenant = await createTenant({ role: 'ANALYST' });
  const asset = await createAsset(tenant.ctx, {
    name: 'Gateway',
    type: 'WEB_APPLICATION',
    identifier: 'gw.example',
    description: null,
    criticality: 'HIGH',
    status: 'ACTIVE',
  });

  await importFindings(tenant.ctx, [
    { title: 'Reflected XSS', severity: 'HIGH', assetId: asset.id, cvssScore: 7.5 },
  ]);
  const finding = await prisma.finding.findFirstOrThrow({
    where: { organizationId: tenant.organization.id },
    select: { id: true, riskScore: true, dueAt: true, firstSeenAt: true },
  });

  const updated = await updateFinding(tenant.ctx, finding.id, {
    severity: 'CRITICAL',
    remediation: 'Encode output.',
  });

  assert.equal(updated.severity, 'CRITICAL');
  // Re-scored and re-scheduled from the same first observation.
  assert.ok(updated.riskScore > finding.riskScore);
  assert.deepEqual(
    updated.dueAt,
    new Date(finding.firstSeenAt.getTime() + 7 * 86_400_000),
    'CRITICAL deadline should be seven days from first seen',
  );

  const event = await prisma.auditEvent.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, action: 'finding.updated' },
    select: { metadata: true },
  });
  const before = (event.metadata as { before?: Record<string, unknown> }).before;
  assert.ok(before);
  assert.equal(before.cvssScore, 7.5);
  // Whatever the snapshot holds, it must survive a JSON round trip.
  assert.deepEqual(JSON.parse(JSON.stringify(event.metadata)), event.metadata);
});

test('members are resolved regardless of email case', async () => {
  const owner = await createTenant({ role: 'OWNER' });
  const candidate = await createUser();

  const added = await addMember(owner.ctx, {
    email: candidate.email.toUpperCase(),
    role: 'ANALYST',
  });

  assert.equal(added.userId, candidate.id);
  assert.equal(added.role, 'ANALYST');
});
