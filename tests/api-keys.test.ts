import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import { verifyAuditChain } from '@/server/audit/audit';
import { getAuthenticatedUser, requireTenantContext } from '@/server/authz/context';
import {
  apiKeyStatus,
  hashApiKey,
  isApiKeyShape,
  issueApiKey,
  MAX_ACTIVE_API_KEYS_PER_ORGANIZATION,
} from '@/server/domain/api-keys';
import { createUserApiKey, listUserApiKeys, revokeUserApiKey } from '@/server/services/api-keys';
import { setQuotaOverride } from '@/server/services/quotas';
import {
  assertTestDatabase,
  createTenant,
  expectAppError,
  prisma,
  resetDatabase,
  testMeta,
} from './helpers/database.ts';

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

function bearer(key: string): Headers {
  return new Headers({ authorization: `Bearer ${key}` });
}

test('issued keys are shaped, hashed and bounded', () => {
  const now = new Date('2026-01-01T00:00:00.000Z');
  const issued = issueApiKey(30, now);

  assert.ok(issued.key.startsWith('cnk_'));
  assert.ok(isApiKeyShape(issued.key));
  assert.equal(issued.key.length, 'cnk_'.length + 43);
  assert.equal(issued.hash, hashApiKey(issued.key));
  assert.match(issued.hash, /^[0-9a-f]{64}$/);
  assert.equal(issued.prefix, issued.key.slice(0, 10));
  assert.equal(issued.expiresAt.toISOString(), '2026-01-31T00:00:00.000Z');

  // Two keys never collide and the prefix does not reveal the secret.
  const other = issueApiKey(30, now);
  assert.notEqual(other.key, issued.key);
  assert.equal(issued.prefix.includes(issued.key.slice(10, 20)), false);

  // Malformed values are rejected before any database lookup.
  assert.equal(isApiKeyShape('cnk_short'), false);
  assert.equal(isApiKeyShape('cna_' + 'a'.repeat(43)), false);
});

test('status prefers revocation over expiry', () => {
  const now = new Date('2026-06-01T00:00:00.000Z');
  assert.equal(
    apiKeyStatus({ expiresAt: new Date('2026-07-01T00:00:00.000Z'), revokedAt: null }, now),
    'ACTIVE',
  );
  assert.equal(
    apiKeyStatus({ expiresAt: new Date('2026-05-01T00:00:00.000Z'), revokedAt: null }, now),
    'EXPIRED',
  );
  assert.equal(
    apiKeyStatus(
      {
        expiresAt: new Date('2026-05-01T00:00:00.000Z'),
        revokedAt: new Date('2026-04-01T00:00:00.000Z'),
      },
      now,
    ),
    'REVOKED',
  );
  // Expiry is exclusive: a key is unusable at its exact expiry instant.
  assert.equal(apiKeyStatus({ expiresAt: now, revokedAt: null }, now), 'EXPIRED');
});

test('creating a key stores only the digest and audits the creation', async () => {
  const tenant = await createTenant({ role: 'ANALYST', twoFactorEnabled: true });

  const created = await createUserApiKey(
    tenant.ctx.user,
    { name: 'nightly export', organizationId: tenant.organization.id, expiresInDays: 30 },
    testMeta(),
  );

  assert.ok(created.key.startsWith('cnk_'));
  assert.equal(created.apiKey.status, 'ACTIVE');
  assert.equal(created.apiKey.organization.id, tenant.organization.id);

  const row = await prisma.userApiKey.findUniqueOrThrow({
    where: { id: created.apiKey.id },
    select: {
      keyHash: true,
      keyPrefix: true,
      userId: true,
      organizationId: true,
      expiresAt: true,
      revokedAt: true,
    },
  });

  assert.equal(row.keyHash, hashApiKey(created.key));
  assert.notEqual(row.keyHash, created.key);
  assert.equal(row.keyPrefix, created.key.slice(0, 10));
  assert.equal(row.userId, tenant.ctx.user.id);
  assert.equal(row.organizationId, tenant.organization.id);
  assert.equal(row.revokedAt, null);
  // 30 days, allowing for the few milliseconds between issue and read.
  const ttlMs = row.expiresAt.getTime() - Date.now();
  assert.ok(ttlMs > 29.9 * 86_400_000 && ttlMs <= 30 * 86_400_000, `unexpected ttl ${ttlMs}`);

  const audit = await prisma.auditEvent.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, action: 'api_key.created' },
    select: { actorType: true, actorId: true, targetId: true, metadata: true },
  });
  assert.equal(audit.actorType, 'USER');
  assert.equal(audit.actorId, tenant.ctx.user.id);
  assert.equal(audit.targetId, created.apiKey.id);
  const metadata = JSON.stringify(audit.metadata ?? {});
  assert.equal(metadata.includes(created.key), false, 'the plaintext key must never be audited');
  assert.equal(metadata.includes(row.keyHash), false, 'the digest must never be audited');

  // The list returns metadata only, never the credential.
  const listed = await listUserApiKeys(tenant.ctx.user.id);
  assert.equal(listed.length, 1);
  assert.equal(listed[0]?.prefix, created.apiKey.prefix);
  assert.equal(JSON.stringify(listed).includes(created.key), false);

  const chain = await verifyAuditChain(tenant.organization.id);
  assert.equal(chain.valid, true);
});

test('key creation requires two-factor, an active membership and a free slot', async () => {
  const withoutMfa = await createTenant({ role: 'ANALYST', twoFactorEnabled: false });
  await expectAppError(
    createUserApiKey(
      withoutMfa.ctx.user,
      { name: 'blocked key', organizationId: withoutMfa.organization.id, expiresInDays: 30 },
      testMeta(),
    ),
    { statusCode: 403, code: 'MFA_REQUIRED' },
  );

  const owner = await createTenant({ role: 'ANALYST', twoFactorEnabled: true });
  const outsider = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  await expectAppError(
    createUserApiKey(
      owner.ctx.user,
      { name: 'foreign key', organizationId: outsider.organization.id, expiresInDays: 30 },
      testMeta(),
    ),
    { statusCode: 404 },
  );

  for (let index = 0; index < MAX_ACTIVE_API_KEYS_PER_ORGANIZATION; index += 1) {
    await createUserApiKey(
      owner.ctx.user,
      { name: `key ${index}`, organizationId: owner.organization.id, expiresInDays: 30 },
      testMeta(),
    );
  }
  await expectAppError(
    createUserApiKey(
      owner.ctx.user,
      { name: 'one too many', organizationId: owner.organization.id, expiresInDays: 30 },
      testMeta(),
    ),
    { statusCode: 409 },
  );
});

test('a bearer key authenticates as its owner and is bound to one organization', async () => {
  // The owner belongs to two organizations; the key is issued for the first.
  const first = await createTenant({ role: 'ANALYST', twoFactorEnabled: true });
  const secondSlug = `tenant-second-${first.organization.id.slice(-6)}`;
  await prisma.organization.create({
    data: {
      name: 'Second tenant',
      slug: secondSlug,
      memberships: { create: { userId: first.ctx.user.id, role: 'VIEWER', status: 'ACTIVE' } },
    },
  });

  const created = await createUserApiKey(
    first.ctx.user,
    { name: 'automation', organizationId: first.organization.id, expiresInDays: 30 },
    testMeta(),
  );

  const user = await getAuthenticatedUser(bearer(created.key));
  assert.ok(user);
  assert.equal(user.id, first.ctx.user.id);
  assert.equal(user.sessionId, null);
  assert.deepEqual(user.apiKey, { id: created.apiKey.id, organizationId: first.organization.id });

  // The key works for its own organization...
  const ctx = await requireTenantContext(
    bearer(created.key),
    first.organization.slug,
    'finding.read',
  );
  assert.equal(ctx.organization.id, first.organization.id);
  assert.equal(ctx.membership.role, 'ANALYST');

  // ...and is a 404 for every other organization, including one the owner is in.
  await expectAppError(requireTenantContext(bearer(created.key), secondSlug, 'finding.read'), {
    statusCode: 404,
  });

  // The role is re-read per request: a demotion narrows the key immediately.
  await prisma.membership.update({
    where: {
      userId_organizationId: { userId: first.ctx.user.id, organizationId: first.organization.id },
    },
    data: { role: 'VIEWER' },
  });
  await expectAppError(
    requireTenantContext(bearer(created.key), first.organization.slug, 'finding.create'),
    { statusCode: 403 },
  );

  // Disabling the membership ends the key's access without revoking it.
  await prisma.membership.update({
    where: {
      userId_organizationId: { userId: first.ctx.user.id, organizationId: first.organization.id },
    },
    data: { status: 'DISABLED' },
  });
  await expectAppError(
    requireTenantContext(bearer(created.key), first.organization.slug, 'finding.read'),
    { statusCode: 404 },
  );

  const usage = await prisma.userApiKey.findUniqueOrThrow({
    where: { id: created.apiKey.id },
    select: { lastUsedAt: true },
  });
  assert.ok(usage.lastUsedAt, 'a successful authentication records its last use');
});

test('revoked, expired and tampered credentials are rejected', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const created = await createUserApiKey(
    tenant.ctx.user,
    { name: 'short lived', organizationId: tenant.organization.id, expiresInDays: 7 },
    testMeta(),
  );

  // Tampering with one character of the body changes the digest.
  const tampered = `${created.key.slice(0, -1)}${created.key.endsWith('A') ? 'B' : 'A'}`;
  await expectAppError(getAuthenticatedUser(bearer(tampered)), { statusCode: 401 });

  // A non-bearer Authorization header fails closed instead of falling back to cookies.
  await expectAppError(getAuthenticatedUser(new Headers({ authorization: 'Basic dXNlcjpwYXNz' })), {
    statusCode: 401,
  });

  const expired = await createUserApiKey(
    tenant.ctx.user,
    { name: 'expiring', organizationId: tenant.organization.id, expiresInDays: 7 },
    testMeta(),
  );
  await prisma.userApiKey.update({
    where: { id: expired.apiKey.id },
    data: { expiresAt: new Date(Date.now() - 1000) },
  });
  await expectAppError(getAuthenticatedUser(bearer(expired.key)), { statusCode: 401 });

  const revoked = await revokeUserApiKey(tenant.ctx.user, created.apiKey.id, testMeta());
  assert.equal(revoked.status, 'REVOKED');
  await expectAppError(getAuthenticatedUser(bearer(created.key)), { statusCode: 401 });
  await expectAppError(revokeUserApiKey(tenant.ctx.user, created.apiKey.id, testMeta()), {
    statusCode: 409,
  });

  // Keys are personal: another user cannot revoke them, and the 404 does not
  // confirm the key exists.
  const intruder = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  await expectAppError(revokeUserApiKey(intruder.ctx.user, expired.apiKey.id, testMeta()), {
    statusCode: 404,
  });

  const audit = await prisma.auditEvent.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, action: 'api_key.revoked' },
    select: { actorType: true, actorId: true, targetId: true, metadata: true },
  });
  assert.equal(audit.actorType, 'USER');
  assert.equal(audit.actorId, tenant.ctx.user.id);
  assert.equal(audit.targetId, created.apiKey.id);
  assert.equal((audit.metadata as Record<string, unknown>).via, 'session');
});

test('a key only sees its own organization on /me', async () => {
  const tenant = await createTenant({ role: 'ANALYST', twoFactorEnabled: true });
  const otherOrg = await prisma.organization.create({
    data: {
      name: 'Other tenant',
      slug: `tenant-me-${tenant.organization.id.slice(-6)}`,
      memberships: { create: { userId: tenant.ctx.user.id, role: 'VIEWER', status: 'ACTIVE' } },
    },
    select: { id: true },
  });

  const created = await createUserApiKey(
    tenant.ctx.user,
    { name: 'scoped', organizationId: tenant.organization.id, expiresInDays: 30 },
    testMeta(),
  );

  const [{ GET }, { NextRequest }] = await Promise.all([
    import('@/app/api/v1/me/route'),
    import('next/server'),
  ]);
  const response = await GET(
    new NextRequest('http://localhost:3000/api/v1/me', {
      headers: { authorization: `Bearer ${created.key}` },
    }),
    { params: Promise.resolve({}) },
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.user.id, tenant.ctx.user.id);
  assert.deepEqual(
    body.organizations.map((organization: { id: string }) => organization.id),
    [tenant.organization.id],
    "memberships outside the key's organization must not be listed",
  );
  assert.notEqual(body.organizations[0].id, otherOrg.id);
});

test('a key cannot mint another key', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const created = await createUserApiKey(
    tenant.ctx.user,
    { name: 'self service', organizationId: tenant.organization.id, expiresInDays: 30 },
    testMeta(),
  );

  const keyUser = await getAuthenticatedUser(bearer(created.key));
  assert.ok(keyUser);

  await expectAppError(
    createUserApiKey(
      keyUser,
      { name: 'escalated', organizationId: tenant.organization.id, expiresInDays: 30 },
      testMeta(),
    ),
    { statusCode: 403 },
  );
  assert.equal(await prisma.userApiKey.count({ where: { userId: tenant.ctx.user.id } }), 1);
});

test('an operator-imposed key ceiling stops creation and is audited', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });

  await setQuotaOverride(tenant.organization.id, 'apiKeys', 1, { actorLabel: 'test:quota' });

  await createUserApiKey(
    tenant.ctx.user,
    { name: 'first', organizationId: tenant.organization.id, expiresInDays: 30 },
    testMeta(),
  );

  await expectAppError(
    createUserApiKey(
      tenant.ctx.user,
      { name: 'second', organizationId: tenant.organization.id, expiresInDays: 30 },
      testMeta(),
    ),
    { statusCode: 409, code: 'CONFLICT' },
  );
  assert.equal(
    await prisma.userApiKey.count({ where: { organizationId: tenant.organization.id } }),
    1,
    'a rejected create must not leave a row behind',
  );

  // Clearing the override removes the tenant-wide ceiling; only the per-user
  // constant still applies, so another key is allowed.
  await setQuotaOverride(tenant.organization.id, 'apiKeys', null, { actorLabel: 'test:quota' });
  await createUserApiKey(
    tenant.ctx.user,
    { name: 'third', organizationId: tenant.organization.id, expiresInDays: 30 },
    testMeta(),
  );

  const events = await prisma.auditEvent.findMany({
    where: { organizationId: tenant.organization.id, action: 'quota.override_changed' },
    orderBy: { sequence: 'asc' },
    select: { metadata: true },
  });
  assert.deepEqual(
    events.map((event) => (event.metadata as { limit: number | null }).limit),
    [1, null],
    'the chain must record the applied limit and the cleared one',
  );
  assert.equal((await verifyAuditChain(tenant.organization.id)).valid, true);
});
