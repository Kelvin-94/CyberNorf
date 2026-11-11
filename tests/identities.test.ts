import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { before, test } from 'node:test';
import {
  canTransitionIdentity,
  evaluateIdentityRisk,
  hashIdentityCredential,
  initialIdentityStatus,
  isIdentityCredentialShape,
  issueIdentityCredential,
  normalizeIdentityIdentifier,
  riskLevelForScore,
  typeMatchesKind,
} from '@/server/domain/identity';
import {
  authenticateMachineIdentity,
  createIdentity,
  describeMachineIdentity,
  getIdentityDetail,
  issueCredential,
  listIdentities,
  machineIdentityHasScope,
  revokeCredential,
  rotateCredential,
  transitionIdentity,
  updateIdentity,
} from '@/server/services/identities';
import { createUserApiKey } from '@/server/services/api-keys';
import {
  createAccessReviewSchema,
  createIdentitySchema,
  type CreateIdentityInput,
} from '@/server/validation/identities';
import {
  assertTestDatabase,
  createTenant,
  expectAppError,
  prisma,
  resetDatabase,
  testMeta,
  type TestTenant,
} from './helpers/database.ts';

const SCOPE = 'identity.self.read' as const;

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

function identityInput(overrides: Partial<CreateIdentityInput>): CreateIdentityInput {
  return {
    kind: 'HUMAN',
    type: 'USER',
    displayName: 'Test identity',
    identifier: `user-${randomUUID()}@example.test`,
    criticality: 'MEDIUM',
    source: 'MANUAL',
    credentialTtlDays: 90,
    ...overrides,
  };
}

async function createMachine(
  tenant: TestTenant,
  options: { approvedScopes?: readonly (typeof SCOPE)[]; ownerUserId?: string } = {},
) {
  return createIdentity(
    tenant.ctx,
    identityInput({
      kind: 'MACHINE',
      type: 'SERVICE_ACCOUNT',
      displayName: 'Backup service',
      identifier: `svc-${randomUUID()}`,
      ownerUserId: options.ownerUserId ?? tenant.user.id,
      approvedScopes: [...(options.approvedScopes ?? [])],
    }),
  );
}

async function approveMachine(tenant: TestTenant, identityId: string) {
  return transitionIdentity(tenant.ctx, identityId, { action: 'APPROVE' });
}

// ---------------------------------------------------------------------------
// Pure domain rules
// ---------------------------------------------------------------------------

test('domain rules canonicalize identifiers and constrain lifecycle moves', () => {
  assert.equal(normalizeIdentityIdentifier('  SVC-Backup.Example  '), 'svc-backup.example');
  assert.equal(initialIdentityStatus('MACHINE'), 'PENDING_APPROVAL');
  assert.equal(initialIdentityStatus('HUMAN'), 'ACTIVE');

  assert.equal(typeMatchesKind('HUMAN', 'USER'), true);
  assert.equal(typeMatchesKind('HUMAN', 'SERVICE_ACCOUNT'), false);
  assert.equal(typeMatchesKind('MACHINE', 'USER'), false);
  assert.equal(typeMatchesKind('MACHINE', 'API_CLIENT'), true);

  assert.equal(canTransitionIdentity('PENDING_APPROVAL', 'ACTIVE'), true);
  assert.equal(canTransitionIdentity('PENDING_APPROVAL', 'SUSPENDED'), false);
  assert.equal(canTransitionIdentity('ACTIVE', 'DEPROVISIONED'), true);
  assert.equal(canTransitionIdentity('SUSPENDED', 'ACTIVE'), true);
  assert.equal(canTransitionIdentity('DEPROVISIONED', 'ACTIVE'), false);
});

test('credential minting returns the plaintext once and stores only a digest', () => {
  const now = new Date('2026-01-01T00:00:00.000Z');
  const issued = issueIdentityCredential({ ttlDays: 30, now });

  assert.match(issued.token, /^cnid_[A-Za-z0-9_-]{43}$/);
  assert.equal(isIdentityCredentialShape(issued.token), true);
  assert.equal(isIdentityCredentialShape('cnid_short'), false);
  assert.equal(isIdentityCredentialShape(`cnk_${'a'.repeat(43)}`), false);
  assert.equal(issued.hash, hashIdentityCredential(issued.token));
  assert.match(issued.hash, /^[0-9a-f]{64}$/);
  assert.notEqual(issued.hash, issued.token);
  assert.equal(issued.prefix, issued.token.slice(0, 'cnid_'.length + 6));
  assert.equal(issued.expiresAt.toISOString(), '2026-01-31T00:00:00.000Z');

  // The TTL is clamped rather than trusted, so a caller cannot mint a
  // decade-long machine credential through a bad request.
  const clamped = issueIdentityCredential({ ttlDays: 10_000, now });
  assert.equal(clamped.expiresAt.toISOString(), '2027-01-01T00:00:00.000Z');
});

test('risk signals are explainable and prioritized', () => {
  const now = new Date('2026-06-01T00:00:00.000Z');

  const unowned = evaluateIdentityRisk({
    kind: 'MACHINE',
    status: 'PENDING_APPROVAL',
    createdAt: now,
    ownerUserId: null,
    linkedUserId: null,
    linkedMembershipStatus: null,
    lastActivityAt: now,
    failedAuthLast24h: 0,
    activeSessions: 0,
    credentials: [],
    now,
  });
  assert.deepEqual(
    unowned.signals.map((signal) => signal.code),
    ['UNOWNED_MACHINE', 'PENDING_APPROVAL'],
  );
  const ownerSignal = unowned.signals[0];
  assert.ok(ownerSignal);
  assert.equal(ownerSignal.score, 40);
  assert.equal(ownerSignal.severity, 'HIGH');
  assert.equal(unowned.level, 'HIGH');

  const orphaned = evaluateIdentityRisk({
    kind: 'HUMAN',
    status: 'ACTIVE',
    createdAt: now,
    ownerUserId: null,
    linkedUserId: 'usr_1',
    linkedMembershipStatus: 'DISABLED',
    lastActivityAt: now,
    failedAuthLast24h: 0,
    activeSessions: 0,
    credentials: [],
    now,
  });
  assert.ok(orphaned.signals.some((signal) => signal.code === 'ORPHANED_ACCOUNT'));
  assert.ok(orphaned.signals.every((signal) => signal.detail.length > 0));

  const unlinked = evaluateIdentityRisk({
    kind: 'HUMAN',
    status: 'ACTIVE',
    createdAt: now,
    ownerUserId: null,
    linkedUserId: null,
    linkedMembershipStatus: null,
    lastActivityAt: now,
    failedAuthLast24h: 0,
    activeSessions: 0,
    credentials: [],
    now,
  });
  assert.ok(unlinked.signals.some((signal) => signal.code === 'UNLINKED_HUMAN'));

  const retired = evaluateIdentityRisk({
    kind: 'MACHINE',
    status: 'DEPROVISIONED',
    createdAt: now,
    ownerUserId: null,
    linkedUserId: null,
    linkedMembershipStatus: null,
    lastActivityAt: null,
    failedAuthLast24h: 50,
    activeSessions: 0,
    credentials: [],
    now,
  });
  assert.deepEqual(retired, { score: 0, level: 'LOW', signals: [] });

  assert.equal(riskLevelForScore(0), 'LOW');
  assert.equal(riskLevelForScore(19), 'LOW');
  assert.equal(riskLevelForScore(20), 'MEDIUM');
  assert.equal(riskLevelForScore(49), 'MEDIUM');
  assert.equal(riskLevelForScore(50), 'HIGH');
  assert.equal(riskLevelForScore(79), 'HIGH');
  assert.equal(riskLevelForScore(80), 'CRITICAL');
});

test('validation rejects mismatched identity shapes and unsafe review dates', () => {
  const machineWithoutOwner = createIdentitySchema.safeParse({
    kind: 'MACHINE',
    type: 'SERVICE_ACCOUNT',
    displayName: 'svc',
    identifier: `svc-${randomUUID()}`,
  });
  assert.equal(machineWithoutOwner.success, false);

  const humanAsMachine = createIdentitySchema.safeParse({
    kind: 'MACHINE',
    type: 'USER',
    displayName: 'person',
    identifier: `user-${randomUUID()}@example.test`,
    ownerUserId: 'usr_owner',
  });
  assert.equal(humanAsMachine.success, false);

  const humanWithScopes = createIdentitySchema.safeParse({
    kind: 'HUMAN',
    type: 'USER',
    displayName: 'person',
    identifier: `user-${randomUUID()}@example.test`,
    approvedScopes: [SCOPE],
  });
  assert.equal(humanWithScopes.success, false);

  const valid = createIdentitySchema.safeParse({
    kind: 'MACHINE',
    type: 'SERVICE_ACCOUNT',
    displayName: 'svc',
    identifier: `svc-${randomUUID()}`,
    ownerUserId: 'usr_owner',
  });
  assert.equal(valid.success, true);
  if (valid.success) {
    assert.equal(valid.data.criticality, 'MEDIUM');
    assert.equal(valid.data.source, 'MANUAL');
    assert.equal(valid.data.credentialTtlDays, 90);
    assert.deepEqual(valid.data.approvedScopes, undefined);
  }

  const pastDue = createAccessReviewSchema.safeParse({
    title: 'Quarterly review',
    dueAt: new Date(Date.now() - 60_000).toISOString(),
  });
  assert.equal(pastDue.success, false);

  const farDue = createAccessReviewSchema.safeParse({
    title: 'Quarterly review',
    dueAt: new Date(Date.now() + 181 * 24 * 60 * 60 * 1000).toISOString(),
  });
  assert.equal(farDue.success, false);

  const okDue = createAccessReviewSchema.safeParse({
    title: 'Quarterly review',
    dueAt: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
  });
  assert.equal(okDue.success, true);
});

// ---------------------------------------------------------------------------
// Inventory and lifecycle
// ---------------------------------------------------------------------------

test('human identities are canonicalized, auto-linked and tenant visible', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });

  const identity = await createIdentity(
    tenant.ctx,
    identityInput({
      kind: 'HUMAN',
      type: 'USER',
      displayName: 'Owner person',
      identifier: tenant.user.email.toUpperCase(),
      department: 'Security',
    }),
  );

  assert.equal(identity.identifier, tenant.user.email.toLowerCase());
  assert.equal(identity.status, 'ACTIVE');
  assert.equal(identity.linkedUser?.id, tenant.user.id);
  assert.deepEqual(identity.approvedScopes, []);
  assert.equal(identity.createdBy?.id, tenant.user.id);
  const createdEvent = identity.events.find((event) => event.type === 'CREATED');
  assert.ok(createdEvent);
  assert.equal(
    (createdEvent.metadata as Record<string, unknown>).identifier,
    tenant.user.email.toLowerCase(),
  );

  const audit = await prisma.auditEvent.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, action: 'identity.created' },
    select: { targetId: true, actorId: true, metadata: true },
  });
  assert.equal(audit.targetId, identity.id);
  assert.equal(audit.actorId, tenant.user.id);
  assert.equal((audit.metadata as Record<string, unknown>).linkedToUser, true);

  await expectAppError(
    createIdentity(
      tenant.ctx,
      identityInput({
        kind: 'HUMAN',
        type: 'USER',
        displayName: 'Duplicate',
        identifier: tenant.user.email,
      }),
    ),
    { statusCode: 409, code: 'CONFLICT' },
  );

  const page = await listIdentities(tenant.organization.id, {
    page: 1,
    pageSize: 20,
    sort: 'createdAt',
    direction: 'desc',
    search: 'owner person',
  });
  assert.equal(page.pagination.total, 1);
  const [listed] = page.items;
  assert.ok(listed);
  assert.equal(listed.id, identity.id);
  assert.equal(listed.risk.level, 'LOW');
});

test('only an owner can approve a machine identity, and approval is one-way', async () => {
  const adminTenant = await createTenant({ role: 'ADMIN', twoFactorEnabled: true });
  const pending = await createMachine(adminTenant);
  assert.equal(pending.status, 'PENDING_APPROVAL');
  assert.ok(pending.events.some((event) => event.type === 'SUBMITTED_FOR_APPROVAL'));

  await expectAppError(
    transitionIdentity(adminTenant.ctx, pending.id, { action: 'APPROVE' }),
    { statusCode: 403, code: 'FORBIDDEN' },
  );
  const stillPending = await getIdentityDetail(adminTenant.organization.id, pending.id);
  assert.equal(stillPending.status, 'PENDING_APPROVAL');

  await expectAppError(
    issueCredential(adminTenant.ctx, pending.id, { name: 'blocked', scopes: [SCOPE] }),
    { statusCode: 409, code: 'CONFLICT' },
  );

  const ownerTenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const machine = await createMachine(ownerTenant, { approvedScopes: [SCOPE] });
  const approved = await approveMachine(ownerTenant, machine.id);
  assert.equal(approved.status, 'ACTIVE');
  assert.equal(approved.approvedBy?.id, ownerTenant.user.id);
  assert.ok(approved.approvedAt);

  const human = await createIdentity(
    ownerTenant.ctx,
    identityInput({
      kind: 'HUMAN',
      type: 'USER',
      displayName: 'Human',
      identifier: `human-${randomUUID()}@example.test`,
    }),
  );
  await expectAppError(
    transitionIdentity(ownerTenant.ctx, human.id, { action: 'APPROVE' }),
    { statusCode: 400, code: 'BAD_REQUEST' },
  );

  const suspended = await transitionIdentity(ownerTenant.ctx, machine.id, {
    action: 'SUSPEND',
    note: 'rotation window',
  });
  assert.equal(suspended.status, 'SUSPENDED');
  assert.equal(suspended.suspendedAt === null, false);

  const reactivated = await transitionIdentity(ownerTenant.ctx, machine.id, {
    action: 'REACTIVATE',
  });
  assert.equal(reactivated.status, 'ACTIVE');

  const deprovisioned = await transitionIdentity(ownerTenant.ctx, machine.id, {
    action: 'DEPROVISION',
  });
  assert.equal(deprovisioned.status, 'DEPROVISIONED');
  assert.ok(deprovisioned.deprovisionedAt);

  await expectAppError(
    transitionIdentity(ownerTenant.ctx, machine.id, { action: 'REACTIVATE' }),
    { statusCode: 409, code: 'CONFLICT' },
  );
});

test('a linked person cannot be suspended while console access remains', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const human = await createIdentity(
    tenant.ctx,
    identityInput({
      kind: 'HUMAN',
      type: 'USER',
      displayName: 'Linked owner',
      identifier: tenant.user.email,
    }),
  );
  assert.equal(human.linkedUser?.id, tenant.user.id);

  await expectAppError(
    transitionIdentity(tenant.ctx, human.id, { action: 'SUSPEND' }),
    { statusCode: 409, code: 'CONFLICT' },
  );

  await prisma.membership.update({
    where: { id: tenant.membership.id },
    data: { status: 'DISABLED' },
  });

  const suspended = await transitionIdentity(tenant.ctx, human.id, { action: 'SUSPEND' });
  assert.equal(suspended.status, 'SUSPENDED');
});

// ---------------------------------------------------------------------------
// Machine credentials
// ---------------------------------------------------------------------------

test('credential issuance enforces approved scopes and stores only a hash', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const machine = await createMachine(tenant, { approvedScopes: [SCOPE] });
  await approveMachine(tenant, machine.id);

  const scoped = await createMachine(tenant, { approvedScopes: [] });
  await approveMachine(tenant, scoped.id);
  await expectAppError(
    issueCredential(tenant.ctx, scoped.id, { name: 'not approved', scopes: [SCOPE] }),
    { statusCode: 403, code: 'FORBIDDEN' },
  );

  const issued = await issueCredential(tenant.ctx, machine.id, {
    name: 'backup job',
    scopes: [SCOPE],
    ttlDays: 30,
  });

  assert.match(issued.token, /^cnid_/);
  assert.equal(issued.credential.status, 'ACTIVE');
  assert.deepEqual(issued.credential.scopes, [SCOPE]);
  assert.equal(issued.credential.prefix, issued.token.slice(0, 11));
  assert.equal(issued.credential.createdBy?.id, tenant.user.id);

  const stored = await prisma.identityCredential.findUniqueOrThrow({
    where: { id: issued.credential.id },
    select: { keyHash: true, keyPrefix: true, scopes: true, expiresAt: true },
  });
  assert.equal(stored.keyHash, hashIdentityCredential(issued.token));
  assert.notEqual(stored.keyHash, issued.token);
  assert.equal(stored.keyPrefix, issued.credential.prefix);
  assert.deepEqual(stored.scopes, [SCOPE]);
  assert.ok(stored.expiresAt.getTime() > Date.now());

  const audit = await prisma.auditEvent.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, action: 'identity.credential_issued' },
    select: { targetId: true, metadata: true },
  });
  assert.equal(audit.targetId, issued.credential.id);
  const metadata = audit.metadata as Record<string, unknown>;
  assert.equal(metadata.identityId, machine.id);
  assert.equal(JSON.stringify(metadata).includes(issued.token), false);
});

test('rotation replaces a credential atomically and revocation is final', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const machine = await createMachine(tenant, { approvedScopes: [SCOPE] });
  await approveMachine(tenant, machine.id);

  const first = await issueCredential(tenant.ctx, machine.id, {
    name: 'primary',
    scopes: [SCOPE],
  });
  const principal = await authenticateMachineIdentity(first.token);
  assert.ok(principal);
  assert.equal(principal.identityId, machine.id);
  assert.equal(machineIdentityHasScope(principal, SCOPE), true);

  const self = await describeMachineIdentity(principal);
  assert.ok(self);
  assert.equal(self.identity.id, machine.id);
  assert.equal(self.credential.id, first.credential.id);
  assert.equal(JSON.stringify(self).includes(first.token), false);

  const rotated = await rotateCredential(tenant.ctx, machine.id, first.credential.id);
  assert.notEqual(rotated.token, first.token);
  assert.equal(await authenticateMachineIdentity(first.token), null);
  assert.ok(await authenticateMachineIdentity(rotated.token));

  const oldRow = await prisma.identityCredential.findUniqueOrThrow({
    where: { id: first.credential.id },
    select: { revokedAt: true, revokedReason: true },
  });
  assert.ok(oldRow.revokedAt);
  assert.equal(oldRow.revokedReason, 'rotated');

  const revoked = await revokeCredential(tenant.ctx, machine.id, rotated.credential.id);
  assert.equal(revoked.status, 'REVOKED');
  assert.equal(revoked.revokedReason, 'revoked_by_operator');
  assert.equal(await authenticateMachineIdentity(rotated.token), null);
  await expectAppError(revokeCredential(tenant.ctx, machine.id, rotated.credential.id), {
    statusCode: 409,
    code: 'CONFLICT',
  });
});

test('credential limits, expiry and suspension all fail closed', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const machine = await createMachine(tenant, { approvedScopes: [SCOPE] });
  await approveMachine(tenant, machine.id);

  const issuedRows: Array<{ token: string; id: string }> = [];
  for (let index = 0; index < 5; index += 1) {
    const issued = await issueCredential(tenant.ctx, machine.id, {
      name: `credential ${index}`,
      scopes: [SCOPE],
    });
    issuedRows.push({ token: issued.token, id: issued.credential.id });
  }
  const tokens = issuedRows.map((row) => row.token);

  await expectAppError(
    issueCredential(tenant.ctx, machine.id, { name: 'one too many', scopes: [SCOPE] }),
    { statusCode: 409, code: 'CONFLICT' },
  );

  const expired = issuedRows[0];
  const stillValid = issuedRows[1];
  assert.ok(expired);
  assert.ok(stillValid);
  await prisma.identityCredential.update({
    where: { id: expired.id },
    data: { expiresAt: new Date(Date.now() - 1_000) },
  });
  assert.equal(await authenticateMachineIdentity(expired.token), null);
  assert.ok(await authenticateMachineIdentity(stillValid.token));

  // Revoking a single credential leaves the others usable.
  const victim = await issueCredential(tenant.ctx, machine.id, {
    name: 'revoked only',
    scopes: [SCOPE],
  });
  await revokeCredential(tenant.ctx, machine.id, victim.credential.id);
  assert.equal(await authenticateMachineIdentity(victim.token), null);

  await transitionIdentity(tenant.ctx, machine.id, { action: 'SUSPEND' });
  for (const token of tokens) {
    assert.equal(await authenticateMachineIdentity(token), null);
  }
  const active = await prisma.identityCredential.count({
    where: { identityId: machine.id, revokedAt: null },
  });
  assert.equal(active, 0);

  assert.equal(await authenticateMachineIdentity('not-a-credential'), null);
  assert.equal(await authenticateMachineIdentity(`cnid_${'a'.repeat(43)}`), null);
});

test('narrowing approved scopes revokes credentials that are no longer covered', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const machine = await createMachine(tenant, { approvedScopes: [SCOPE] });
  await approveMachine(tenant, machine.id);
  const issued = await issueCredential(tenant.ctx, machine.id, {
    name: 'scoped',
    scopes: [SCOPE],
  });
  assert.ok(await authenticateMachineIdentity(issued.token));

  const updated = await updateIdentity(tenant.ctx, machine.id, { approvedScopes: [] });
  assert.deepEqual(updated.approvedScopes, []);
  const credential = updated.credentials.find((row) => row.id === issued.credential.id);
  assert.equal(credential?.status, 'REVOKED');
  assert.equal(credential?.revokedReason, 'scope_narrowed');
  assert.equal(await authenticateMachineIdentity(issued.token), null);
  assert.ok(updated.events.some((event) => event.type === 'CREDENTIAL_REVOKED'));
});

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

test('identities and credentials never cross tenant boundaries', async () => {
  const tenantA = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const tenantB = await createTenant({ role: 'OWNER', twoFactorEnabled: true });

  const sharedIdentifier = `svc-${randomUUID()}`;
  const identityA = await createIdentity(
    tenantA.ctx,
    identityInput({
      kind: 'MACHINE',
      type: 'SERVICE_ACCOUNT',
      displayName: 'Tenant A service',
      identifier: sharedIdentifier,
      ownerUserId: tenantA.user.id,
      approvedScopes: [SCOPE],
    }),
  );

  // Uniqueness is tenant-scoped, so the same identifier can exist elsewhere.
  const identityB = await createIdentity(
    tenantB.ctx,
    identityInput({
      kind: 'MACHINE',
      type: 'SERVICE_ACCOUNT',
      displayName: 'Tenant B service',
      identifier: sharedIdentifier,
      ownerUserId: tenantB.user.id,
    }),
  );
  assert.notEqual(identityA.id, identityB.id);

  await expectAppError(getIdentityDetail(tenantB.organization.id, identityA.id), {
    statusCode: 404,
    code: 'NOT_FOUND',
  });
  await expectAppError(
    transitionIdentity(tenantB.ctx, identityA.id, { action: 'APPROVE' }),
    { statusCode: 404, code: 'NOT_FOUND' },
  );
  await expectAppError(
    issueCredential(tenantB.ctx, identityA.id, { name: 'cross tenant', scopes: [SCOPE] }),
    { statusCode: 404, code: 'NOT_FOUND' },
  );

  const pageA = await listIdentities(tenantA.organization.id, {
    page: 1,
    pageSize: 20,
    sort: 'createdAt',
    direction: 'desc',
    search: undefined,
  });
  assert.equal(pageA.pagination.total, 1);
  const [firstOfA] = pageA.items;
  assert.ok(firstOfA);
  assert.equal(firstOfA.id, identityA.id);

  const pageB = await listIdentities(tenantB.organization.id, {
    page: 1,
    pageSize: 20,
    sort: 'createdAt',
    direction: 'desc',
    search: undefined,
  });
  assert.equal(pageB.pagination.total, 1);
  const [firstOfB] = pageB.items;
  assert.ok(firstOfB);
  assert.equal(firstOfB.id, identityB.id);
});

// ---------------------------------------------------------------------------
// HTTP route layer
// ---------------------------------------------------------------------------

test('HTTP routes enforce capability, tenant scope and one-time credential reveal', async () => {
  const tenantA = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const tenantB = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const keyA = await createUserApiKey(
    tenantA.ctx.user,
    { name: 'identity routes', organizationId: tenantA.organization.id, expiresInDays: 30 },
    testMeta(),
  );
  const keyB = await createUserApiKey(
    tenantB.ctx.user,
    { name: 'identity routes', organizationId: tenantB.organization.id, expiresInDays: 30 },
    testMeta(),
  );

  const [{ POST: createRoute, GET: listRoute }, { GET: detailRoute }, { NextRequest }] =
    await Promise.all([
      import('@/app/api/v1/organizations/[orgSlug]/identities/route'),
      import('@/app/api/v1/organizations/[orgSlug]/identities/[identityId]/route'),
      import('next/server'),
    ]);

  const identifier = `svc-${randomUUID()}`;
  const createResponse = await createRoute(
    new NextRequest(
      `http://localhost:3000/api/v1/organizations/${tenantA.organization.slug}/identities`,
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${keyA.key}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          kind: 'MACHINE',
          type: 'SERVICE_ACCOUNT',
          displayName: 'Route-created machine',
          identifier,
          ownerUserId: tenantA.user.id,
          approvedScopes: [SCOPE],
        }),
      },
    ),
    { params: Promise.resolve({ orgSlug: tenantA.organization.slug }) },
  );
  assert.equal(createResponse.status, 201);
  assert.equal(createResponse.headers.get('x-identity-pending-approval'), 'true');
  const created = (await createResponse.json()) as {
    identity: { id: string; status: string; identifier: string; approvedScopes: string[] };
  };
  assert.equal(created.identity.status, 'PENDING_APPROVAL');
  assert.equal(created.identity.identifier, identifier);

  const listResponse = await listRoute(
    new NextRequest(
      `http://localhost:3000/api/v1/organizations/${tenantA.organization.slug}/identities`,
      { headers: { authorization: `Bearer ${keyA.key}` } },
    ),
    { params: Promise.resolve({ orgSlug: tenantA.organization.slug }) },
  );
  assert.equal(listResponse.status, 200);
  const list = (await listResponse.json()) as {
    pagination: { total: number };
    overview: { counts: { total: number; pendingApproval: number } };
  };
  assert.equal(list.pagination.total, 1);
  assert.equal(list.overview.counts.total, 1);
  assert.equal(list.overview.counts.pendingApproval, 1);

  // A key bound to another organization cannot reach this identity, even when
  // it supplies the correct organization slug.
  const crossTenant = await detailRoute(
    new NextRequest(
      `http://localhost:3000/api/v1/organizations/${tenantA.organization.slug}/identities/${created.identity.id}`,
      { headers: { authorization: `Bearer ${keyB.key}` } },
    ),
    {
      params: Promise.resolve({
        orgSlug: tenantA.organization.slug,
        identityId: created.identity.id,
      }),
    },
  );
  assert.equal(crossTenant.status, 404);

  // A viewer can read the inventory but cannot create an identity.
  const viewer = await createTenant({ role: 'VIEWER', twoFactorEnabled: true });
  const viewerKey = await createUserApiKey(
    viewer.ctx.user,
    { name: 'read only', organizationId: viewer.organization.id, expiresInDays: 30 },
    testMeta(),
  );
  const denied = await createRoute(
    new NextRequest(
      `http://localhost:3000/api/v1/organizations/${viewer.organization.slug}/identities`,
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${viewerKey.key}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          kind: 'HUMAN',
          type: 'USER',
          displayName: 'No permission',
          identifier: 'viewer-attempt@example.test',
        }),
      },
    ),
    { params: Promise.resolve({ orgSlug: viewer.organization.slug }) },
  );
  assert.equal(denied.status, 403);

  // Machine credentials work only on the bearer endpoint and are never echoed.
  await approveMachine(tenantA, created.identity.id);
  const issued = await issueCredential(tenantA.ctx, created.identity.id, {
    name: 'route credential',
    scopes: [SCOPE],
  });
  const { GET: machineMe } = await import('@/app/api/v1/identity/me/route');
  const meResponse = await machineMe(
    new NextRequest('http://localhost:3000/api/v1/identity/me', {
      headers: { authorization: `Bearer ${issued.token}` },
    }),
    { params: Promise.resolve({}) },
  );
  assert.equal(meResponse.status, 200);
  const me = (await meResponse.json()) as {
    identity: { id: string; status: string };
    credential: { prefix: string; scopes: string[] };
  };
  assert.equal(me.identity.id, created.identity.id);
  assert.equal(me.identity.status, 'ACTIVE');
  assert.equal(me.credential.prefix, issued.credential.prefix);
  assert.deepEqual(me.credential.scopes, [SCOPE]);
  assert.equal(JSON.stringify(me).includes(issued.token), false);

  await revokeCredential(tenantA.ctx, created.identity.id, issued.credential.id);
  const revokedResponse = await machineMe(
    new NextRequest('http://localhost:3000/api/v1/identity/me', {
      headers: { authorization: `Bearer ${issued.token}` },
    }),
    { params: Promise.resolve({}) },
  );
  assert.equal(revokedResponse.status, 401);
});
