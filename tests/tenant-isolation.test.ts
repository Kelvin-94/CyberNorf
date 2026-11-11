import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import { requireTenantContext } from '@/server/authz/context';
import { createAsset, getAssetDetail, updateAsset } from '@/server/services/assets';
import {
  changeFindingStatus,
  createFinding,
  getFindingDetail,
  listFindings,
} from '@/server/services/findings';
import {
  assertTestDatabase,
  createTenant,
  expectAppError,
  prisma,
  resetDatabase,
  testHeaders,
  testMeta,
} from './helpers/database.ts';

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

test('records from another organization are invisible, not merely read-only', async () => {
  const tenantA = await createTenant({ role: 'ANALYST' });
  const tenantB = await createTenant({ role: 'ANALYST' });

  const assetB = await createAsset(tenantB.ctx, {
    name: 'Tenant B portal',
    type: 'WEB_APPLICATION',
    identifier: 'portal.tenant-b.example',
    description: null,
    criticality: 'HIGH',
    status: 'ACTIVE',
  });
  const findingB = await createFinding(tenantB.ctx, {
    title: 'Tenant B authentication bypass',
    severity: 'CRITICAL',
    assetId: assetB.id,
  });

  await expectAppError(getFindingDetail(tenantA.ctx, findingB.id), {
    statusCode: 404,
    code: 'NOT_FOUND',
  });
  await expectAppError(getAssetDetail(tenantA.ctx, assetB.id), {
    statusCode: 404,
    code: 'NOT_FOUND',
  });
  await expectAppError(changeFindingStatus(tenantA.ctx, findingB.id, 'RESOLVED'), {
    statusCode: 404,
  });
  await expectAppError(updateAsset(tenantA.ctx, assetB.id, { name: 'Hijacked' }), {
    statusCode: 404,
  });

  const listA = await listFindings(tenantA.organization.id, {
    page: 1,
    pageSize: 50,
    sort: 'createdAt',
    direction: 'desc',
  });
  assert.equal(
    listA.items.some((item) => item.id === findingB.id),
    false,
    'tenant A must not see tenant B findings',
  );
  assert.equal(listA.total, 0);
});

test('a non-member cannot resolve another tenant, even with a valid session', async () => {
  const outsider = await createTenant({ role: 'ANALYST' });
  const target = await createTenant({ role: 'OWNER', twoFactorEnabled: true });

  await expectAppError(
    requireTenantContext(
      testHeaders(),
      target.organization.slug,
      'finding.read',
      testMeta(),
      outsider.user,
    ),
    { statusCode: 404, code: 'NOT_FOUND' },
  );
});

test('a viewer is denied mutating capabilities and the denial is audited', async () => {
  const viewer = await createTenant({ role: 'VIEWER' });

  const ctx = await requireTenantContext(
    testHeaders(),
    viewer.organization.slug,
    'finding.read',
    testMeta(),
    viewer.user,
  );
  assert.equal(ctx.membership.role, 'VIEWER');

  await expectAppError(
    requireTenantContext(
      testHeaders(),
      viewer.organization.slug,
      'finding.create',
      testMeta(),
      viewer.user,
    ),
    { statusCode: 403, code: 'FORBIDDEN' },
  );

  const denied = await prisma.auditEvent.findFirst({
    where: { organizationId: viewer.organization.id, action: 'access.denied' },
    select: { outcome: true, actorId: true, metadata: true, targetId: true },
  });
  assert.ok(denied, 'a denied authorization decision must be recorded');
  assert.equal(denied.outcome, 'DENIED');
  assert.equal(denied.actorId, viewer.user.id);
  assert.equal(denied.targetId, viewer.organization.id);
  assert.deepEqual((denied.metadata as { capability?: string }).capability, 'finding.create');
});

test('privileged mutations require a second factor', async () => {
  const ownerWithoutMfa = await createTenant({ role: 'OWNER', twoFactorEnabled: false });

  await expectAppError(
    requireTenantContext(
      testHeaders(),
      ownerWithoutMfa.organization.slug,
      'asset.create',
      testMeta(),
      ownerWithoutMfa.user,
    ),
    { statusCode: 403, code: 'MFA_REQUIRED' },
  );

  const mfaEvent = await prisma.auditEvent.findFirst({
    where: { organizationId: ownerWithoutMfa.organization.id, action: 'access.denied' },
    select: { metadata: true },
  });
  assert.deepEqual((mfaEvent?.metadata as { reason?: string }).reason, 'second_factor_required');

  const ownerWithMfa = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const ctx = await requireTenantContext(
    testHeaders(),
    ownerWithMfa.organization.slug,
    'asset.create',
    testMeta(),
    ownerWithMfa.user,
  );
  assert.equal(ctx.membership.role, 'OWNER');
});

test('a disabled membership loses access to the organization', async () => {
  const tenant = await createTenant({ role: 'ANALYST' });

  await prisma.membership.update({
    where: { id: tenant.membership.id },
    data: { status: 'DISABLED' },
  });

  await expectAppError(
    requireTenantContext(
      testHeaders(),
      tenant.organization.slug,
      'finding.read',
      testMeta(),
      tenant.user,
    ),
    { statusCode: 404, code: 'NOT_FOUND' },
  );
});

test('relationships cannot be used to reach records in another tenant', async () => {
  const tenantA = await createTenant({ role: 'ANALYST' });
  const tenantB = await createTenant({ role: 'ANALYST' });

  const assetB = await createAsset(tenantB.ctx, {
    name: 'Tenant B database',
    type: 'HOSTNAME',
    identifier: 'db.tenant-b.example',
    description: null,
    criticality: 'CRITICAL',
    status: 'ACTIVE',
  });

  await expectAppError(
    createFinding(tenantA.ctx, {
      title: 'Attempted cross-tenant reference',
      severity: 'HIGH',
      assetId: assetB.id,
    }),
    { statusCode: 404, code: 'NOT_FOUND' },
  );

  await expectAppError(
    createFinding(tenantA.ctx, {
      title: 'Attempted cross-tenant assignee',
      severity: 'LOW',
      assignedToId: tenantB.user.id,
    }),
    { statusCode: 400, code: 'BAD_REQUEST' },
  );
});
