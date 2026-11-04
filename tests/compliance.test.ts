import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import { verifyAuditChain } from '@/server/audit/audit';
import {
  addEvidence,
  adoptFramework,
  deleteEvidence,
  getComplianceOverview,
  getFrameworkDetail,
  updateControl,
  withdrawFramework,
} from '@/server/services/compliance';
import { createFinding } from '@/server/services/findings';
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

async function adoptionControl(
  organizationId: string,
  organizationFrameworkId: string,
  controlCode: string,
) {
  const row = await prisma.organizationControl.findFirstOrThrow({
    where: {
      organizationId,
      organizationFrameworkId,
      control: { code: controlCode },
    },
    select: { id: true, status: true, lastReviewedAt: true },
  });
  return row;
}

test('adopting a framework opens one attestation per control and audits the adoption', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });

  const adoption = await adoptFramework(tenant.ctx, { frameworkId: 'SOC2' });
  assert.equal(adoption.frameworkCode, 'SOC2');
  assert.equal(adoption.controlsAdopted, 12);

  const controls = await prisma.organizationControl.count({
    where: { organizationId: tenant.organization.id },
  });
  assert.equal(controls, 12);

  const overview = await getComplianceOverview(tenant.ctx);
  assert.equal(overview.adopted, 1);
  assert.equal(overview.frameworks.find((row) => row.code === 'SOC2')?.posture?.score, 0);
  assert.equal(overview.frameworks.find((row) => row.code === 'SOC2')?.posture?.band, 'AT_RISK');
  // Nothing has been attested, so nothing can be reported as an evidence gap.
  assert.equal(overview.integrityWarnings.length, 0);

  const audit = await prisma.auditEvent.findFirst({
    where: {
      organizationId: tenant.organization.id,
      action: 'compliance.framework_adopted',
      targetId: 'fw_soc2',
    },
    select: { outcome: true },
  });
  assert.equal(audit?.outcome, 'SUCCESS');

  const chain = await verifyAuditChain(tenant.organization.id);
  assert.equal(chain.valid, true);
});

test('re-adopting an already adopted framework is refused instead of resetting attestations', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  await adoptFramework(tenant.ctx, { frameworkId: 'PCIDSS' });

  await expectAppError(adoptFramework(tenant.ctx, { frameworkId: 'PCIDSS' }), {
    statusCode: 409,
    code: 'CONFLICT',
  });
});

test('a control cannot be marked implemented without supporting evidence', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const adoption = await adoptFramework(tenant.ctx, { frameworkId: 'ISO27001' });
  const control = await adoptionControl(
    tenant.organization.id,
    adoption.organizationFrameworkId,
    'A.5.15',
  );

  await expectAppError(updateControl(tenant.ctx, control.id, { status: 'IMPLEMENTED' }), {
    statusCode: 409,
    code: 'CONFLICT',
  });

  const unchanged = await prisma.organizationControl.findUniqueOrThrow({
    where: { id: control.id },
    select: { status: true, lastReviewedAt: true },
  });
  assert.equal(unchanged.status, 'NOT_STARTED');
  assert.equal(unchanged.lastReviewedAt, null);
});

test('evidence pointing at another tenant record is rejected as not found', async () => {
  const owner = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const other = await createTenant({ role: 'ANALYST' });

  const foreignFinding = await createFinding(other.ctx, {
    title: 'Foreign tenant finding',
    severity: 'HIGH',
  });

  const adoption = await adoptFramework(owner.ctx, { frameworkId: 'NISTCSF' });
  const control = await adoptionControl(
    owner.organization.id,
    adoption.organizationFrameworkId,
    'GV.OC-01',
  );

  await expectAppError(
    addEvidence(owner.ctx, control.id, { kind: 'FINDING', findingId: foreignFinding.id }),
    { statusCode: 404, code: 'NOT_FOUND' },
  );

  const evidenceCount = await prisma.controlEvidence.count({
    where: { organizationId: owner.organization.id },
  });
  assert.equal(evidenceCount, 0);
});

test('reference evidence unlocks implementation, stamps the review date, and raises posture', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const adoption = await adoptFramework(tenant.ctx, { frameworkId: 'GDPR' });
  const control = await adoptionControl(
    tenant.organization.id,
    adoption.organizationFrameworkId,
    'Art. 33',
  );

  const evidence = await addEvidence(tenant.ctx, control.id, {
    kind: 'REFERENCE',
    reference: 'https://example.test/runbooks/breach-notification',
    note: '72-hour notification runbook approved',
  });
  assert.equal(evidence.evidenceCount, 1);

  const updated = await updateControl(tenant.ctx, control.id, { status: 'IMPLEMENTED' });
  assert.equal(updated.status, 'IMPLEMENTED');

  const stored = await prisma.organizationControl.findUniqueOrThrow({
    where: { id: control.id },
    select: { lastReviewedAt: true, updatedById: true },
  });
  assert.notEqual(stored.lastReviewedAt, null);
  assert.equal(stored.updatedById, tenant.user.id);

  const overview = await getComplianceOverview(tenant.ctx);
  const gdpr = overview.frameworks.find((row) => row.code === 'GDPR');
  assert.ok(gdpr?.posture);
  assert.ok(gdpr.posture.score > 0);

  const audit = await prisma.auditEvent.findFirst({
    where: {
      organizationId: tenant.organization.id,
      action: 'compliance.control_updated',
    },
    select: { summary: true },
  });
  assert.match(audit?.summary ?? '', /Art\. 33 moved from NOT_STARTED to IMPLEMENTED/);
});

test('removing the last evidence of an implemented control is refused until the status steps back', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const adoption = await adoptFramework(tenant.ctx, { frameworkId: 'SOC2' });
  const control = await adoptionControl(
    tenant.organization.id,
    adoption.organizationFrameworkId,
    'CC7.1',
  );

  const evidence = await addEvidence(tenant.ctx, control.id, {
    kind: 'REFERENCE',
    reference: 'ticket:SEC-1042',
  });
  await updateControl(tenant.ctx, control.id, { status: 'IMPLEMENTED' });

  await expectAppError(deleteEvidence(tenant.ctx, evidence.id), {
    statusCode: 409,
    code: 'CONFLICT',
  });

  await updateControl(tenant.ctx, control.id, { status: 'PARTIAL' });
  const removed = await deleteEvidence(tenant.ctx, evidence.id);
  assert.equal(removed.organizationControlId, control.id);

  const remaining = await prisma.controlEvidence.count({
    where: { organizationId: tenant.organization.id },
  });
  assert.equal(remaining, 0);
});

test('withdrawing is refused while evidence exists and removes attestations once it is clear', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const adoption = await adoptFramework(tenant.ctx, { frameworkId: 'PCIDSS' });
  const control = await adoptionControl(
    tenant.organization.id,
    adoption.organizationFrameworkId,
    '1.3',
  );
  const evidence = await addEvidence(tenant.ctx, control.id, {
    kind: 'REFERENCE',
    reference: 'doc:pci-network-diagram',
  });

  await expectAppError(withdrawFramework(tenant.ctx, 'PCIDSS'), {
    statusCode: 409,
    code: 'CONFLICT',
  });

  await deleteEvidence(tenant.ctx, evidence.id);
  const withdrawn = await withdrawFramework(tenant.ctx, 'PCIDSS');
  assert.equal(withdrawn.controlsRemoved, 12);

  const remaining = await prisma.organizationControl.count({
    where: { organizationId: tenant.organization.id },
  });
  assert.equal(remaining, 0);
});

test('framework detail keeps catalog order and is readable before adoption', async () => {
  const tenant = await createTenant({ role: 'VIEWER' });

  const gdpr = await getFrameworkDetail(tenant.ctx, 'gdpr');
  assert.equal(gdpr.framework.code, 'GDPR');
  assert.equal(gdpr.adoption, null);
  assert.equal(gdpr.controls.length, 12);
  assert.equal(gdpr.controls[0]?.code, 'Art. 5');
  assert.equal(
    gdpr.controls.every((control) => control.status === null),
    true,
  );

  const soc2 = await getFrameworkDetail(tenant.ctx, 'SOC2');
  assert.equal(soc2.controls[0]?.code, 'CC6.1');
  assert.equal(soc2.controls[1]?.code, 'CC6.2');
});

test('another tenant cannot update or withdraw controls it does not own', async () => {
  const owner = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const intruder = await createTenant({ role: 'OWNER', twoFactorEnabled: true });

  const adoption = await adoptFramework(owner.ctx, { frameworkId: 'ISO27001' });
  const control = await adoptionControl(
    owner.organization.id,
    adoption.organizationFrameworkId,
    'A.8.16',
  );

  await expectAppError(updateControl(intruder.ctx, control.id, { status: 'PARTIAL' }), {
    statusCode: 404,
    code: 'NOT_FOUND',
  });
  await expectAppError(withdrawFramework(intruder.ctx, 'ISO27001'), {
    statusCode: 404,
    code: 'NOT_FOUND',
  });

  const stillOwned = await prisma.organizationControl.findUniqueOrThrow({
    where: { id: control.id },
    select: { organizationId: true, status: true },
  });
  assert.equal(stillOwned.organizationId, owner.organization.id);
  assert.equal(stillOwned.status, 'NOT_STARTED');
});
