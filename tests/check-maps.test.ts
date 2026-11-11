import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import { authenticateAgentToken, recordAgentRun, registerAgent } from '@/server/services/agents';
import { createCheckMap, deleteCheckMap, listCheckMaps } from '@/server/services/check-maps';
import { adoptFramework } from '@/server/services/compliance';
import {
  assertTestDatabase,
  createTenant,
  expectAppError,
  prisma,
  resetDatabase,
  type TestTenant,
} from './helpers/database.ts';

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

const FIREWALL_CHECK = {
  id: 'access.host-firewall',
  title: 'Host firewall state',
  findingTitle: 'Host firewall is disabled',
  status: 'FAIL' as const,
  severity: 'HIGH' as const,
  target: 'host-a',
  detail: 'socketfilterfw –getglobalstate reports State = 0',
  remediation: 'Enable the application firewall in System Settings > Network.',
};

const PASSING_CHECK = {
  id: 'vuln.filevault',
  title: 'Full-disk encryption is enabled',
  status: 'PASS' as const,
  severity: 'MEDIUM' as const,
  target: 'host-a',
};

function report(checks: Array<typeof FIREWALL_CHECK | typeof PASSING_CHECK>) {
  return {
    hostname: 'host-a',
    platform: 'darwin 25.6.0',
    startedAt: new Date(),
    durationMs: 1200,
    checks,
  };
}

/** Registers a builtin agent and returns its authenticated principal. */
async function monitoredAgent(tenant: TestTenant, name: string) {
  const registration = await registerAgent(tenant.ctx, { name, source: 'BUILTIN' });
  assert.ok(registration.token, 'builtin registration must issue a credential');
  const principal = await authenticateAgentToken(registration.token);
  return { agent: registration.agent, principal };
}

/** Adopts ISO 27001 and returns one of the resulting tenant control rows. */
async function adoptedControl(tenant: TestTenant) {
  await adoptFramework(tenant.ctx, { frameworkId: 'ISO27001' });
  return prisma.organizationControl.findFirstOrThrow({
    where: { organizationId: tenant.organization.id },
    orderBy: { createdAt: 'asc' },
    select: {
      id: true,
      organizationFrameworkId: true,
      control: { select: { code: true, title: true } },
    },
  });
}

test('a mapped check files its finding as control evidence exactly once', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const { principal } = await monitoredAgent(tenant, 'builtin-host-monitor');
  const control = await adoptedControl(tenant);

  const { map } = await createCheckMap(tenant.ctx, {
    checkId: FIREWALL_CHECK.id,
    organizationControlId: control.id,
  });
  assert.equal(map.organizationControlId, control.id);
  assert.equal(map.controlCode, control.control.code);
  assert.equal(map.frameworkCode, 'ISO27001');

  const first = await recordAgentRun(principal, report([FIREWALL_CHECK, PASSING_CHECK]));
  assert.equal(first.findingsCreated, 1);
  assert.equal(first.controlEvidenceAttached, 1);

  const evidence = await prisma.controlEvidence.findMany({
    where: { organizationControlId: control.id },
    select: { kind: true, findingId: true, note: true, createdById: true },
  });
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0]?.kind, 'FINDING');
  assert.ok(evidence[0]?.findingId, 'evidence must point at the finding it proves');
  assert.match(evidence[0]?.note ?? '', /access\.host-firewall/);
  assert.match(evidence[0]?.note ?? '', /Host firewall is disabled/);
  assert.equal(evidence[0]?.createdById, tenant.user.id);

  // The same failing check on a later run refreshes the finding and must not
  // pile up duplicate evidence on the control.
  const second = await recordAgentRun(principal, report([FIREWALL_CHECK, PASSING_CHECK]));
  assert.equal(second.findingsRefreshed, 1);
  assert.equal(second.controlEvidenceAttached, 0);
  assert.equal(
    await prisma.controlEvidence.count({ where: { organizationControlId: control.id } }),
    1,
  );

  const audit = await prisma.auditEvent.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, action: 'compliance.evidence_added' },
    select: { actorType: true, targetId: true, metadata: true },
  });
  // Automatic evidence is attributed to the agent, not to the operator who
  // registered it, so the compliance history stays truthful.
  assert.equal(audit.actorType, 'AGENT');
  assert.equal(audit.targetId, control.organizationFrameworkId);
  const metadata = audit.metadata as Record<string, unknown>;
  assert.equal(metadata.automatic, true);
  assert.equal(metadata.checkId, FIREWALL_CHECK.id);
  assert.equal(metadata.agentId, principal.id);

  const mapAudit = await prisma.auditEvent.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, action: 'agent.check_mapped' },
    select: { actorType: true, actorId: true, targetId: true },
  });
  assert.equal(mapAudit.actorType, 'USER');
  assert.equal(mapAudit.actorId, tenant.user.id);
  assert.equal(mapAudit.targetId, control.organizationFrameworkId);
});

test('the mapping overview lists observed checks, their status and their controls', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const { agent, principal } = await monitoredAgent(tenant, 'builtin-overview-monitor');
  const control = await adoptedControl(tenant);

  const empty = await listCheckMaps(tenant.ctx, agent.id);
  assert.equal(empty.checks.length, 0, 'nothing is observed before the first run');
  assert.ok(empty.controls.length > 0, 'every adopted control is offered');
  assert.ok(empty.controls.every((option) => option.frameworkCode === 'ISO27001'));

  const { map } = await createCheckMap(tenant.ctx, {
    checkId: FIREWALL_CHECK.id,
    organizationControlId: control.id,
  });
  await recordAgentRun(principal, report([FIREWALL_CHECK, PASSING_CHECK]));

  const overview = await listCheckMaps(tenant.ctx, agent.id);
  assert.deepEqual(
    overview.checks.map((check) => check.checkId),
    [PASSING_CHECK.id, FIREWALL_CHECK.id].sort(),
  );
  const firewall = overview.checks.find((check) => check.checkId === FIREWALL_CHECK.id);
  assert.equal(firewall?.lastStatus, 'FAIL');
  assert.equal(firewall?.title, FIREWALL_CHECK.title);
  assert.equal(firewall?.mappings.length, 1);
  assert.equal(firewall?.mappings[0]?.mapId, map.mapId);
  assert.equal(
    firewall?.mappings[0]?.evidenceCount,
    1,
    'the control now carries the filed evidence',
  );

  // A mapping without a recent run stays visible, so it can still be removed.
  const unmappedCheck = await listCheckMaps(tenant.ctx, null);
  assert.ok(unmappedCheck.checks.some((check) => check.checkId === FIREWALL_CHECK.id));
});

test('mappings are unique per check and cannot cross tenants', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const control = await adoptedControl(tenant);

  await createCheckMap(tenant.ctx, {
    checkId: FIREWALL_CHECK.id,
    organizationControlId: control.id,
  });
  await expectAppError(
    createCheckMap(tenant.ctx, {
      checkId: FIREWALL_CHECK.id,
      organizationControlId: control.id,
    }),
    { statusCode: 409 },
  );

  const stranger = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  await expectAppError(
    createCheckMap(stranger.ctx, {
      checkId: FIREWALL_CHECK.id,
      organizationControlId: control.id,
    }),
    { statusCode: 404 },
  );

  const stored = await prisma.checkControlMap.findFirstOrThrow({
    where: { checkId: FIREWALL_CHECK.id, organizationId: tenant.organization.id },
  });
  await expectAppError(deleteCheckMap(stranger.ctx, stored.id), { statusCode: 404 });
  assert.ok(await prisma.checkControlMap.findUnique({ where: { id: stored.id } }));

  const removed = await deleteCheckMap(tenant.ctx, stored.id);
  assert.equal(removed.id, stored.id);
  assert.equal(
    await prisma.checkControlMap.count({ where: { organizationId: tenant.organization.id } }),
    0,
  );
});

test('a mapping added after the finding exists still receives evidence', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const { principal } = await monitoredAgent(tenant, 'builtin-late-mapping');
  const control = await adoptedControl(tenant);

  const first = await recordAgentRun(principal, report([FIREWALL_CHECK]));
  assert.equal(first.findingsCreated, 1);
  assert.equal(first.controlEvidenceAttached, 0);

  await createCheckMap(tenant.ctx, {
    checkId: FIREWALL_CHECK.id,
    organizationControlId: control.id,
  });

  const second = await recordAgentRun(principal, report([FIREWALL_CHECK]));
  assert.equal(second.findingsRefreshed, 1);
  assert.equal(second.controlEvidenceAttached, 1);

  const evidence = await prisma.controlEvidence.findFirstOrThrow({
    where: { organizationControlId: control.id },
    select: { findingId: true },
  });
  const finding = await prisma.finding.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, source: 'AGENT' },
    select: { id: true },
  });
  assert.equal(evidence.findingId, finding.id);

  // A check that passes never produces evidence, mapped or not.
  const passing = await recordAgentRun(principal, report([PASSING_CHECK]));
  assert.equal(passing.controlEvidenceAttached, 0);
});
