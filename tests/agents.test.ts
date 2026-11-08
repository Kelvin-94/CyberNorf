import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import type { TenantContext } from '@/server/authz/context';
import type { OrgRole } from '@/server/authz/roles';
import { agentHasScope, hashAgentToken } from '@/server/domain/agents';
import {
  approveAgent,
  authenticateAgentToken,
  describeAgent,
  getAgentDetail,
  getAgentRun,
  listAgents,
  recordAgentRun,
  registerAgent,
  resumeAgent,
  revokeAgent,
  suspendAgent,
} from '@/server/services/agents';
import {
  assertTestDatabase,
  createTenant,
  createUser,
  expectAppError,
  prisma,
  resetDatabase,
  type TestTenant,
} from './helpers/database.ts';

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

/** Adds a second member with another role to an existing tenant. */
async function addMember(tenant: TestTenant, role: OrgRole): Promise<TenantContext> {
  const user = await createUser({ twoFactorEnabled: true });
  await prisma.membership.create({
    data: {
      userId: user.id,
      organizationId: tenant.organization.id,
      role,
      status: 'ACTIVE',
    },
  });
  const membership = await prisma.membership.findUniqueOrThrow({
    where: {
      userId_organizationId: { userId: user.id, organizationId: tenant.organization.id },
    },
    select: { id: true, role: true },
  });

  return {
    user,
    organization: tenant.organization,
    membership,
    meta: tenant.ctx.meta,
  };
}

const FAILING_SSH_CHECK = {
  id: 'auth.ssh-password-authentication',
  title: 'SSH password authentication is disabled',
  status: 'FAIL' as const,
  severity: 'HIGH' as const,
  detail: 'PasswordAuthentication=yes in sshd_config',
  remediation: 'Set PasswordAuthentication no and reload sshd.',
};

function monitoringReport() {
  return {
    hostname: 'kelvins-imac',
    platform: 'darwin 25.6.0',
    startedAt: new Date(Date.now() - 1500),
    durationMs: 1500,
    checks: [
      FAILING_SSH_CHECK,
      {
        id: 'vuln.filevault',
        title: 'Full-disk encryption is enabled',
        status: 'PASS' as const,
        severity: 'MEDIUM' as const,
      },
      {
        id: 'access.sudo-nopasswd',
        title: 'Passwordless sudo is not configured',
        status: 'SKIP' as const,
        severity: 'LOW' as const,
        detail: 'sudoers is not readable as the invoking user',
      },
    ],
  };
}

test('a builtin agent is active on registration and its issued token authenticates', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const registration = await registerAgent(tenant.ctx, {
    name: 'builtin-host-monitor',
    source: 'BUILTIN',
    description: 'Checks local authentication, access and vulnerability posture.',
  });

  assert.equal(registration.agent.status, 'ACTIVE');
  assert.deepEqual(registration.agent.scopes, ['monitor.report', 'monitor.read']);
  assert.ok(registration.token, 'builtin registration must return a credential');
  const token = registration.token;
  assert.match(token, /^cna_/);

  const stored = await prisma.agent.findUniqueOrThrow({
    where: { id: registration.agent.id },
    select: { tokenHash: true, tokenPrefix: true, tokenExpiresAt: true },
  });
  assert.equal(stored.tokenHash, hashAgentToken(token));
  assert.notEqual(stored.tokenHash, token);
  assert.ok(token.startsWith(stored.tokenPrefix ?? ''));
  const daysToExpiry =
    ((stored.tokenExpiresAt?.getTime() ?? 0) - Date.now()) / (24 * 60 * 60 * 1000);
  assert.ok(daysToExpiry > 360 && daysToExpiry <= 365);

  const principal = await authenticateAgentToken(token);
  assert.equal(principal.id, registration.agent.id);
  assert.equal(principal.organizationId, tenant.organization.id);
  assert.equal(principal.createdById, tenant.user.id);

  const self = await describeAgent(principal);
  assert.equal(self.name, 'builtin-host-monitor');
  assert.equal(self.status, 'ACTIVE');

  const audit = await prisma.auditEvent.findFirst({
    where: {
      organizationId: tenant.organization.id,
      action: 'agent.registered',
      targetId: registration.agent.id,
    },
    select: { outcome: true },
  });
  assert.equal(audit?.outcome, 'SUCCESS');
});

test('an external agent stays inert until the organization owner approves it', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const admin = await addMember(tenant, 'ADMIN');

  const registration = await registerAgent(tenant.ctx, {
    name: 'claude-soc-reviewer',
    source: 'ANTHROPIC',
    scopes: ['monitor.report'],
  });
  assert.equal(registration.agent.status, 'PENDING_APPROVAL');
  assert.equal(registration.token, null);
  assert.deepEqual(registration.agent.scopes, ['monitor.report']);

  const stored = await prisma.agent.findUniqueOrThrow({
    where: { id: registration.agent.id },
    select: { tokenHash: true, tokenPrefix: true },
  });
  assert.equal(stored.tokenHash, null);
  assert.equal(stored.tokenPrefix, null);

  // Administrators can see the agent but cannot grant it access.
  await expectAppError(approveAgent(admin, registration.agent.id, {}), { statusCode: 403 });
  // Approval can narrow the requested scopes, never widen them.
  await expectAppError(
    approveAgent(tenant.ctx, registration.agent.id, {
      scopes: ['monitor.report', 'monitor.read'],
    }),
    { statusCode: 400 },
  );

  const approval = await approveAgent(tenant.ctx, registration.agent.id, {
    scopes: ['monitor.report'],
    note: 'Approved for the nightly authentication sweep only.',
  });
  assert.equal(approval.agent.status, 'ACTIVE');
  assert.deepEqual(approval.agent.scopes, ['monitor.report']);
  assert.match(approval.token, /^cna_/);

  const principal = await authenticateAgentToken(approval.token);
  assert.equal(agentHasScope(principal.scopes, 'monitor.report'), true);
  assert.equal(agentHasScope(principal.scopes, 'monitor.read'), false);

  const audit = await prisma.auditEvent.findFirst({
    where: {
      organizationId: tenant.organization.id,
      action: 'agent.approved',
      targetId: registration.agent.id,
    },
    select: { actorType: true, actorId: true },
  });
  assert.equal(audit?.actorType, 'USER');
  assert.equal(audit?.actorId, tenant.user.id);

  await expectAppError(
    authenticateAgentToken(`cna_${'a'.repeat(43)}`),
    { statusCode: 401 },
  );
});

test('failed checks raise one finding per check and target, and closed findings stay closed', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const registration = await registerAgent(tenant.ctx, {
    name: 'builtin-run-agent',
    source: 'BUILTIN',
  });
  const token = registration.token ?? assert.fail('expected a builtin token');
  const principal = await authenticateAgentToken(token);

  const first = await recordAgentRun(principal, monitoringReport());
  assert.equal(first.run.status, 'PARTIAL');
  assert.equal(first.run.checkCount, 3);
  assert.equal(first.run.passCount, 1);
  assert.equal(first.run.failCount, 1);
  assert.equal(first.run.skipCount, 1);
  assert.equal(first.findingsCreated, 1);

  const findings = await prisma.finding.findMany({
    where: { organizationId: tenant.organization.id, source: 'AGENT' },
    select: {
      id: true,
      title: true,
      severity: true,
      status: true,
      agentId: true,
      createdById: true,
      fingerprint: true,
    },
  });
  assert.equal(findings.length, 1);
  const finding = findings[0];
  assert.ok(finding);
  assert.equal(finding.title, FAILING_SSH_CHECK.title);
  assert.equal(finding.severity, 'HIGH');
  assert.equal(finding.status, 'OPEN');
  assert.equal(finding.agentId, registration.agent.id);
  assert.equal(finding.createdById, tenant.user.id);

  const detail = await getAgentRun(tenant.ctx, registration.agent.id, first.run.id);
  assert.equal(detail.checks.length, 3);
  assert.equal(detail.findings.length, 1);

  const second = await recordAgentRun(principal, monitoringReport());
  assert.equal(second.findingsCreated, 0);
  assert.equal(second.findingsRefreshed, 1);
  const afterSecond = await prisma.finding.count({ where: { organizationId: tenant.organization.id } });
  assert.equal(afterSecond, 1, 'a repeated failure must not duplicate the finding');

  // A human closed the finding; later runs must not reopen that decision.
  await prisma.finding.update({ where: { id: finding.id }, data: { status: 'RESOLVED' } });
  const third = await recordAgentRun(principal, monitoringReport());
  assert.equal(third.findingsCreated, 0);
  assert.equal(third.findingsRefreshed, 0);
  assert.equal(third.findingsSuppressed, 1);
  const resolved = await prisma.finding.findUniqueOrThrow({
    where: { id: finding.id },
    select: { status: true },
  });
  assert.equal(resolved.status, 'RESOLVED');

  const agent = await prisma.agent.findUniqueOrThrow({
    where: { id: registration.agent.id },
    select: { runCount: true, lastRunAt: true, lastSeenAt: true },
  });
  assert.equal(agent.runCount, 3);
  assert.ok(agent.lastRunAt);
  assert.ok(agent.lastSeenAt);

  const runAudit = await prisma.auditEvent.findFirst({
    where: {
      organizationId: tenant.organization.id,
      action: 'agent.run_recorded',
      targetId: registration.agent.id,
    },
    select: { actorType: true },
  });
  assert.equal(runAudit?.actorType, 'AGENT');

  const history = await getAgentDetail(tenant.ctx, registration.agent.id);
  assert.equal(history.runs.length, 3);
  assert.equal(history.findings.length, 1);
});

test('suspension stops the credential, resumption restores it and revocation is terminal', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const admin = await addMember(tenant, 'ADMIN');
  const registration = await registerAgent(tenant.ctx, {
    name: 'rotating-endpoint-agent',
    source: 'BUILTIN',
  });
  const token = registration.token ?? assert.fail('expected a builtin token');

  await expectAppError(suspendAgent(admin, registration.agent.id, 'not owner'), { statusCode: 403 });

  const suspended = await suspendAgent(tenant.ctx, registration.agent.id, 'Rotating the host image.');
  assert.equal(suspended.status, 'SUSPENDED');
  await expectAppError(authenticateAgentToken(token), { statusCode: 401 });

  const resumed = await resumeAgent(tenant.ctx, registration.agent.id, null);
  assert.equal(resumed.status, 'ACTIVE');
  const principal = await authenticateAgentToken(token);
  assert.equal(principal.id, registration.agent.id);

  // Suspending again after resumption is allowed, revocation is not.
  const revoked = await revokeAgent(tenant.ctx, registration.agent.id, 'Host decommissioned.');
  assert.equal(revoked.status, 'REVOKED');
  assert.ok(revoked.revokedAt);
  await expectAppError(authenticateAgentToken(token), { statusCode: 401 });
  await expectAppError(suspendAgent(tenant.ctx, registration.agent.id, null), { statusCode: 409 });
  await expectAppError(resumeAgent(tenant.ctx, registration.agent.id, null), { statusCode: 409 });
  await expectAppError(revokeAgent(tenant.ctx, registration.agent.id, null), { statusCode: 409 });

  const cleared = await prisma.agent.findUniqueOrThrow({
    where: { id: registration.agent.id },
    select: { tokenHash: true },
  });
  assert.equal(cleared.tokenHash, null, 'revocation must clear the stored hash too');
});

test('agents are scoped to their organization and names stay unique per tenant', async () => {
  const first = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const second = await createTenant({ role: 'OWNER', twoFactorEnabled: true });

  const registration = await registerAgent(first.ctx, {
    name: 'edge-node-monitor',
    source: 'BUILTIN',
  });

  await expectAppError(getAgentDetail(second.ctx, registration.agent.id), { statusCode: 404 });
  await expectAppError(revokeAgent(second.ctx, registration.agent.id, null), { statusCode: 404 });
  const otherList = await listAgents(second.ctx);
  assert.equal(otherList.agents.length, 0);

  const ownList = await listAgents(first.ctx);
  assert.equal(ownList.agents.length, 1);
  assert.equal(ownList.counts.ACTIVE, 1);

  await expectAppError(
    registerAgent(first.ctx, { name: 'edge-node-monitor', source: 'OPENAI' }),
    { statusCode: 409 },
  );
  // The same name is fine in a different organization.
  const elsewhere = await registerAgent(second.ctx, {
    name: 'edge-node-monitor',
    source: 'BUILTIN',
  });
  assert.equal(elsewhere.agent.status, 'ACTIVE');
});

test('every agent action extends the hash-chained audit trail', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const { verifyAuditChain } = await import('@/server/audit/audit');

  const registration = await registerAgent(tenant.ctx, {
    name: 'audited-agent',
    source: 'CUSTOM',
  });
  await approveAgent(tenant.ctx, registration.agent.id, { note: 'custom integration' });
  await suspendAgent(tenant.ctx, registration.agent.id, 'pause');
  await resumeAgent(tenant.ctx, registration.agent.id, null);
  await revokeAgent(tenant.ctx, registration.agent.id, 'retired');

  const actions = await prisma.auditEvent.findMany({
    where: { organizationId: tenant.organization.id, targetId: registration.agent.id },
    orderBy: { sequence: 'asc' },
    select: { action: true },
  });
  assert.deepEqual(
    actions.map((row) => row.action),
    [
      'agent.registered',
      'agent.approved',
      'agent.suspended',
      'agent.resumed',
      'agent.revoked',
    ],
  );

  const chain = await verifyAuditChain(tenant.organization.id);
  assert.equal(chain.valid, true);
});

test('a failing check titles the finding with the reported faulty state', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const registration = await registerAgent(tenant.ctx, {
    name: 'control-titles',
    source: 'BUILTIN',
  });
  assert.ok(registration.token, 'builtin registration must return a credential');
  const principal = await authenticateAgentToken(registration.token);

  const result = await recordAgentRun(principal, {
    hostname: 'control-title-host',
    startedAt: new Date(),
    checks: [
      {
        id: 'access.host-firewall',
        title: 'Host firewall state',
        findingTitle: 'Host firewall is disabled',
        status: 'FAIL',
        severity: 'HIGH',
        detail: 'Firewall is disabled. (State = 0)',
      },
    ],
  });

  assert.equal(result.findingsCreated, 1);
  assert.equal(result.run.failCount, 1);

  const finding = await prisma.finding.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, agentId: registration.agent.id },
    select: { title: true, description: true },
  });
  // The run keeps the control name; the finding states the faulty condition.
  assert.equal(finding.title, 'Host firewall is disabled');
  assert.equal(finding.description, 'Firewall is disabled. (State = 0)');

  const detail = await getAgentRun(tenant.ctx, registration.agent.id, result.run.id);
  assert.equal(detail.checks[0]?.title, 'Host firewall state');

  // The finding detail page builds its history from the audit trail, so the
  // creation event has to exist and name the agent as the actor.
  const findingId = detail.findings[0]?.id;
  assert.ok(findingId, 'the run should link the finding it created');
  const creationEvent = await prisma.auditEvent.findFirstOrThrow({
    where: {
      organizationId: tenant.organization.id,
      targetType: 'finding',
      targetId: findingId,
    },
    select: { action: true, actorType: true, metadata: true },
  });
  assert.equal(creationEvent.action, 'finding.created');
  assert.equal(creationEvent.actorType, 'AGENT');
  assert.equal(
    (creationEvent.metadata as { agentId?: string }).agentId,
    registration.agent.id,
  );
  assert.equal(
    (creationEvent.metadata as { runId?: string }).runId,
    result.run.id,
  );
});
