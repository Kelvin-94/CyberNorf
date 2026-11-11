import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import {
  AGENT_SIGNATURE_HEADER,
  AGENT_TIMESTAMP_HEADER,
  signAgentBody,
} from '@/server/domain/agent-signature';
import { assertAgentRequestSignature } from '@/server/http/agent-signature';
import {
  authenticateAgentToken,
  registerAgent,
  revokeAgent,
  rotateAgentToken,
} from '@/server/services/agents';
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

after(() => {
  delete process.env.AGENT_REQUIRE_SIGNED_RUNS;
});

test('rotation replaces an active credential and the old token stops working', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const registration = await registerAgent(tenant.ctx, {
    name: 'rotating-agent',
    source: 'BUILTIN',
  });
  const original = registration.token ?? assert.fail('expected a builtin token');

  const rotated = await rotateAgentToken(tenant.ctx, registration.agent.id, 'scheduled rotation');

  assert.equal(rotated.agent.id, registration.agent.id);
  assert.equal(rotated.agent.status, 'ACTIVE');
  assert.notEqual(rotated.token, original);
  assert.equal(rotated.agent.tokenPrefix, rotated.token.slice(0, 10));

  // The old credential no longer resolves; the new one does, on the same agent.
  await expectAppError(authenticateAgentToken(original), { statusCode: 401 });
  const principal = await authenticateAgentToken(rotated.token);
  assert.equal(principal.id, registration.agent.id);

  const audit = await prisma.auditEvent.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, action: 'agent.token_rotated' },
    select: { actorType: true, metadata: true },
  });
  assert.equal(audit.actorType, 'USER');
  const metadata = (audit.metadata ?? {}) as Record<string, unknown>;
  assert.equal(metadata.previousPrefix, registration.agent.tokenPrefix);
  assert.equal(metadata.tokenPrefix, rotated.agent.tokenPrefix);
  assert.equal(metadata.note, 'scheduled rotation');

  // Rotating again keeps working and keeps the row count at one.
  const again = await rotateAgentToken(tenant.ctx, registration.agent.id);
  await expectAppError(authenticateAgentToken(rotated.token), { statusCode: 401 });
  await authenticateAgentToken(again.token);
  assert.equal(await prisma.agent.count({ where: { organizationId: tenant.organization.id } }), 1);
});

test('only an owner can rotate, and only an active agent', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const registration = await registerAgent(tenant.ctx, {
    name: 'guarded-agent',
    source: 'BUILTIN',
  });

  const adminCtx = await createTenant({ role: 'ADMIN', twoFactorEnabled: true });
  // The owner check runs before the agent is loaded, so an administrator is
  // refused outright rather than told whether the agent exists.
  await expectAppError(rotateAgentToken(adminCtx.ctx, registration.agent.id), {
    statusCode: 403,
  });

  await prisma.agent.update({
    where: { id: registration.agent.id },
    data: { status: 'SUSPENDED' },
  });
  await expectAppError(rotateAgentToken(tenant.ctx, registration.agent.id), { statusCode: 409 });

  await revokeAgent(tenant.ctx, registration.agent.id);
  await expectAppError(rotateAgentToken(tenant.ctx, registration.agent.id), { statusCode: 409 });
});

test('signature enforcement accepts a valid signature and rejects tampering', () => {
  const credential = 'cna_cccccccccccccccccccccccccccccccccccccccccccc';
  const body = '{"hostname":"host","checks":[]}';
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = signAgentBody(credential, timestamp, body);

  const signed = new Request('https://cybernorf.example/api/v1/agents/me/runs', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      [AGENT_SIGNATURE_HEADER]: signature,
      [AGENT_TIMESTAMP_HEADER]: String(timestamp),
    },
    body,
  });
  assert.doesNotThrow(() => assertAgentRequestSignature(signed, credential, body));

  // Same signature, different body: rejected even with signing optional.
  assert.throws(() => assertAgentRequestSignature(signed, credential, `${body} `), /signature/);

  // A signature is only valid for the credential that produced it.
  assert.throws(() => assertAgentRequestSignature(signed, `${credential}x`, body), /signature/);

  // Unsigned submissions pass only while enforcement is off.
  const unsigned = new Request('https://cybernorf.example/api/v1/agents/me/runs', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  });
  assert.doesNotThrow(() => assertAgentRequestSignature(unsigned, credential, body));

  process.env.AGENT_REQUIRE_SIGNED_RUNS = 'true';
  assert.throws(() => assertAgentRequestSignature(unsigned, credential, body), /signature/);
  assert.doesNotThrow(() => assertAgentRequestSignature(signed, credential, body));
  process.env.AGENT_REQUIRE_SIGNED_RUNS = 'false';
  assert.doesNotThrow(() => assertAgentRequestSignature(unsigned, credential, body));
});
