import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import { recordAuditEvent, verifyAuditChain } from '@/server/audit/audit';
import { prisma } from '@/lib/prisma';
import { assertTestDatabase, createTenant, resetDatabase } from './helpers/database.ts';

const fixture = (...parts: string[]) => parts.join('');

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

test('audit storage rejects credentials in summaries and metadata', async () => {
  const tenant = await createTenant({ role: 'OWNER' });

  const bearer = fixture('cnk_', 'live_', 'abcdef1234567890');
  const webhookSecret = fixture('whsec_', 'abcdef123456');
  const apiKey = fixture('cnk_', 'abcdef');
  const queryCredential = fixture('abc', '123def456');

  await recordAuditEvent({
    organizationId: tenant.organization.id,
    actorType: 'USER',
    actorId: tenant.user.id,
    action: 'organization.updated',
    outcome: 'SUCCESS',
    summary: `Updated webhook with Authorization: Bearer ${bearer}`,
    metadata: {
      password: 'hunter2hunter2',
      webhookSecret,
      endpoint: `https://alerts.example.test/hook?token=${queryCredential}`,
      nested: { apiKey, note: 'rotated signing key' },
    },
  });

  const event = await prisma.auditEvent.findFirstOrThrow({
    where: { organizationId: tenant.organization.id },
  });

  assert.ok(event.summary !== null);
  assert.ok(!event.summary.includes(bearer));
  assert.match(event.summary, /\[redacted\]/);

  const metadata = event.metadata as Record<string, unknown>;
  assert.equal(metadata.password, '[redacted]');
  assert.equal(metadata.webhookSecret, '[redacted]');
  assert.ok(!String(metadata.endpoint).includes(queryCredential));
  assert.ok(String(metadata.endpoint).includes('/hook'));
  const nested = metadata.nested as Record<string, unknown>;
  assert.equal(nested.apiKey, '[redacted]');
  assert.equal(nested.note, 'rotated signing key');

  // Redaction happens before hashing, so the stored chain still verifies.
  const verification = await verifyAuditChain(tenant.organization.id);
  assert.equal(verification.valid, true);
  assert.equal(verification.checked, 1);
});
