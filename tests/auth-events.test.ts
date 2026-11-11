import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { before, test } from 'node:test';
import { APIError } from 'better-auth/api';
import { prisma } from '@/lib/prisma';
import {
  AuthEventActions,
  listRecentAuthEvents,
  recordAuthActivity,
  recordAuthEvent,
  recordSessionEnded,
} from '@/server/auth/events';
import { assertTestDatabase, createUser, resetDatabase } from './helpers/database.ts';

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

const rejectedPassword = () =>
  new APIError(401, { message: 'Invalid email or password', code: 'INVALID_EMAIL_OR_PASSWORD' });

test('a failed password sign-in is attributed to the account, never to the typed address', async () => {
  const user = await createUser();

  await recordAuthActivity({
    path: '/sign-in/email',
    body: { email: user.email.toUpperCase(), password: 'not-the-password' },
    headers: new Headers({ 'user-agent': 'node-test', 'x-forwarded-for': '203.0.113.9, 10.0.0.1' }),
    context: { returned: rejectedPassword() },
  });

  const attributed = await prisma.authEvent.findFirstOrThrow({
    where: { action: AuthEventActions.SIGN_IN_FAILED, userId: user.id },
  });
  assert.equal(attributed.outcome, 'FAILURE');
  assert.deepEqual(attributed.metadata, {
    method: 'password',
    code: 'INVALID_EMAIL_OR_PASSWORD',
  });
  assert.equal(attributed.userAgent, 'node-test');
  assert.equal(attributed.ipAddress, '203.0.113.9');

  const unknown = `intruder-${randomUUID()}@cybernorf.test`;
  await recordAuthActivity({
    path: '/sign-in/email',
    body: { email: unknown, password: 'not-the-password' },
    context: { returned: rejectedPassword() },
  });

  const unattributed = await prisma.authEvent.findFirstOrThrow({
    where: { action: AuthEventActions.SIGN_IN_FAILED, userId: null },
  });
  // The address an attacker types is not evidence about an account, so it is
  // not stored anywhere on the row.
  assert.equal(JSON.stringify(unattributed).includes('intruder-'), false);
});

test('a sign-in is recorded only for a request that created a session', async () => {
  const user = await createUser();

  await recordAuthActivity({
    path: '/sign-in/email',
    body: { email: user.email, password: 'correct-horse-battery' },
    context: { returned: { token: 'session-token' }, newSession: { user: { id: user.id } } },
  });

  const signedIn = await prisma.authEvent.findFirstOrThrow({
    where: { userId: user.id, action: AuthEventActions.SIGNED_IN },
  });
  assert.deepEqual(signedIn.metadata, { method: 'password' });

  // The second-factor challenge answers 200 without a session; nothing is
  // recorded until the second factor succeeds.
  const challengeOnly = await createUser();
  await recordAuthActivity({
    path: '/sign-in/email',
    body: { email: challengeOnly.email },
    context: { returned: { twoFactorRedirect: true }, newSession: null },
  });
  assert.equal(await prisma.authEvent.count({ where: { userId: challengeOnly.id } }), 0);
});

test('second-factor verification and enrolment are recorded with the method', async () => {
  const user = await createUser();

  await recordAuthActivity({
    path: '/two-factor/verify-totp',
    context: { returned: { ok: true }, newSession: { user: { id: user.id } } },
  });
  await recordAuthActivity({
    path: '/two-factor/verify-backup-code',
    context: { returned: { ok: true }, session: { user: { id: user.id } } },
  });

  const events = await prisma.authEvent.findMany({
    where: { userId: user.id, action: AuthEventActions.SECOND_FACTOR_SUCCEEDED },
    orderBy: { createdAt: 'asc' },
  });
  assert.equal(events.length, 2);
  assert.deepEqual(
    events.map((event) => event.metadata),
    [{ method: 'totp' }, { method: 'backup_code' }],
  );
});

test('ending a session records the account it belonged to', async () => {
  const user = await createUser();

  await recordSessionEnded({
    userId: user.id,
    headers: new Headers({ 'user-agent': 'node-test', 'x-real-ip': '198.51.100.4' }),
  });

  const event = await prisma.authEvent.findFirstOrThrow({
    where: { userId: user.id, action: AuthEventActions.SESSION_ENDED },
  });
  assert.equal(event.outcome, 'SUCCESS');
  assert.equal(event.ipAddress, '198.51.100.4');
});

test('stored request metadata is bounded and credential-redacted', async () => {
  const user = await createUser();
  const secret = ['Bearer', 'cnk_live_abcdef1234567890'].join(' ');

  await recordAuthEvent({
    action: AuthEventActions.SIGNED_IN,
    outcome: 'SUCCESS',
    userId: user.id,
    ipAddress: 'x'.repeat(500),
    userAgent: `agent/1.0 ${secret} ${'y'.repeat(500)}`,
    metadata: {},
  });

  const event = await prisma.authEvent.findFirstOrThrow({ where: { userId: user.id } });
  assert.equal(event.ipAddress?.length, 64);
  assert.equal(event.userAgent?.length, 256);
  assert.equal(event.userAgent?.includes('abcdef1234567890'), false);
});

test('the activity of one account is never returned for another', async () => {
  const first = await createUser();
  const second = await createUser();

  await recordAuthEvent({
    action: AuthEventActions.SIGNED_IN,
    outcome: 'SUCCESS',
    userId: first.id,
    metadata: { method: 'password' },
  });
  await recordAuthEvent({
    action: AuthEventActions.SIGN_IN_FAILED,
    outcome: 'FAILURE',
    userId: second.id,
    metadata: { method: 'password' },
  });

  const events = await listRecentAuthEvents(first.id);
  assert.equal(events.length, 1);
  assert.equal(events[0]?.label, 'Signed in');
  assert.equal(events[0]?.outcome, 'SUCCESS');
});

test('the activity table rejects updates and deletes', async () => {
  const user = await createUser();
  await recordAuthEvent({
    action: AuthEventActions.SIGNED_IN,
    outcome: 'SUCCESS',
    userId: user.id,
    metadata: {},
  });
  const event = await prisma.authEvent.findFirstOrThrow({ where: { userId: user.id } });

  await assert.rejects(
    prisma.authEvent.update({ where: { id: event.id }, data: { outcome: 'FAILURE' } }),
    /append-only/,
  );
  await assert.rejects(prisma.authEvent.delete({ where: { id: event.id } }), /append-only/);
});
