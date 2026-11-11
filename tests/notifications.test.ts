import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, test } from 'node:test';
import { verifyDelivery } from '@/server/domain/notifications';
import { registerAgent } from '@/server/services/agents';
import {
  createNotificationChannel,
  deleteNotificationChannel,
  dispatchDueNotifications,
  getNotificationSettings,
  sendTestNotification,
  sweepAgentHealth,
} from '@/server/services/notifications';
import {
  assertTestDatabase,
  createTenant,
  expectAppError,
  prisma,
  resetDatabase,
} from './helpers/database.ts';

/**
 * A local receiver stands in for a customer's alert endpoint. Loopback
 * destinations are refused by default, so the suite opts in the same way a
 * deployment with an internal collector would.
 */
interface ReceivedDelivery {
  path: string;
  headers: IncomingMessage['headers'];
  body: string;
}

const received: ReceivedDelivery[] = [];
let server: Server;
let baseUrl = '';

function listen(handler: (request: IncomingMessage, response: ServerResponse) => void): Server {
  const instance = createServer((request, response) => {
    let body = '';
    request.on('data', (chunk: Buffer) => {
      body += chunk.toString('utf8');
    });
    request.on('end', () => {
      received.push({ path: request.url ?? '/', headers: request.headers, body });
      handler(request, response);
    });
  });
  instance.listen(0, '127.0.0.1');
  return instance;
}

before(async () => {
  assertTestDatabase();
  await resetDatabase();
  process.env.NOTIFY_ALLOW_PRIVATE_WEBHOOKS = 'true';
  server = listen((request, response) => {
    response.statusCode = request.url === '/reject' ? 500 : 204;
    response.end();
  });
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const address = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  delete process.env.NOTIFY_ALLOW_PRIVATE_WEBHOOKS;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

test('a destination keeps only a sealed secret and never returns it', async () => {
  const tenant = await createTenant({ role: 'ADMIN' });
  const secret = 'signing-secret-'.padEnd(48, 'x');

  const created = await createNotificationChannel(tenant.ctx, {
    name: 'SOC bridge',
    url: `${baseUrl}/accept`,
    secret,
  });

  assert.equal(created.channel.url, `${baseUrl}/accept`);
  assert.equal(created.channel.name, 'SOC bridge');
  assert.ok(
    !JSON.stringify(created).includes(secret),
    'the signing secret must not appear in the API view',
  );

  const stored = await prisma.notificationChannel.findFirstOrThrow({
    where: { organizationId: tenant.organization.id },
    select: { secretSealed: true },
  });
  assert.notEqual(stored.secretSealed, secret);
  assert.match(stored.secretSealed, /^v1\./);

  const settings = await getNotificationSettings(tenant.ctx);
  assert.equal(settings.channels.length, 1);
  assert.ok(!JSON.stringify(settings).includes(secret));
  assert.equal(
    settings.scheduling.enabled,
    Boolean(process.env.CRON_SECRET?.trim()),
    'the console must reflect whether the sweep can run at all',
  );

  await deleteNotificationChannel(tenant.ctx, created.channel.id);
  assert.equal(
    await prisma.notificationChannel.count({ where: { organizationId: tenant.organization.id } }),
    0,
  );
});

test('a destination with a duplicate name is refused', async () => {
  const tenant = await createTenant({ role: 'ADMIN' });
  await createNotificationChannel(tenant.ctx, {
    name: 'Duplicate',
    url: `${baseUrl}/accept`,
    secret: 'a'.repeat(40),
  });

  await expectAppError(
    createNotificationChannel(tenant.ctx, {
      name: 'Duplicate',
      url: `${baseUrl}/accept`,
      secret: 'b'.repeat(40),
    }),
    { statusCode: 409 },
  );
});

test('a private destination is refused unless the deployment opts in', async () => {
  const tenant = await createTenant({ role: 'ADMIN' });
  delete process.env.NOTIFY_ALLOW_PRIVATE_WEBHOOKS;
  try {
    await expectAppError(
      createNotificationChannel(tenant.ctx, {
        name: 'Internal collector',
        url: `${baseUrl}/accept`,
        secret: 'c'.repeat(40),
      }),
      { statusCode: 400 },
    );
  } finally {
    process.env.NOTIFY_ALLOW_PRIVATE_WEBHOOKS = 'true';
  }
});

test('a test delivery is signed over the timestamp and body', async () => {
  const tenant = await createTenant({ role: 'ADMIN' });
  const secret = 'test-signature-secret'.padEnd(40, 'z');
  const { channel } = await createNotificationChannel(tenant.ctx, {
    name: 'Signed bridge',
    url: `${baseUrl}/accept`,
    secret,
  });

  received.length = 0;
  const result = await sendTestNotification(tenant.ctx, channel.id);
  assert.equal(result.status, 'SENT');
  assert.equal(result.error, null);

  assert.equal(received.length, 1);
  const delivery = received[0]!;
  const timestamp = delivery.headers['x-cybernorf-timestamp'];
  const signature = delivery.headers['x-cybernorf-signature'];
  assert.equal(typeof timestamp, 'string');
  assert.equal(typeof signature, 'string');

  const payload = JSON.parse(delivery.body) as { type: string; organizationId: string };
  assert.equal(payload.type, 'TEST');
  assert.equal(payload.organizationId, tenant.organization.id);
  assert.equal(
    verifyDelivery(
      secret,
      String(timestamp),
      delivery.body,
      String(signature).replace(/^sha256=/, ''),
    ),
    true,
    'the receiver must be able to verify the delivery with the shared secret',
  );

  const stored = await prisma.notificationEvent.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, channelId: channel.id },
    select: { status: true, attempts: true, deliveredAt: true },
  });
  assert.equal(stored.status, 'SENT');
  assert.equal(stored.attempts, 1);
  assert.ok(stored.deliveredAt);
});

test('a refused delivery stays pending with backoff and a recorded error', async () => {
  const tenant = await createTenant({ role: 'ADMIN' });
  const { channel } = await createNotificationChannel(tenant.ctx, {
    name: 'Rejecting bridge',
    url: `${baseUrl}/reject`,
    secret: 'd'.repeat(40),
  });

  const result = await sendTestNotification(tenant.ctx, channel.id);
  assert.equal(result.status, 'PENDING');
  assert.match(result.error ?? '', /500/);

  const stored = await prisma.notificationEvent.findFirstOrThrow({
    where: { channelId: channel.id },
    select: { status: true, attempts: true, nextAttemptAt: true, lastError: true },
  });
  assert.equal(stored.status, 'PENDING');
  assert.equal(stored.attempts, 1);
  assert.ok(stored.nextAttemptAt.getTime() > Date.now(), 'a failed attempt schedules a retry');
  assert.match(stored.lastError ?? '', /500/);
});

test('the sweep alerts once per outage, delivers, then reports recovery', async () => {
  const tenant = await createTenant({ role: 'OWNER' });
  const accepting = await createNotificationChannel(tenant.ctx, {
    name: 'Accepting bridge',
    url: `${baseUrl}/accept`,
    secret: 'e'.repeat(40),
  });
  const rejecting = await createNotificationChannel(tenant.ctx, {
    name: 'Rejecting bridge',
    url: `${baseUrl}/reject`,
    secret: 'f'.repeat(40),
  });

  const registration = await registerAgent(tenant.ctx, { name: 'quiet-host', source: 'BUILTIN' });
  const agentId = registration.agent.id;
  const threeHoursAgo = new Date(Date.now() - 3 * 60 * 60 * 1000);
  await prisma.agent.update({
    where: { id: agentId },
    data: { expectedIntervalMinutes: 60, lastRunAt: threeHoursAgo, lastSeenAt: threeHoursAgo },
  });

  const first = await sweepAgentHealth({ organizationId: tenant.organization.id });
  assert.equal(first.agentsChecked, 1);
  assert.equal(first.wentOffline, 1);
  assert.equal(first.queued, 2, 'one alert per enabled destination');

  const second = await sweepAgentHealth({ organizationId: tenant.organization.id });
  assert.equal(second.wentOffline, 0, 'a repeated sweep must not page twice');
  assert.equal(second.queued, 0);

  const offlineEvents = await prisma.notificationEvent.findMany({
    where: { organizationId: tenant.organization.id, type: 'AGENT_OFFLINE' },
    select: { channelId: true, status: true, dedupeKey: true },
  });
  assert.equal(offlineEvents.length, 2);
  assert.deepEqual(
    new Set(offlineEvents.map((event) => event.channelId)),
    new Set([accepting.channel.id, rejecting.channel.id]),
  );

  const dispatched = await dispatchDueNotifications({ organizationId: tenant.organization.id });
  assert.equal(dispatched.attempted, 2);
  assert.equal(dispatched.sent, 1);
  assert.equal(dispatched.retried, 1);

  const marked = await prisma.agent.findUniqueOrThrow({
    where: { id: agentId },
    select: { offlineNotifiedAt: true },
  });
  assert.ok(marked.offlineNotifiedAt, 'the outage marker is set while the agent is down');

  await prisma.agent.update({
    where: { id: agentId },
    data: { lastRunAt: new Date(), lastSeenAt: new Date() },
  });

  const recovery = await sweepAgentHealth({ organizationId: tenant.organization.id });
  assert.equal(recovery.recovered, 1);
  assert.equal(recovery.queued, 2);

  const after = await prisma.notificationEvent.groupBy({
    by: ['type', 'status'],
    where: { organizationId: tenant.organization.id },
    _count: { _all: true },
  });
  const pendingOffline = after.find(
    (row) => row.type === 'AGENT_OFFLINE' && row.status === 'PENDING',
  );
  assert.equal(
    pendingOffline?._count._all ?? 0,
    0,
    'an outage alert still queued when the host recovers must not be delivered',
  );
  const recoveredPending = after.find(
    (row) => row.type === 'AGENT_RECOVERED' && row.status === 'PENDING',
  );
  assert.equal(recoveredPending?._count._all ?? 0, 2, 'each destination hears about the recovery');

  const cleared = await prisma.agent.findUniqueOrThrow({
    where: { id: agentId },
    select: { offlineNotifiedAt: true },
  });
  assert.equal(cleared.offlineNotifiedAt, null);
});

test('an agent without a destination is not marked as notified', async () => {
  const tenant = await createTenant({ role: 'OWNER' });
  const registration = await registerAgent(tenant.ctx, { name: 'unwatched', source: 'BUILTIN' });
  await prisma.agent.update({
    where: { id: registration.agent.id },
    data: {
      expectedIntervalMinutes: 30,
      lastRunAt: new Date(Date.now() - 4 * 60 * 60 * 1000),
    },
  });

  const sweep = await sweepAgentHealth({ organizationId: tenant.organization.id });
  assert.equal(sweep.wentOffline, 0);
  assert.equal(sweep.queued, 0);

  const agent = await prisma.agent.findUniqueOrThrow({
    where: { id: registration.agent.id },
    select: { offlineNotifiedAt: true },
  });
  assert.equal(agent.offlineNotifiedAt, null);
});

test('a destination and its deliveries appear in the settings view', async () => {
  const tenant = await createTenant({ role: 'ADMIN' });
  const { channel } = await createNotificationChannel(tenant.ctx, {
    name: 'Analyst visible',
    url: `${baseUrl}/accept`,
    secret: 'g'.repeat(40),
  });
  await sendTestNotification(tenant.ctx, channel.id);

  const settings = await getNotificationSettings(tenant.ctx);
  assert.equal(settings.channels[0]?.name, 'Analyst visible');
  assert.equal(settings.deliveries[0]?.status, 'SENT');
  assert.equal(settings.deliveries[0]?.channel.name, 'Analyst visible');
});
