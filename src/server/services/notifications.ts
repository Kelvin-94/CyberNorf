import { Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent, recordAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import {
  MAX_DELIVERY_ATTEMPTS,
  deliveryBackoffMs,
  deriveAgentHealth,
  offlineDedupeKey,
  offlineDedupePrefix,
  recoveredDedupeKey,
  signDelivery,
  type AgentHealth,
  type NotificationEventType,
} from '@/server/domain/notifications';
import { AppError, conflict, notFound } from '@/server/errors';
import {
  allowPrivateWebhooks,
  assertSafeWebhookUrl,
  resolveWebhookTarget,
} from '@/server/security/outbound';
import { openSecret, sealSecret } from '@/server/security/secrets';
import { sendPinnedPost } from '@/server/security/webhook-transport';
import { isUniqueConstraintError } from '@/server/services/shared';
import type { CreateNotificationChannelInput } from '@/server/validation/notifications';

/** Per-delivery network budget. A slow endpoint must not stall the sweep. */
const DELIVERY_TIMEOUT_MS = 5_000;

/** How many due deliveries one sweep handles, so a backlog cannot pin a worker. */
const DELIVERY_BATCH_SIZE = 25;

/** How many agents one health sweep examines. */
const HEALTH_BATCH_SIZE = 500;

const ERROR_TEXT_LIMIT = 300;

export interface NotificationChannelView {
  id: string;
  name: string;
  kind: 'WEBHOOK';
  url: string;
  enabled: boolean;
  createdAt: string;
  lastDeliveredAt: string | null;
  lastError: string | null;
  createdBy: string | null;
}

export interface NotificationDeliveryView {
  id: string;
  type: NotificationEventType;
  status: 'PENDING' | 'SENT' | 'FAILED';
  attempts: number;
  channel: { id: string; name: string };
  createdAt: string;
  deliveredAt: string | null;
  nextAttemptAt: string;
  lastError: string | null;
}

export interface NotificationSettingsView {
  channels: NotificationChannelView[];
  deliveries: NotificationDeliveryView[];
  scheduling: {
    enabled: boolean;
    maxAttempts: number;
    allowPrivateDestinations: boolean;
  };
}

const CHANNEL_SELECT = {
  id: true,
  name: true,
  kind: true,
  url: true,
  enabled: true,
  createdAt: true,
  lastDeliveredAt: true,
  lastError: true,
  createdBy: { select: { name: true } },
} as const satisfies Prisma.NotificationChannelSelect;

const DELIVERY_SELECT = {
  id: true,
  type: true,
  status: true,
  attempts: true,
  createdAt: true,
  deliveredAt: true,
  nextAttemptAt: true,
  lastError: true,
  channel: { select: { id: true, name: true } },
} as const satisfies Prisma.NotificationEventSelect;

type ChannelRow = Prisma.NotificationChannelGetPayload<{ select: typeof CHANNEL_SELECT }>;
type DeliveryRow = Prisma.NotificationEventGetPayload<{ select: typeof DELIVERY_SELECT }>;

function serializeChannel(row: ChannelRow): NotificationChannelView {
  return {
    id: row.id,
    name: row.name,
    kind: 'WEBHOOK',
    url: row.url,
    enabled: row.enabled,
    createdAt: row.createdAt.toISOString(),
    lastDeliveredAt: row.lastDeliveredAt?.toISOString() ?? null,
    lastError: row.lastError,
    createdBy: row.createdBy?.name ?? null,
  };
}

function serializeDelivery(row: DeliveryRow): NotificationDeliveryView {
  return {
    id: row.id,
    type: row.type,
    status: row.status,
    attempts: row.attempts,
    channel: row.channel,
    createdAt: row.createdAt.toISOString(),
    deliveredAt: row.deliveredAt?.toISOString() ?? null,
    nextAttemptAt: row.nextAttemptAt.toISOString(),
    lastError: row.lastError,
  };
}

export async function getNotificationSettings(
  ctx: TenantContext,
): Promise<NotificationSettingsView> {
  const [channels, deliveries] = await Promise.all([
    prisma.notificationChannel.findMany({
      where: { organizationId: ctx.organization.id },
      orderBy: { createdAt: 'asc' },
      take: 50,
      select: CHANNEL_SELECT,
    }),
    prisma.notificationEvent.findMany({
      where: { organizationId: ctx.organization.id },
      orderBy: { createdAt: 'desc' },
      take: 25,
      select: DELIVERY_SELECT,
    }),
  ]);

  return {
    channels: channels.map(serializeChannel),
    deliveries: deliveries.map(serializeDelivery),
    scheduling: {
      // Without a shared secret the cron route refuses to run, so the console
      // can tell the operator why nothing is being delivered.
      enabled: Boolean(process.env.CRON_SECRET?.trim()),
      maxAttempts: MAX_DELIVERY_ATTEMPTS,
      allowPrivateDestinations: allowPrivateWebhooks(),
    },
  };
}

/**
 * Registers an alert destination. The URL is validated against the outbound
 * policy before it is stored, and the signing secret is sealed so a database
 * reader cannot forge deliveries.
 */
export async function createNotificationChannel(
  ctx: TenantContext,
  input: CreateNotificationChannelInput,
): Promise<{ channel: NotificationChannelView }> {
  const target = await assertSafeWebhookUrl(input.url);
  const sealed = sealSecret(input.secret);

  try {
    const channel = await prisma.$transaction(async (tx) => {
      const created = await tx.notificationChannel.create({
        data: {
          organizationId: ctx.organization.id,
          name: input.name,
          url: target.toString(),
          secretSealed: sealed,
          createdById: ctx.user.id,
        },
        select: CHANNEL_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.NOTIFICATION_CHANNEL_CREATED,
        outcome: 'SUCCESS',
        targetType: 'notification_channel',
        targetId: created.id,
        summary: `Alert webhook "${created.name}" created`,
        // The host is useful for review; the path and the signing secret are not
        // recorded, so the audit trail cannot be used to replay a delivery.
        metadata: { name: created.name, host: target.host },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return created;
    });

    return { channel: serializeChannel(channel) };
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict('An alert destination with that name already exists.');
    }
    throw error;
  }
}

export async function deleteNotificationChannel(
  ctx: TenantContext,
  channelId: string,
): Promise<{ id: string }> {
  const existing = await prisma.notificationChannel.findFirst({
    where: { id: channelId, organizationId: ctx.organization.id },
    select: { id: true, name: true, url: true },
  });
  if (!existing) {
    throw notFound('Alert destination not found in this organization.');
  }

  await prisma.$transaction(async (tx) => {
    await tx.notificationChannel.delete({ where: { id: existing.id } });
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.NOTIFICATION_CHANNEL_DELETED,
      outcome: 'SUCCESS',
      targetType: 'notification_channel',
      targetId: existing.id,
      summary: `Alert webhook "${existing.name}" deleted`,
      metadata: { name: existing.name, host: safeHost(existing.url) },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });

  return { id: existing.id };
}

function safeHost(raw: string): string | null {
  try {
    return new URL(raw).host;
  } catch {
    return null;
  }
}

/**
 * Queues and immediately attempts one test delivery, so the operator learns
 * whether the endpoint accepts and verifies a signature now instead of when the
 * first real outage happens.
 */
export async function sendTestNotification(
  ctx: TenantContext,
  channelId: string,
): Promise<{ status: 'SENT' | 'PENDING' | 'FAILED'; error: string | null }> {
  const channel = await prisma.notificationChannel.findFirst({
    where: { id: channelId, organizationId: ctx.organization.id },
    select: { id: true, name: true },
  });
  if (!channel) {
    throw notFound('Alert destination not found in this organization.');
  }

  const event = await prisma.notificationEvent.create({
    data: {
      organizationId: ctx.organization.id,
      channelId: channel.id,
      type: 'TEST',
      payload: {
        message: 'CyberNorf test delivery',
        requestedBy: ctx.user.name,
        organizationId: ctx.organization.id,
      },
    },
    select: { id: true },
  });

  const result = await dispatchEventById(event.id);

  // A test that fails is as worth recording as one that succeeds: the operator
  // needs to know an alert path was exercised and what the endpoint answered.
  await recordAuditEvent({
    organizationId: ctx.organization.id,
    actorType: 'USER',
    actorId: ctx.user.id,
    action: AuditActions.NOTIFICATION_TEST_SENT,
    outcome: result.status === 'SENT' ? 'SUCCESS' : 'FAILURE',
    targetType: 'notification_channel',
    targetId: channel.id,
    summary:
      result.status === 'SENT'
        ? `Test alert delivered to "${channel.name}"`
        : `Test alert to "${channel.name}" was not delivered`,
    metadata: { channel: channel.name, status: result.status, error: result.error },
    ipAddress: ctx.meta.ipAddress,
    userAgent: ctx.meta.userAgent,
    requestId: ctx.meta.requestId,
  });

  return { status: result.status, error: result.error };
}

interface DeliveryAttemptResult {
  status: 'SENT' | 'PENDING' | 'FAILED';
  error: string | null;
  /** True when another sweep claimed the attempt first; nothing was sent. */
  skipped?: boolean;
}

function describeError(caught: unknown): string {
  if (caught instanceof AppError) {
    return caught.message.slice(0, ERROR_TEXT_LIMIT);
  }
  if (caught instanceof Error) {
    const message =
      caught.name === 'TimeoutError' ? 'The endpoint did not answer in time.' : caught.message;
    return message.slice(0, ERROR_TEXT_LIMIT);
  }
  return 'Delivery failed.';
}

type EventWithChannel = Prisma.NotificationEventGetPayload<{ include: { channel: true } }>;

/**
 * Performs one delivery attempt and records the outcome.
 *
 * Success marks the event SENT. Failure increments the attempt count and either
 * schedules the next attempt with exponential backoff or, once the budget is
 * spent, marks the event FAILED. The event row stays either way: a failed
 * delivery is operational history the operator needs to see.
 */
async function deliverEvent(
  event: EventWithChannel,
  channel: EventWithChannel['channel'],
): Promise<DeliveryAttemptResult> {
  const attempts = event.attempts + 1;

  if (!channel.enabled) {
    await prisma.notificationEvent.update({
      where: { id: event.id },
      data: { status: 'FAILED', attempts, lastError: 'The destination is disabled.' },
    });
    return { status: 'FAILED', error: 'The destination is disabled.' };
  }

  // Claim the attempt atomically. Two overlapping sweeps (a retried timer, a
  // manual run) then cannot both deliver the same event: the one that loses the
  // compare-and-set sends nothing. attempts doubles as the claim token because
  // it changes on every attempt.
  const claim = await prisma.notificationEvent.updateMany({
    where: { id: event.id, status: 'PENDING', attempts: event.attempts },
    data: { attempts: { increment: 1 } },
  });
  if (claim.count === 0) {
    return { status: 'PENDING', error: null, skipped: true };
  }

  let error: string | null = null;
  try {
    // Re-validated at delivery time, not only at creation: DNS can change
    // between the two, and a stored URL must not bypass the current policy. The
    // addresses resolved here are the ones the transport dials, so the name is
    // never resolved a second time (no DNS-rebinding window).
    const target = await resolveWebhookTarget(channel.url);
    const secret = openSecret(channel.secretSealed);
    const timestamp = String(Math.floor(Date.now() / 1000));
    const body = JSON.stringify({
      id: event.id,
      type: event.type,
      createdAt: event.createdAt.toISOString(),
      organizationId: event.organizationId,
      payload: event.payload,
    });
    const signature = signDelivery(secret, timestamp, body);

    const status = await sendPinnedPost(target.url, target.addresses, {
      headers: {
        'content-type': 'application/json',
        'user-agent': 'CyberNorf-Webhook/1.0',
        'x-cybernorf-event': event.type,
        'x-cybernorf-delivery': event.id,
        'x-cybernorf-timestamp': timestamp,
        'x-cybernorf-signature': `sha256=${signature}`,
      },
      body,
      timeoutMs: DELIVERY_TIMEOUT_MS,
    });

    if (status < 200 || status >= 300) {
      error = `The endpoint answered HTTP ${status}.`;
    }
  } catch (caught) {
    error = describeError(caught);
  }

  if (!error) {
    await prisma.$transaction([
      prisma.notificationEvent.update({
        where: { id: event.id },
        data: {
          status: 'SENT',
          attempts,
          deliveredAt: new Date(),
          lastError: null,
        },
      }),
      prisma.notificationChannel.update({
        where: { id: channel.id },
        data: { lastDeliveredAt: new Date(), lastError: null },
      }),
    ]);
    return { status: 'SENT', error: null };
  }

  const exhausted = attempts >= MAX_DELIVERY_ATTEMPTS;
  await prisma.$transaction([
    prisma.notificationEvent.update({
      where: { id: event.id },
      data: {
        status: exhausted ? 'FAILED' : 'PENDING',
        attempts,
        lastError: error,
        ...(exhausted ? {} : { nextAttemptAt: new Date(Date.now() + deliveryBackoffMs(attempts)) }),
      },
    }),
    prisma.notificationChannel.update({
      where: { id: channel.id },
      data: { lastError: error },
    }),
  ]);

  return { status: exhausted ? 'FAILED' : 'PENDING', error };
}

export async function dispatchEventById(eventId: string): Promise<DeliveryAttemptResult> {
  const event = await prisma.notificationEvent.findUnique({
    where: { id: eventId },
    include: { channel: true },
  });
  if (!event) {
    throw notFound('Notification event not found.');
  }
  return deliverEvent(event, event.channel);
}

export interface DispatchResult {
  attempted: number;
  sent: number;
  retried: number;
  failed: number;
}

/**
 * Delivers everything currently due. Called by the cron sweep and, for a test
 * delivery, directly after queueing. Organization scope is optional because the
 * cron route sweeps every tenant.
 */
export async function dispatchDueNotifications(
  options: { organizationId?: string; limit?: number } = {},
): Promise<DispatchResult> {
  const due = await prisma.notificationEvent.findMany({
    where: {
      ...(options.organizationId ? { organizationId: options.organizationId } : {}),
      status: 'PENDING',
      nextAttemptAt: { lte: new Date() },
      channel: { enabled: true },
    },
    orderBy: { nextAttemptAt: 'asc' },
    take: options.limit ?? DELIVERY_BATCH_SIZE,
    include: { channel: true },
  });

  const result: DispatchResult = { attempted: 0, sent: 0, retried: 0, failed: 0 };
  for (const event of due) {
    const outcome = await deliverEvent(event, event.channel);
    if (outcome.skipped) {
      continue;
    }
    result.attempted += 1;
    if (outcome.status === 'SENT') {
      result.sent += 1;
    } else if (outcome.status === 'PENDING') {
      result.retried += 1;
    } else {
      result.failed += 1;
    }
  }
  return result;
}

export interface HealthSweepResult {
  agentsChecked: number;
  wentOffline: number;
  recovered: number;
  queued: number;
}

interface QueueInput {
  organizationId: string;
  channelIds: readonly string[];
  type: NotificationEventType;
  dedupeKey: string;
  payload: Prisma.InputJsonValue;
}

/**
 * Queues one alert per channel. createMany with skipDuplicates makes repeated
 * sweeps idempotent: the unique (channelId, dedupeKey) pair turns a second
 * attempt for the same outage into a no-op instead of a second page.
 */
async function queueAlerts(input: QueueInput): Promise<number> {
  if (input.channelIds.length === 0) {
    return 0;
  }
  const created = await prisma.notificationEvent.createMany({
    data: input.channelIds.map((channelId) => ({
      organizationId: input.organizationId,
      channelId,
      type: input.type,
      dedupeKey: input.dedupeKey,
      payload: input.payload,
    })),
    skipDuplicates: true,
  });
  return created.count;
}

/**
 * Recomputes heartbeat state for active agents with a configured cadence and
 * queues an alert when one crosses into OFFLINE, or a recovery when it reports
 * again. Runs on the cron sweep; it never delivers by itself.
 */
export async function sweepAgentHealth(
  options: { organizationId?: string; now?: Date } = {},
): Promise<HealthSweepResult> {
  const now = options.now ?? new Date();
  const agents = await prisma.agent.findMany({
    where: {
      status: 'ACTIVE',
      expectedIntervalMinutes: { not: null },
      ...(options.organizationId ? { organizationId: options.organizationId } : {}),
    },
    take: HEALTH_BATCH_SIZE,
    select: {
      id: true,
      organizationId: true,
      name: true,
      source: true,
      lastRunAt: true,
      expectedIntervalMinutes: true,
      offlineNotifiedAt: true,
    },
  });

  const result: HealthSweepResult = {
    agentsChecked: agents.length,
    wentOffline: 0,
    recovered: 0,
    queued: 0,
  };
  if (agents.length === 0) {
    return result;
  }

  const channels = await prisma.notificationChannel.findMany({
    where: {
      organizationId: { in: [...new Set(agents.map((agent) => agent.organizationId))] },
      enabled: true,
    },
    select: { id: true, organizationId: true },
  });
  const channelsByOrg = new Map<string, string[]>();
  for (const channel of channels) {
    const list = channelsByOrg.get(channel.organizationId) ?? [];
    list.push(channel.id);
    channelsByOrg.set(channel.organizationId, list);
  }

  for (const agent of agents) {
    const health: AgentHealth = deriveAgentHealth({
      status: 'ACTIVE',
      lastRunAt: agent.lastRunAt,
      expectedIntervalMinutes: agent.expectedIntervalMinutes,
      now,
    });
    const channelIds = channelsByOrg.get(agent.organizationId) ?? [];
    const payload = {
      agent: {
        id: agent.id,
        name: agent.name,
        source: agent.source,
        lastRunAt: agent.lastRunAt?.toISOString() ?? null,
        expectedIntervalMinutes: agent.expectedIntervalMinutes,
      },
      health,
      observedAt: now.toISOString(),
    };

    if (health === 'OFFLINE' && !agent.offlineNotifiedAt) {
      // No channel means nothing was told; the marker stays clear so the next
      // sweep after a destination is added still raises the alert.
      if (channelIds.length === 0) {
        continue;
      }
      result.queued += await queueAlerts({
        organizationId: agent.organizationId,
        channelIds,
        type: 'AGENT_OFFLINE',
        dedupeKey: offlineDedupeKey(agent.id, agent.lastRunAt),
        payload,
      });
      await prisma.agent.update({
        where: { id: agent.id },
        data: { offlineNotifiedAt: now },
      });
      result.wentOffline += 1;
    } else if ((health === 'ONLINE' || health === 'STALE') && agent.offlineNotifiedAt) {
      // The outage ended before its alert left the outbox: an alert that the
      // host is still down must not be delivered after it is back.
      await prisma.notificationEvent.deleteMany({
        where: {
          organizationId: agent.organizationId,
          channelId: { in: channelIds },
          type: 'AGENT_OFFLINE',
          status: 'PENDING',
          dedupeKey: { startsWith: offlineDedupePrefix(agent.id) },
        },
      });
      result.queued += await queueAlerts({
        organizationId: agent.organizationId,
        channelIds,
        type: 'AGENT_RECOVERED',
        dedupeKey: recoveredDedupeKey(agent.id, agent.lastRunAt),
        payload,
      });
      await prisma.agent.update({
        where: { id: agent.id },
        data: { offlineNotifiedAt: null },
      });
      result.recovered += 1;
    }
  }

  return result;
}
