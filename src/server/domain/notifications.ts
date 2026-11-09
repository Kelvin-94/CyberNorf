import { createHmac, timingSafeEqual } from 'node:crypto';

export const NOTIFICATION_EVENT_TYPES = ['AGENT_OFFLINE', 'AGENT_RECOVERED', 'TEST'] as const;
export type NotificationEventType = (typeof NOTIFICATION_EVENT_TYPES)[number];

/** Retry budget per delivery, after which the event is terminally FAILED. */
export const MAX_DELIVERY_ATTEMPTS = 5;

/** Backoff between attempts: 1m, 5m, 15m, 1h, 4h. */
const BACKOFF_MS: readonly number[] = [60_000, 300_000, 900_000, 3_600_000, 14_400_000];

/**
 * Delay before the next attempt. `attempt` is the number of attempts already
 * made, so the first retry uses the first (shortest) delay. Values beyond the
 * schedule keep the longest delay instead of growing without bound.
 */
export function deliveryBackoffMs(attempt: number): number {
  const index = Math.min(Math.max(attempt - 1, 0), BACKOFF_MS.length - 1);
  return BACKOFF_MS[index] ?? BACKOFF_MS[BACKOFF_MS.length - 1]!;
}

/**
 * Signature over `timestamp.body`, hex encoded. Signing the timestamp as well as
 * the body lets the receiver reject replayed deliveries by checking how old the
 * header is, instead of accepting any body it has ever seen.
 */
export function signDelivery(secret: string, timestamp: string, body: string): string {
  return createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
}

/** Constant-time verification, for receivers and for our own tests. */
export function verifyDelivery(
  secret: string,
  timestamp: string,
  body: string,
  signature: string,
): boolean {
  const expected = Buffer.from(signDelivery(secret, timestamp, body), 'hex');
  const received = Buffer.from(signature, 'hex');
  if (expected.length !== received.length || expected.length === 0) {
    return false;
  }
  return timingSafeEqual(expected, received);
}

export const AGENT_HEALTH_STATES = ['ONLINE', 'STALE', 'OFFLINE', 'UNKNOWN'] as const;
export type AgentHealth = (typeof AGENT_HEALTH_STATES)[number];

export interface AgentHealthInput {
  status: 'PENDING_APPROVAL' | 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
  lastRunAt: Date | null;
  expectedIntervalMinutes: number | null;
  now?: Date;
}

/**
 * Heartbeat state for one agent.
 *
 * - A suspended, revoked, or pending agent has no cadence expectation: UNKNOWN.
 * - An agent with no configured interval cannot be judged late: UNKNOWN.
 * - An active agent that never reported is OFFLINE, because the operator
 *   configured an interval and nothing has ever arrived.
 * - Within one interval is ONLINE, a missed interval is STALE, and a missed
 *   second interval is OFFLINE. Alerting on OFFLINE (not STALE) keeps a single
 *   late run from paging someone.
 */
export function deriveAgentHealth(input: AgentHealthInput): AgentHealth {
  const interval = input.expectedIntervalMinutes;
  if (input.status !== 'ACTIVE' || !interval || interval <= 0) {
    return 'UNKNOWN';
  }

  const now = input.now ?? new Date();
  if (!input.lastRunAt) {
    return 'OFFLINE';
  }

  const ageMs = now.getTime() - input.lastRunAt.getTime();
  const intervalMs = interval * 60_000;
  if (ageMs <= intervalMs) {
    return 'ONLINE';
  }
  if (ageMs <= intervalMs * 2) {
    return 'STALE';
  }
  return 'OFFLINE';
}

/** Stable key so one outage queues one alert per channel, however often we sweep. */
export function offlineDedupeKey(agentId: string, lastRunAt: Date | null): string {
  return `${offlineDedupePrefix(agentId)}${lastRunAt ? lastRunAt.toISOString() : 'never'}`;
}

/**
 * Prefix shared by every outage alert of one agent. A recovery uses it to drop
 * an outage alert that was queued but not yet delivered, so a host that comes
 * back before the next sweep does not page anyone after the fact.
 */
export function offlineDedupePrefix(agentId: string): string {
  return `agent_offline:${agentId}:`;
}

/** Stable key for the recovery that closes one specific outage. */
export function recoveredDedupeKey(agentId: string, lastRunAt: Date | null): string {
  return `agent_recovered:${agentId}:${lastRunAt ? lastRunAt.toISOString() : 'unknown'}`;
}
