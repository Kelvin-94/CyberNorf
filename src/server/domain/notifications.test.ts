import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  MAX_DELIVERY_ATTEMPTS,
  deliveryBackoffMs,
  deriveAgentHealth,
  offlineDedupeKey,
  recoveredDedupeKey,
  signDelivery,
  verifyDelivery,
} from './notifications';

const NOW = new Date('2026-11-09T12:00:00.000Z');
const MINUTE = 60_000;

function ageMinutes(minutes: number): Date {
  return new Date(NOW.getTime() - minutes * MINUTE);
}

test('a healthy agent is ONLINE within its interval', () => {
  assert.equal(
    deriveAgentHealth({
      status: 'ACTIVE',
      lastRunAt: ageMinutes(30),
      expectedIntervalMinutes: 60,
      now: NOW,
    }),
    'ONLINE',
  );
});

test('one missed interval is STALE, a second is OFFLINE', () => {
  const stale = deriveAgentHealth({
    status: 'ACTIVE',
    lastRunAt: ageMinutes(61),
    expectedIntervalMinutes: 60,
    now: NOW,
  });
  const offline = deriveAgentHealth({
    status: 'ACTIVE',
    lastRunAt: ageMinutes(121),
    expectedIntervalMinutes: 60,
    now: NOW,
  });
  assert.equal(stale, 'STALE');
  assert.equal(offline, 'OFFLINE');
});

test('the interval boundary itself is still ONLINE', () => {
  assert.equal(
    deriveAgentHealth({
      status: 'ACTIVE',
      lastRunAt: ageMinutes(60),
      expectedIntervalMinutes: 60,
      now: NOW,
    }),
    'ONLINE',
  );
});

test('an agent that never ran is OFFLINE once an interval is expected', () => {
  assert.equal(
    deriveAgentHealth({
      status: 'ACTIVE',
      lastRunAt: null,
      expectedIntervalMinutes: 15,
      now: NOW,
    }),
    'OFFLINE',
  );
});

test('agents outside ACTIVE or without an interval are UNKNOWN', () => {
  const base = { lastRunAt: ageMinutes(600), expectedIntervalMinutes: 60, now: NOW };
  assert.equal(deriveAgentHealth({ ...base, status: 'SUSPENDED' }), 'UNKNOWN');
  assert.equal(deriveAgentHealth({ ...base, status: 'PENDING_APPROVAL' }), 'UNKNOWN');
  assert.equal(deriveAgentHealth({ ...base, status: 'REVOKED' }), 'UNKNOWN');
  assert.equal(
    deriveAgentHealth({ ...base, status: 'ACTIVE', expectedIntervalMinutes: null }),
    'UNKNOWN',
  );
});

test('backoff grows with each attempt and stops growing at the last step', () => {
  const delays = Array.from({ length: MAX_DELIVERY_ATTEMPTS }, (_, index) =>
    deliveryBackoffMs(index + 1),
  );
  for (let index = 1; index < delays.length; index += 1) {
    assert.ok(
      (delays[index] ?? 0) >= (delays[index - 1] ?? 0),
      `attempt ${index + 1} must not wait less than attempt ${index}`,
    );
  }
  assert.equal(delays[0], 60_000);
  assert.equal(deliveryBackoffMs(MAX_DELIVERY_ATTEMPTS + 10), delays[delays.length - 1]);
});

test('a delivery signature verifies only with the same secret, timestamp and body', () => {
  const secret = 'a'.repeat(40);
  const timestamp = '1762690000';
  const body = JSON.stringify({ type: 'TEST' });
  const signature = signDelivery(secret, timestamp, body);

  assert.equal(verifyDelivery(secret, timestamp, body, signature), true);
  assert.equal(verifyDelivery('b'.repeat(40), timestamp, body, signature), false);
  assert.equal(verifyDelivery(secret, '1762690001', body, signature), false);
  assert.equal(verifyDelivery(secret, timestamp, `${body} `, signature), false);
  assert.equal(verifyDelivery(secret, timestamp, body, ''), false);
  assert.equal(verifyDelivery(secret, timestamp, body, signature.slice(0, 20)), false);
});

test('dedupe keys are stable for one outage and distinct across outages', () => {
  const first = new Date('2026-11-09T10:00:00.000Z');
  const second = new Date('2026-11-09T11:00:00.000Z');
  assert.equal(offlineDedupeKey('agt_1', first), offlineDedupeKey('agt_1', first));
  assert.notEqual(offlineDedupeKey('agt_1', first), offlineDedupeKey('agt_1', second));
  assert.notEqual(offlineDedupeKey('agt_1', first), offlineDedupeKey('agt_2', first));
  assert.equal(offlineDedupeKey('agt_1', null), 'agent_offline:agt_1:never');
  assert.notEqual(recoveredDedupeKey('agt_1', first), offlineDedupeKey('agt_1', first));
});
