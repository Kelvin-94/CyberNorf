import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { before, test } from 'node:test';
import { consumeRateLimit, enforceRateLimit } from '@/server/security/rate-limit';
import { assertTestDatabase, expectAppError, resetDatabase } from './helpers/database.ts';

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

function uniqueKey(): string {
  return `test:${randomUUID()}`;
}

test('the limiter allows exactly the configured number of requests', async () => {
  const key = uniqueKey();

  const first = await consumeRateLimit(key, 3, 60);
  assert.equal(first.allowed, true);
  assert.equal(first.remaining, 2);

  const second = await consumeRateLimit(key, 3, 60);
  assert.equal(second.allowed, true);
  assert.equal(second.remaining, 1);

  const third = await consumeRateLimit(key, 3, 60);
  assert.equal(third.allowed, true);
  assert.equal(third.remaining, 0);

  const fourth = await consumeRateLimit(key, 3, 60);
  assert.equal(fourth.allowed, false);
  assert.equal(fourth.remaining, 0);
  assert.ok(fourth.retryAfterSeconds >= 1);
});

test('enforceRateLimit raises a 429 with a retry hint once the budget is spent', async () => {
  const key = uniqueKey();
  await enforceRateLimit(key, 1, 60);
  await enforceRateLimit(key, 1, 60).catch(() => undefined);

  try {
    await enforceRateLimit(key, 1, 60);
    throw new Error('Expected the third request to be limited.');
  } catch (error) {
    assert.equal((error as { code?: string }).code, 'RATE_LIMITED');
    assert.equal((error as { statusCode?: number }).statusCode, 429);
    const retryAfter = (error as { headers?: Record<string, string> }).headers?.['Retry-After'];
    assert.ok(retryAfter && Number(retryAfter) >= 1);
  }
});

test('separate keys have independent budgets', async () => {
  const firstKey = uniqueKey();
  const secondKey = uniqueKey();

  await enforceRateLimit(firstKey, 1, 60);
  await expectAppError(enforceRateLimit(firstKey, 1, 60), { statusCode: 429, code: 'RATE_LIMITED' });
  await enforceRateLimit(secondKey, 1, 60);
});

test('the window resets after it expires', async () => {
  const key = uniqueKey();
  await enforceRateLimit(key, 1, 1);
  await expectAppError(enforceRateLimit(key, 1, 1), { statusCode: 429 });

  await delay(1100);

  const afterReset = await consumeRateLimit(key, 1, 1);
  assert.equal(afterReset.allowed, true);
  assert.equal(afterReset.remaining, 0);
});
