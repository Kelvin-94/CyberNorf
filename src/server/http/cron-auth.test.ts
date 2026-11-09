import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import { authorizeCronRequest } from './cron-auth';

const SECRET = 'scheduler-secret-value-1234567890';

function cronRequest(authorization?: string): Request {
  return new Request('http://localhost:3000/api/cron/notifications', {
    headers: authorization ? { authorization } : {},
  });
}

beforeEach(() => {
  process.env.CRON_SECRET = SECRET;
});

test('an unset secret fails closed with 503', () => {
  delete process.env.CRON_SECRET;
  const result = authorizeCronRequest(cronRequest(`Bearer ${SECRET}`));
  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.status, 503);
});

test('a secret too short to be safe fails closed with 503', () => {
  process.env.CRON_SECRET = 'short';
  const result = authorizeCronRequest(cronRequest('Bearer short'));
  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.status, 503);
});

test('a missing or wrong bearer token is rejected with 401', () => {
  const missing = authorizeCronRequest(cronRequest());
  assert.equal(missing.ok === false && missing.status, 401);

  const wrong = authorizeCronRequest(cronRequest('Bearer not-the-secret'));
  assert.equal(wrong.ok === false && wrong.status, 401);

  const wrongScheme = authorizeCronRequest(cronRequest(`Basic ${SECRET}`));
  assert.equal(wrongScheme.ok === false && wrongScheme.status, 401);
});

test('the configured token is accepted regardless of scheme case or padding', () => {
  assert.equal(authorizeCronRequest(cronRequest(`Bearer ${SECRET}`)).ok, true);
  assert.equal(authorizeCronRequest(cronRequest(`bearer   ${SECRET}  `)).ok, true);
  assert.equal(authorizeCronRequest(cronRequest(`BEARER ${SECRET}`)).ok, true);
});
