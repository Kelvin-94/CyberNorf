import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  AUDIT_ACTION_MAX_LENGTH,
  auditQuerySchema,
  isAuditAction,
} from '@/server/validation/audit';

test('audit action filters accept identifier-shaped values', () => {
  const accepted = ['a', 'user.login', 'agent.run.succeeded', 'user.login_failed', 'a_b.c_d'];

  for (const action of accepted) {
    assert.equal(isAuditAction(action), true, `expected "${action}" to be accepted`);
    assert.equal(auditQuerySchema.parse({ action }).action, action);
  }
});

test('audit action filters reject values outside the identifier form', () => {
  const rejected = ['', ' ', 'User.Login', '1user.login', 'a.', '.a', 'a..b', 'a b', 'a-b', 'a!'];

  for (const action of rejected) {
    assert.equal(isAuditAction(action), false, `expected "${action}" to be rejected`);
    assert.equal(
      auditQuerySchema.safeParse({ action }).success,
      false,
      `schema accepted "${action}"`,
    );
  }
});

test('adversarial action filters are rejected in linear time', () => {
  // A separator followed by a long underscore run is the shape that made the
  // previous single-expression check backtrack over every way to split the run.
  // It must now be rejected without stalling the request thread.
  const adversarial = `a.${'_'.repeat(4000)}`;
  const startedAt = process.hrtime.bigint();
  assert.equal(auditQuerySchema.safeParse({ action: adversarial }).success, false);
  const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
  assert.ok(elapsedMs < 250, `validation of an oversized filter took ${elapsedMs.toFixed(1)}ms`);

  // The same shape inside the accepted length is the case a length cap alone
  // cannot stop, so it exercises the scan itself.
  const withinLimit = `a.${'_'.repeat(AUDIT_ACTION_MAX_LENGTH - 2)}`;
  assert.equal(withinLimit.length, AUDIT_ACTION_MAX_LENGTH);
  const boundedStart = process.hrtime.bigint();
  assert.equal(auditQuerySchema.safeParse({ action: withinLimit }).success, false);
  const boundedMs = Number(process.hrtime.bigint() - boundedStart) / 1e6;
  assert.ok(
    boundedMs < 250,
    `validation of a ${withinLimit.length}-character filter took ${boundedMs.toFixed(1)}ms`,
  );
});
