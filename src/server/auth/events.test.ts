import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AuthEventActions, describeAuthActivity } from './events';

test('a password sign-in counts only once a session exists', () => {
  assert.deepEqual(
    describeAuthActivity({ path: '/sign-in/email', failed: false, newSession: true }),
    {
      action: AuthEventActions.SIGNED_IN,
      outcome: 'SUCCESS',
      metadata: { method: 'password' },
    },
  );

  // A correct password that stops at the second-factor challenge is not a
  // sign-in, so the endpoint returning 200 must not produce a success event.
  assert.equal(
    describeAuthActivity({ path: '/sign-in/email', failed: false, newSession: false }),
    null,
  );
});

test('a rejected password records the method and the provider error code', () => {
  assert.deepEqual(
    describeAuthActivity({
      path: '/sign-in/email',
      failed: true,
      errorCode: 'INVALID_EMAIL_OR_PASSWORD',
    }),
    {
      action: AuthEventActions.SIGN_IN_FAILED,
      outcome: 'FAILURE',
      metadata: { method: 'password', code: 'INVALID_EMAIL_OR_PASSWORD' },
    },
  );
});

test('single sign-on callbacks are recorded as the identifier provider method', () => {
  assert.deepEqual(
    describeAuthActivity({ path: '/callback/acme', failed: false, newSession: true }),
    {
      action: AuthEventActions.SIGNED_IN,
      outcome: 'SUCCESS',
      metadata: { method: 'oidc' },
    },
  );
  assert.deepEqual(describeAuthActivity({ path: '/oauth2/callback/acme', failed: true }), {
    action: AuthEventActions.SIGN_IN_FAILED,
    outcome: 'FAILURE',
    metadata: { method: 'oidc' },
  });
  // Starting the flow is not a sign-in.
  assert.equal(describeAuthActivity({ path: '/sign-in/social', failed: false }), null);
});

test('second-factor verification distinguishes TOTP from a backup code', () => {
  assert.deepEqual(
    describeAuthActivity({ path: '/two-factor/verify-totp', failed: false, newSession: true }),
    {
      action: AuthEventActions.SECOND_FACTOR_SUCCEEDED,
      outcome: 'SUCCESS',
      metadata: { method: 'totp' },
    },
  );
  assert.deepEqual(
    describeAuthActivity({ path: '/two-factor/verify-backup-code', failed: false }),
    {
      action: AuthEventActions.SECOND_FACTOR_SUCCEEDED,
      outcome: 'SUCCESS',
      metadata: { method: 'backup_code' },
    },
  );
  assert.deepEqual(describeAuthActivity({ path: '/two-factor/verify-totp', failed: true }), {
    action: AuthEventActions.SECOND_FACTOR_FAILED,
    outcome: 'FAILURE',
    metadata: { method: 'totp' },
  });
});

test('disabling two-factor authentication is its own event', () => {
  assert.deepEqual(describeAuthActivity({ path: '/two-factor/disable', failed: false }), {
    action: AuthEventActions.TWO_FACTOR_DISABLED,
    outcome: 'SUCCESS',
    metadata: {},
  });
  assert.equal(describeAuthActivity({ path: '/two-factor/enable', failed: false }), null);
  // A refused disable changes no state and is not a rejected second factor.
  assert.equal(describeAuthActivity({ path: '/two-factor/disable', failed: true }), null);
});

test('the first session of a new account is recorded as a sign-up sign-in', () => {
  assert.deepEqual(
    describeAuthActivity({ path: '/sign-up/email', failed: false, newSession: true }),
    {
      action: AuthEventActions.SIGNED_IN,
      outcome: 'SUCCESS',
      metadata: { method: 'password', via: 'sign_up' },
    },
  );
  // A rejected sign-up is a validation problem, not an authentication failure.
  assert.equal(describeAuthActivity({ path: '/sign-up/email', failed: true }), null);
});

test('unrelated identity endpoints are not recorded', () => {
  for (const path of ['/get-session', '/change-password', '/', '']) {
    assert.equal(describeAuthActivity({ path, failed: false, newSession: true }), null, path);
  }
});
