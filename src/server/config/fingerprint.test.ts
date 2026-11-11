import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fingerprintConfiguration } from './fingerprint';

const BASE: NodeJS.ProcessEnv = {
  NODE_ENV: 'production',
  DATABASE_URL: 'postgresql://user:password@db.internal:5432/cybernorf',
  BETTER_AUTH_SECRET: 'a'.repeat(40),
  WEBHOOK_ALLOW_PRIVATE_ADDRESSES: 'false',
};

test('the same effective configuration produces the same digest', () => {
  assert.equal(fingerprintConfiguration(BASE), fingerprintConfiguration({ ...BASE }));
});

test('a changed value or a removed variable changes the digest', () => {
  const baseline = fingerprintConfiguration(BASE);

  assert.notEqual(baseline, fingerprintConfiguration({ ...BASE, NODE_ENV: 'development' }));
  assert.notEqual(
    baseline,
    fingerprintConfiguration({ ...BASE, WEBHOOK_ALLOW_PRIVATE_ADDRESSES: 'true' }),
  );

  const withoutDatabaseUrl = { ...BASE };
  delete withoutDatabaseUrl.DATABASE_URL;
  assert.notEqual(baseline, fingerprintConfiguration(withoutDatabaseUrl));
});

test('variables that change every start do not change the digest', () => {
  const baseline = fingerprintConfiguration(BASE);
  assert.equal(
    baseline,
    fingerprintConfiguration({
      ...BASE,
      HOSTNAME: 'container-7f9c2a',
      PWD: '/app',
      SHLVL: '2',
      npm_lifecycle_event: 'start',
      NEXT_RUNTIME: 'nodejs',
    }),
    'a restart must not look like a configuration change',
  );
});

test('the digest is keyed, so it cannot be used to guess a value without the secret', () => {
  const keyed = fingerprintConfiguration(BASE);
  const otherKey = fingerprintConfiguration({ ...BASE, BETTER_AUTH_SECRET: 'b'.repeat(40) });
  const unkeyed = fingerprintConfiguration({ ...BASE, BETTER_AUTH_SECRET: undefined });

  assert.notEqual(keyed, otherKey);
  assert.notEqual(keyed, unkeyed);
  assert.match(keyed, /^[0-9a-f]{64}$/);
  assert.equal(keyed.includes('password'), false);
});
