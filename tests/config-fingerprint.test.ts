import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { fingerprintConfiguration, recordConfigurationFingerprint } from '@/server/config/fingerprint';
import { assertTestDatabase, prisma } from './helpers/database.ts';

/**
 * The record exists so an operator can tell, after the fact, whether a restart
 * changed the configuration. These assertions cover the three states a restart
 * can observe and the promise that no value is written down.
 */

assertTestDatabase();

test('a changed configuration is recorded as CHANGED, not silently accepted', async () => {
  const key = `config.fingerprint.test-${randomUUID()}`;
  const secret = 's'.repeat(40);
  const baseline: NodeJS.ProcessEnv = {
    BETTER_AUTH_SECRET: secret,
    NODE_ENV: 'production',
    DATABASE_URL: 'postgresql://db/app',
  };

  try {
    const first = await recordConfigurationFingerprint(fingerprintConfiguration(baseline), { key });
    assert.equal(first.status, 'NEW');
    assert.equal(first.changed, false);
    assert.match(first.digest, /^[0-9a-f]{12}$/);

    const same = await recordConfigurationFingerprint(fingerprintConfiguration({ ...baseline }), {
      key,
    });
    assert.equal(same.status, 'UNCHANGED');
    assert.equal(same.digest, first.digest);

    const rotated = await recordConfigurationFingerprint(
      fingerprintConfiguration({ ...baseline, DATABASE_URL: 'postgresql://db/other' }),
      { key },
    );
    assert.equal(rotated.status, 'CHANGED');
    assert.equal(rotated.changed, true);
    assert.notEqual(rotated.digest, first.digest);

    const row = await prisma.systemSetting.findUniqueOrThrow({ where: { key } });
    const stored = JSON.stringify(row.value);
    assert.equal(stored.includes('postgresql://db/other'), false, 'no value is stored');
    assert.equal(stored.includes(secret), false, 'no secret is stored');
    assert.ok(stored.includes(rotated.digest), 'the digest is what makes a change visible');
  } finally {
    await prisma.systemSetting.deleteMany({ where: { key } });
  }
});
