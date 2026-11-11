import assert from 'node:assert/strict';
import { test } from 'node:test';
import { expectedMigrations } from '@/server/health/readiness';
import { GET } from './route.ts';

test('GET /api/ready reports the database and migration state', async () => {
  const response = await GET(new Request('http://localhost/api/ready'));

  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.ok(response.headers.get('X-Request-Id'));

  const body = (await response.json()) as {
    status: string;
    checks: { database: string; migrations: string };
    migrations: { applied: number; expected: number };
  };

  // The test database is prepared with `prisma migrate deploy`, so it must be
  // current; a failure here means the schema and the code have drifted.
  assert.equal(body.status, 'ready');
  assert.deepEqual(body.checks, { database: 'ok', migrations: 'ok' });
  assert.equal(body.migrations.expected, expectedMigrations().length);
  assert.equal(body.migrations.applied, body.migrations.expected);
});

test('GET /api/ready returns no error text or migration names', async () => {
  const response = await GET(new Request('http://localhost/api/ready'));
  const body = JSON.stringify(await response.json());

  assert.ok(!body.includes('prisma'), 'response mentions the ORM');
  assert.ok(!/_\d{14}_|migration_/.test(body), 'response leaks migration names');
});
