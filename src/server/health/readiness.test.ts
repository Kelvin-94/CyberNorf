import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  assessMigrations,
  expectedMigrations,
  resetMigrationCache,
  type MigrationQueryClient,
} from './readiness.ts';

function clientReturning(names: string[]): MigrationQueryClient {
  return {
    async $queryRawUnsafe<T>(query: string): Promise<T> {
      if (query.includes('to_regclass')) {
        return [{ present: 'public._prisma_migrations' }] as T;
      }
      return names.map((migration_name) => ({ migration_name })) as T;
    },
  };
}

/** A database where the migrations table has never been created. */
function unmigratedClient(): MigrationQueryClient {
  return {
    async $queryRawUnsafe<T>(): Promise<T> {
      return [{ present: null }] as T;
    },
  };
}

function clientFailing(): MigrationQueryClient {
  return {
    async $queryRawUnsafe<T>(): Promise<T> {
      throw new Error('probe failed');
    },
  };
}

test('the repository ships migrations to compare against', () => {
  resetMigrationCache();
  const migrations = expectedMigrations();

  assert.ok(migrations.length > 0, 'no migration directories were found');
  assert.ok(
    migrations.every((name) => /^\d{14}_/.test(name)),
    'migration directory names must keep the Prisma timestamp prefix',
  );
});

test('every shipped migration applied is ok', async () => {
  const expected = expectedMigrations();
  const assessment = await assessMigrations(clientReturning(expected));

  assert.deepEqual(assessment, {
    status: 'ok',
    applied: expected.length,
    expected: expected.length,
  });
});

test('a shipped migration missing from the database is pending', async () => {
  const expected = expectedMigrations();
  const applied = expected.slice(0, -1);
  const assessment = await assessMigrations(clientReturning(applied));

  assert.equal(assessment.status, 'pending');
  assert.equal(assessment.applied, applied.length);
  assert.equal(assessment.expected, expected.length);
});

test('a database that was never migrated is pending, not unknown', async () => {
  const assessment = await assessMigrations(unmigratedClient());

  assert.equal(assessment.status, 'pending');
  assert.equal(assessment.applied, 0);
  assert.ok(assessment.expected > 0);
});

test('a database newer than this build is reported ahead, not pending', async () => {
  const expected = expectedMigrations();
  const assessment = await assessMigrations(
    clientReturning([...expected, '20990101000000_from_the_future']),
  );

  assert.equal(assessment.status, 'ahead');
  assert.equal(assessment.applied, expected.length + 1);
});

test('a connection or permission failure is unknown rather than a verdict', async () => {
  const assessment = await assessMigrations(clientFailing());

  assert.equal(assessment.status, 'unknown');
});
