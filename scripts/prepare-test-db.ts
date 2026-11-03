import { spawnSync } from 'node:child_process';

/**
 * Applies migrations to the test database. It refuses to run unless
 * DATABASE_URL names a test database, so `npm run test:db:prepare` can never
 * migrate the development or production database by accident.
 */
const databaseUrl = process.env.DATABASE_URL ?? '';
const databaseName = databaseUrl.split('?')[0]?.split('/').pop() ?? '';

if (!/test/i.test(databaseName)) {
  console.error(
    `Refusing to migrate: DATABASE_URL points at "${databaseName || '(unset)'}" instead of a test database.`,
  );
  console.error('Set DATABASE_URL via .env.test (see .env.example) before running this command.');
  process.exit(1);
}

const result = spawnSync('npx', ['prisma', 'migrate', 'deploy'], {
  stdio: 'inherit',
  env: process.env,
});

process.exit(result.status ?? 1);
