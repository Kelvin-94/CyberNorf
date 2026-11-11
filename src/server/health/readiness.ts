import { readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Compares the migrations shipped in the image with the ones recorded as
 * applied in the database it is talking to.
 *
 * The production stack runs `prisma migrate deploy` before the app starts, so
 * the two normally agree. When they do not, the app is serving code against a
 * schema it was not built for, and readiness must say so instead of answering
 * 200 and letting a load balancer send traffic to it.
 */

export type MigrationStatus = 'ok' | 'pending' | 'ahead' | 'unknown';

export interface MigrationAssessment {
  status: MigrationStatus;
  /** Migrations applied in the database, excluding rolled-back ones. */
  applied: number;
  /** Migration directories present in the image. */
  expected: number;
}

/** The subset of PrismaClient this module needs, so tests can supply a fake. */
export interface MigrationQueryClient {
  $queryRawUnsafe<T>(query: string): Promise<T>;
}

const MIGRATIONS_DIR = join(process.cwd(), 'prisma', 'migrations');

let cachedMigrations: string[] | null = null;

/**
 * Migration directory names shipped with this build. Read once: the image is
 * immutable, so the answer cannot change while the process runs.
 */
export function expectedMigrations(): string[] {
  if (cachedMigrations) {
    return cachedMigrations;
  }

  try {
    cachedMigrations = readdirSync(MIGRATIONS_DIR, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();
  } catch {
    // A build without the migrations directory cannot judge freshness; that is
    // reported as `unknown` rather than silently treated as up to date.
    cachedMigrations = [];
  }

  return cachedMigrations;
}

/** Only useful in tests that swap the migrations directory. */
export function resetMigrationCache(): void {
  cachedMigrations = null;
}

export async function assessMigrations(client: MigrationQueryClient): Promise<MigrationAssessment> {
  const expected = expectedMigrations();
  if (expected.length === 0) {
    return { status: 'unknown', applied: 0, expected: 0 };
  }

  let appliedNames: string[];
  try {
    // Ask for the table's existence explicitly rather than inferring it from a
    // thrown "relation does not exist" error: Prisma wraps driver errors, so
    // the Postgres error code is not reliably reachable here.
    const presence = await client.$queryRawUnsafe<{ present: string | null }[]>(
      `SELECT to_regclass('public._prisma_migrations')::text AS present`,
    );
    if (!presence[0]?.present) {
      return { status: 'pending', applied: 0, expected: expected.length };
    }

    const rows = await client.$queryRawUnsafe<{ migration_name: string }[]>(
      `SELECT migration_name FROM "_prisma_migrations"
        WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL`,
    );
    appliedNames = rows.map((row) => row.migration_name);
  } catch {
    // A connection, permission or query failure is not a verdict about the
    // schema; the database check already reports reachability separately.
    return { status: 'unknown', applied: 0, expected: expected.length };
  }

  const appliedSet = new Set(appliedNames);
  const pending = expected.filter((name) => !appliedSet.has(name));
  if (pending.length > 0) {
    return { status: 'pending', applied: appliedSet.size, expected: expected.length };
  }

  // The database has migrations this build does not ship, which is what a
  // rollback to an older image looks like. Forward-only migrations are
  // additive, so the app can still serve; this is reported without failing
  // readiness, because refusing traffic would turn a rollback into an outage.
  const known = new Set(expected);
  const ahead = appliedNames.some((name) => !known.has(name));
  if (ahead) {
    return { status: 'ahead', applied: appliedSet.size, expected: expected.length };
  }

  return { status: 'ok', applied: appliedSet.size, expected: expected.length };
}
