import { prisma } from '@/lib/prisma';
import { assessMigrations } from '@/server/health/readiness';
import { getRequestMeta } from '@/server/http/request-meta';

/**
 * Readiness probe. Unlike /api/health (process liveness) this verifies what the
 * process needs in order to serve correctly: a reachable database and a schema
 * that matches the migrations shipped in this build.
 *
 * A load balancer can drain an instance that answers 503. No internal detail —
 * no error text, no migration names — is returned to the caller, because the
 * endpoint is unauthenticated.
 */
export async function GET(request: Request): Promise<Response> {
  const meta = getRequestMeta(request);

  const databaseReady = await prisma.$queryRaw`SELECT 1`.then(() => true).catch(() => false);

  // Only ask about migrations when the database answers; otherwise the
  // migration probe would report a connection failure as a schema problem.
  const migrations = databaseReady
    ? await assessMigrations(prisma)
    : { status: 'unknown' as const, applied: 0, expected: 0 };

  // `ahead` means the database is newer than this build, which is what a
  // rollback looks like; it is reported but does not fail readiness.
  const ready = databaseReady && migrations.status !== 'pending';

  return Response.json(
    {
      status: ready ? 'ready' : 'unavailable',
      checks: {
        database: databaseReady ? 'ok' : 'failed',
        migrations: migrations.status,
      },
      migrations: { applied: migrations.applied, expected: migrations.expected },
    },
    {
      status: ready ? 200 : 503,
      headers: {
        'Cache-Control': 'no-store',
        'X-Request-Id': meta.requestId,
      },
    },
  );
}
