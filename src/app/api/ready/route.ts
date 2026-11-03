import { prisma } from '@/lib/prisma';
import { getRequestMeta } from '@/server/http/request-meta';

/**
 * Readiness probe. Unlike /api/health (process liveness) this verifies the
 * database is reachable, so a load balancer can drain an instance that cannot
 * serve requests. No internal detail is returned to the caller.
 */
export async function GET(request: Request): Promise<Response> {
  const meta = getRequestMeta(request);

  const databaseReady = await prisma.$queryRaw`SELECT 1`.then(() => true).catch(() => false);

  return Response.json(
    {
      status: databaseReady ? 'ready' : 'unavailable',
      checks: { database: databaseReady ? 'ok' : 'failed' },
    },
    {
      status: databaseReady ? 200 : 503,
      headers: {
        'Cache-Control': 'no-store',
        'X-Request-Id': meta.requestId,
      },
    },
  );
}
