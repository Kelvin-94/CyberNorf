import { authorizeCronRequest } from '@/server/http/cron-auth';
import { enforceRetentionSchedules } from '@/server/services/retention';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

function noStore(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      'Cache-Control': 'no-store, max-age=0',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

/**
 * Applies every configured tenant retention policy once.
 *
 * Only organizations that saved a policy are touched, and each tenant is purged
 * in its own transaction with a SYSTEM audit entry. A failure in one tenant is
 * reported but does not stop the sweep for the others; the route answers 500 in
 * that case so the timer's failure shows up instead of looking like success.
 */
async function sweep(request: Request): Promise<Response> {
  const auth = authorizeCronRequest(request);
  if (!auth.ok) {
    return noStore({ error: auth.message }, auth.status);
  }

  const result = await enforceRetentionSchedules();
  return noStore(
    { ...result, sweptAt: new Date().toISOString() },
    result.errors.length === 0 ? 200 : 500,
  );
}

export function GET(request: Request): Promise<Response> {
  return sweep(request);
}

export function POST(request: Request): Promise<Response> {
  return sweep(request);
}
