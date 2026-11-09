import { authorizeCronRequest } from '@/server/http/cron-auth';
import { dispatchDueNotifications, sweepAgentHealth } from '@/server/services/notifications';

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
 * One scheduled pass over every organization: mark agents that stopped
 * reporting, queue the alerts that state implies, then deliver everything due.
 *
 * Sweeping and delivering in one pass keeps the deployment to a single timer.
 * Both halves are idempotent, so an overlapping or retried invocation cannot
 * page the same outage twice: heartbeat alerts are deduplicated per channel and
 * a delivery attempt claims nothing it does not see as still pending.
 */
async function sweep(request: Request): Promise<Response> {
  const auth = authorizeCronRequest(request);
  if (!auth.ok) {
    return noStore({ error: auth.message }, auth.status);
  }

  const health = await sweepAgentHealth();
  const deliveries = await dispatchDueNotifications();
  return noStore({ health, deliveries, sweptAt: new Date().toISOString() });
}

export function GET(request: Request): Promise<Response> {
  return sweep(request);
}

export function POST(request: Request): Promise<Response> {
  return sweep(request);
}
