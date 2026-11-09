import { timingSafeEqual } from 'node:crypto';

/**
 * Scheduler authentication.
 *
 * The alert sweep runs from an external scheduler (cron, a systemd timer, or a
 * platform job) because the platform ships no background worker. That caller has
 * no user session, so it presents a shared secret in an Authorization header.
 *
 * The endpoint fails closed: with no CRON_SECRET configured it answers 503 and
 * never runs the sweep, so a deployment that forgot the variable cannot be
 * triggered by anyone who notices the route. The comparison is constant time so
 * the response time does not leak the secret one byte at a time.
 */

/** Secrets shorter than this are rejected: they are a password guess away. */
const MIN_SECRET_LENGTH = 24;

export type CronAuthResult = { ok: true } | { ok: false; status: 401 | 503; message: string };

export function authorizeCronRequest(request: Request): CronAuthResult {
  const configured = process.env.CRON_SECRET?.trim() ?? '';
  if (configured.length < MIN_SECRET_LENGTH) {
    return {
      ok: false,
      status: 503,
      message: `Scheduled delivery is not configured. Set CRON_SECRET to at least ${MIN_SECRET_LENGTH} characters.`,
    };
  }

  const header = request.headers.get('authorization')?.trim() ?? '';
  const match = /^bearer\s+(.+)$/i.exec(header);
  const provided = match?.[1]?.trim() ?? '';
  if (provided.length === 0) {
    return { ok: false, status: 401, message: 'A Bearer token is required.' };
  }

  const expectedBytes = Buffer.from(configured, 'utf8');
  const providedBytes = Buffer.from(provided, 'utf8');
  if (
    providedBytes.length !== expectedBytes.length ||
    !timingSafeEqual(providedBytes, expectedBytes)
  ) {
    return { ok: false, status: 401, message: 'The scheduler token is not valid.' };
  }

  return { ok: true };
}
