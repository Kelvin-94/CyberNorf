/**
 * Runs once when the Next.js server starts. Configuration problems that would
 * silently weaken a deployment (plain-http origin, remote database without
 * TLS) fail here instead of at the first sign-in attempt.
 */
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== 'nodejs') {
    return;
  }

  const { assertSecureTransport } = await import('@/server/config');
  assertSecureTransport();
}
