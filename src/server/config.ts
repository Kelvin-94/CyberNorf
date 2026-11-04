const DEVELOPMENT_SECRET = 'cybernorf-development-only-secret-do-not-use-outside-local-development';

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.trim().length === 0) {
    throw new Error(`${name} must be configured before this feature can be used.`);
  }
  return value;
}

export function getDatabaseUrl(): string {
  return requireEnv('DATABASE_URL');
}

export function getAuthSecret(): string {
  const secret = process.env.BETTER_AUTH_SECRET;
  if (process.env.NODE_ENV === 'production') {
    if (!secret || secret.length < 32) {
      throw new Error('BETTER_AUTH_SECRET must be set to at least 32 characters in production.');
    }
    return secret;
  }
  return secret && secret.length > 0 ? secret : DEVELOPMENT_SECRET;
}

/**
 * Canonical application origin used for same-origin (CSRF) checks. Set
 * APP_ORIGIN in production when the app is served behind a proxy.
 */
export function getAppOrigin(): string {
  return requireEnv('BETTER_AUTH_URL').replace(/\/+$/, '');
}

export function isProduction(): boolean {
  return process.env.NODE_ENV === 'production';
}

const TLS_SSLMODES = new Set(['require', 'verify-ca', 'verify-full']);

/**
 * Traffic to a loopback host never leaves the machine, so it is the one case
 * where a plain-http origin (local production builds, CI smoke runs) is still
 * safe. Browsers also treat `http://localhost` as a secure context, so
 * `Secure` cookies are accepted there.
 */
export function isLoopbackHost(hostname: string): boolean {
  const host = hostname
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  return host === 'localhost' || host === '::1' || host === '127.0.0.1' || host.startsWith('127.');
}

/**
 * A local database reached over loopback or a unix socket never leaves the
 * host's network stack, so TLS is not what protects it there.
 */
function isLocalDatabase(databaseUrl: string): boolean {
  // libpq socket form (`...@/db?host=/var/run/postgresql`) has an empty host,
  // which the WHATWG URL parser rejects outright, so inspect it as text first.
  if (/[?&]host=(?:%2f|\/)/i.test(databaseUrl)) {
    return true;
  }

  let url: URL;
  try {
    url = new URL(databaseUrl);
  } catch {
    return false;
  }
  return isLoopbackHost(url.hostname);
}

function requestsTls(databaseUrl: string): boolean {
  try {
    const mode = new URL(databaseUrl).searchParams.get('sslmode')?.toLowerCase();
    return mode !== undefined && TLS_SSLMODES.has(mode);
  } catch {
    return false;
  }
}

/**
 * Refuses to boot a production build that would move sessions, credentials or
 * audit data over a cleartext link. Development is exempt so local work over
 * http/loopback keeps working; there the process only talks to itself.
 */
export function assertSecureTransport({
  production = isProduction(),
  origin = process.env.BETTER_AUTH_URL,
  databaseUrl = process.env.DATABASE_URL,
}: {
  production?: boolean;
  origin?: string | undefined;
  databaseUrl?: string | undefined;
} = {}): void {
  if (!production) {
    return;
  }

  let originUrl: URL;
  try {
    originUrl = new URL(origin ?? '');
  } catch {
    throw new Error('BETTER_AUTH_URL must be set to an absolute origin in production.');
  }

  if (originUrl.protocol !== 'https:' && !isLoopbackHost(originUrl.hostname)) {
    throw new Error(
      'BETTER_AUTH_URL must be an https:// origin in production: session cookies are marked Secure and the app will not work over plain http.',
    );
  }

  if (databaseUrl && !isLocalDatabase(databaseUrl) && !requestsTls(databaseUrl)) {
    throw new Error(
      'DATABASE_URL must request TLS for a remote database in production: add sslmode=require (or sslmode=verify-full with a CA).',
    );
  }
}
