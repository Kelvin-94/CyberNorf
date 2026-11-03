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
