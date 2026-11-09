import { isLoopbackHost } from '@/server/config';

/**
 * Provider id registered with Better Auth. It is also the last path segment of
 * the redirect URI the identity provider must be configured with:
 * `${BETTER_AUTH_URL}/api/auth/callback/oidc`.
 */
export const OIDC_PROVIDER_ID = 'oidc';

const DEFAULT_DISPLAY_NAME = 'single sign-on';
const MAX_DISPLAY_NAME_LENGTH = 40;

export type OidcSettings = {
  issuer: string;
  discoveryUrl: string;
  clientId: string;
  clientSecret: string;
  displayName: string;
  redirectUri: string | null;
};

type Env = Record<string, string | undefined>;

/** Variables that switch single sign-on on. All three are required together. */
const REQUIRED_VARIABLES = ['OIDC_ISSUER', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET'] as const;

function read(env: Env, name: string): string {
  return (env[name] ?? '').trim();
}

/**
 * Identity provider endpoints are trusted to convey signed assertions, so they
 * must be reachable over TLS. Plain http is only tolerated for a loopback host,
 * where traffic never leaves the machine (local development and tests).
 */
function parseProviderUrl(name: string, value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute http(s) URL.`);
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`${name} must use http:// or https://.`);
  }
  if (url.protocol === 'http:' && !isLoopbackHost(url.hostname)) {
    throw new Error(
      `${name} must use https://. Plain http is only accepted for a loopback identity provider.`,
    );
  }
  if (url.username || url.password) {
    throw new Error(`${name} must not embed credentials.`);
  }
  if (url.search || url.hash) {
    throw new Error(`${name} must not include a query string or fragment.`);
  }

  return url;
}

function normalizeUrl(url: URL, { stripTrailingSlash }: { stripTrailingSlash: boolean }): string {
  const path = stripTrailingSlash ? url.pathname.replace(/\/+$/, '') : url.pathname;
  return `${url.origin}${path === '/' ? '' : path}`;
}

function normalizeDisplayName(value: string): string {
  const collapsed = value.replace(/\s+/g, ' ').trim();
  return collapsed.length === 0
    ? DEFAULT_DISPLAY_NAME
    : collapsed.slice(0, MAX_DISPLAY_NAME_LENGTH);
}

/**
 * Reads the optional OpenID Connect single sign-on settings.
 *
 * Returns `null` when none of the three required variables is set, which keeps
 * password sign-in as the only method. A partially configured provider throws
 * instead of silently falling back: an operator who set a client id but no
 * issuer most likely expects SSO to work, and a quiet downgrade would hide the
 * mistake. Anything that would let an assertion travel in cleartext is refused
 * for the same reason.
 */
export function readOidcSettings(env: Env = process.env): OidcSettings | null {
  const values = {
    OIDC_ISSUER: read(env, 'OIDC_ISSUER'),
    OIDC_CLIENT_ID: read(env, 'OIDC_CLIENT_ID'),
    OIDC_CLIENT_SECRET: read(env, 'OIDC_CLIENT_SECRET'),
  } satisfies Record<(typeof REQUIRED_VARIABLES)[number], string>;

  const missing = REQUIRED_VARIABLES.filter((name) => values[name].length === 0);
  if (missing.length === REQUIRED_VARIABLES.length) {
    return null;
  }
  if (missing.length > 0) {
    throw new Error(
      `${missing.join(', ')} must also be configured to enable single sign-on; otherwise leave OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET unset.`,
    );
  }

  // Issuers identify a tenant by URL. Keeping a path (for example
  // https://idp.example.com/realms/cybernorf) but dropping a trailing slash
  // keeps discovery and the expected `iss` claim consistent.
  const issuerUrl = parseProviderUrl('OIDC_ISSUER', values.OIDC_ISSUER);
  const issuer = normalizeUrl(issuerUrl, { stripTrailingSlash: true });

  const redirectUriValue = read(env, 'OIDC_REDIRECT_URI');
  const redirectUri =
    redirectUriValue.length === 0
      ? null
      : normalizeUrl(parseProviderUrl('OIDC_REDIRECT_URI', redirectUriValue), {
          stripTrailingSlash: false,
        });

  return {
    issuer,
    discoveryUrl: `${issuer}/.well-known/openid-configuration`,
    clientId: values.OIDC_CLIENT_ID,
    clientSecret: values.OIDC_CLIENT_SECRET,
    displayName: normalizeDisplayName(read(env, 'OIDC_DISPLAY_NAME')),
    redirectUri,
  };
}

/**
 * Gate for the identity provider's `email_verified` claim.
 *
 * CyberNorf never sends verification mail, so every local account stays
 * unverified; the provider's signed assertion is the only trustworthy statement
 * about the address. Missing, false, or non-boolean claims are refused, which
 * also stops an IdP that omits the claim from being treated as vouching for it.
 *
 * Returns `null` when the profile may proceed.
 */
export function oidcEmailClaimRejection(
  profile: unknown,
): { error: string; errorDescription: string } | null {
  if (typeof profile === 'object' && profile !== null) {
    const claims = profile as Record<string, unknown>;
    if (claims.email_verified === true) {
      return null;
    }
  }
  return {
    error: 'email_not_verified',
    errorDescription: 'Your identity provider has not confirmed this email address.',
  };
}

/** Label for the sign-in button, or `null` when SSO is not configured. */
export function getOidcSignInLabel(env: Env = process.env): string | null {
  return readOidcSettings(env)?.displayName ?? null;
}
