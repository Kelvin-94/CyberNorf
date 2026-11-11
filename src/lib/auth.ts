import { betterAuth, type ValidateUserInfoSource } from 'better-auth';
import { createAuthMiddleware } from 'better-auth/api';
import { prismaAdapter } from 'better-auth/adapters/prisma';
import { genericOAuth, twoFactor } from 'better-auth/plugins';
import { prisma } from '@/lib/prisma';
import { boundDiscoveryFetch } from '@/server/auth/discovery-fetch';
import { recordAuthActivity, recordSessionEnded } from '@/server/auth/events';
import { OIDC_PROVIDER_ID, oidcEmailClaimRejection, readOidcSettings } from '@/server/auth/oidc';
import { getAuthSecret, isProduction } from '@/server/config';

const production = isProduction();

/**
 * Optional OpenID Connect single sign-on. `null` keeps password sign-in as the
 * only method; a partly configured provider throws here so a deployment never
 * boots with a silently disabled login.
 */
const oidc = readOidcSettings();

// The plugin fetches discovery without a timeout while it initialises, so the
// request is bounded at the fetch layer before the instance is created.
if (oidc) {
  boundDiscoveryFetch(oidc.discoveryUrl);
}

/**
 * Better Auth is the identity provider for CyberNorf. It owns credentials,
 * sessions, and TOTP second factors. Authorization (organizations, roles,
 * capabilities, and tenant scoping) is implemented in `src/server/authz` and is
 * always evaluated on the server, never inferred from these settings.
 */
export const auth = betterAuth({
  appName: 'CyberNorf',
  baseURL: process.env.BETTER_AUTH_URL,
  // Validated at module load: production requires a 32+ character secret.
  secret: getAuthSecret(),
  database: prismaAdapter(prisma, { provider: 'postgresql' }),
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 12,
    maxPasswordLength: 128,
    autoSignIn: true,
    // Account recovery by email is not implemented in v1; see docs/DEVELOPMENT.md.
    requireEmailVerification: false,
  },
  session: {
    // Eight-hour sessions that slide forward at most every fifteen minutes.
    expiresIn: 60 * 60 * 8,
    updateAge: 60 * 15,
    // Cookie caching would hide server-side revocation, so it stays disabled.
    cookieCache: { enabled: false },
    freshAge: 60 * 60,
  },
  user: {
    changeEmail: { enabled: false },
    deleteUser: { enabled: false },
    // The identity provider's own `email_verified` claim is the trust anchor
    // for SSO, because CyberNorf never sends verification mail and every local
    // account is therefore unverified. Better Auth's provider-level
    // `requireEmailVerification` is not used for this: it tests the *local*
    // user, which would lock every existing account out of the SSO it was just
    // linked to. This gate runs before a user is created, linked, or given a
    // session, and fails closed when the claim is missing.
    ...(oidc
      ? {
          validateUserInfo: ({ source }: { source: ValidateUserInfoSource }) => {
            if (source.method !== 'oauth' || source.oauth?.providerId !== OIDC_PROVIDER_ID) {
              return;
            }
            return oidcEmailClaimRejection(source.oauth.profile) ?? undefined;
          },
        }
      : {}),
  },
  account: {
    accountLinking: {
      // Only meaningful when SSO is on. CyberNorf never sends verification
      // mail, so local accounts carry emailVerified = false forever and Better
      // Auth would refuse to attach an IdP identity to them. Turning this off
      // is what allows SSO to reach an account that already exists, and it is
      // safe only because `oidc` is deliberately NOT listed in
      // `trustedProviders`: Better Auth then links an existing account only
      // when the identity provider reports the address as verified.
      enabled: oidc !== null,
      requireLocalEmailVerified: false,
    },
  },
  advanced: {
    useSecureCookies: production,
    defaultCookieAttributes: {
      httpOnly: true,
      sameSite: 'lax',
      secure: production,
      path: '/',
    },
  },
  trustedOrigins: process.env.BETTER_AUTH_URL ? [process.env.BETTER_AUTH_URL] : [],
  // Authentication activity is recorded outside the tenant audit chain, because
  // a sign-in happens before an organization is known. The hook is best-effort:
  // a failure to write the record never fails the sign-in itself.
  hooks: {
    after: createAuthMiddleware(async (ctx) => {
      await recordAuthActivity(ctx);
    }),
  },
  databaseHooks: {
    session: {
      delete: {
        after: async (session, ctx) => {
          await recordSessionEnded({
            userId: typeof session.userId === 'string' ? session.userId : null,
            headers: ctx?.headers,
          });
        },
      },
    },
  },
  rateLimit: {
    enabled: true,
    window: 60,
    max: 120,
    storage: 'database',
    customRules: {
      '/sign-in/email': { window: 60, max: 10 },
      '/sign-up/email': { window: 60, max: 5 },
      '/two-factor/*': { window: 60, max: 10 },
      '/change-password': { window: 60, max: 5 },
      // Each attempt starts a round trip to the identity provider, so the
      // start and the callback are throttled separately.
      '/sign-in/social': { window: 60, max: 20 },
      [`/callback/${OIDC_PROVIDER_ID}`]: { window: 60, max: 20 },
    },
  },
  plugins: [
    twoFactor({
      issuer: 'CyberNorf',
      totpOptions: { digits: 6, period: 30 },
      backupCodeOptions: { amount: 10, length: 10 },
    }),
    ...(oidc
      ? [
          genericOAuth({
            config: [
              {
                providerId: OIDC_PROVIDER_ID,
                name: oidc.displayName,
                discoveryUrl: oidc.discoveryUrl,
                clientId: oidc.clientId,
                clientSecret: oidc.clientSecret,
                scopes: ['openid', 'email', 'profile'],
                // Signatures from the provider's published keys are the only
                // accepted evidence for the identity; if discovery advertises
                // no issuer or jwks_uri the provider is skipped, never trusted.
                requireIdTokenVerification: true,
                // Left off on purpose; `user.validateUserInfo` above enforces
                // the provider's verified-email claim instead.
                requireEmailVerification: false,
                pkce: true,
                allowIdpInitiated: false,
                ...(oidc.redirectUri ? { redirectURI: oidc.redirectUri } : {}),
              },
            ],
          }),
        ]
      : []),
  ],
});
