import { betterAuth } from 'better-auth';
import { prismaAdapter } from 'better-auth/adapters/prisma';
import { twoFactor } from 'better-auth/plugins';
import { prisma } from '@/lib/prisma';
import { getAuthSecret, isProduction } from '@/server/config';

const production = isProduction();

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
    },
  },
  plugins: [
    twoFactor({
      issuer: 'CyberNorf',
      totpOptions: { digits: 6, period: 30 },
      backupCodeOptions: { amount: 10, length: 10 },
    }),
  ],
});
