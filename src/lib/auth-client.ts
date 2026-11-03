'use client';

import { createAuthClient } from 'better-auth/react';
import { twoFactorClient } from 'better-auth/client/plugins';

/**
 * Browser-side Better Auth client. The server origin is used implicitly so the
 * client never needs the absolute URL, and the two-factor plugin routes a
 * challenge to the verification screen instead of failing silently.
 */
export const authClient = createAuthClient({
  plugins: [
    twoFactorClient({
      onTwoFactorRedirect: () => {
        window.location.href = '/two-factor';
      },
    }),
  ],
});
