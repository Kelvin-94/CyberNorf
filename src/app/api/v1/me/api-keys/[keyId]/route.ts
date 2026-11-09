import { jsonResponse, withApi } from '@/server/api/handler';
import { revokeUserApiKey } from '@/server/services/api-keys';

export const dynamic = 'force-dynamic';

type Params = { keyId: string };

/**
 * Revokes one of the caller's own keys. A key may revoke itself, which is the
 * intended way for a compromised script to shut its own credential down.
 */
export const DELETE = withApi<Params>(
  { rateLimit: { limit: 20, windowSeconds: 60, scope: 'user' } },
  async ({ meta, params, user }) => {
    const apiKey = await revokeUserApiKey(user, params.keyId, meta);
    return jsonResponse({ apiKey }, meta);
  },
);
