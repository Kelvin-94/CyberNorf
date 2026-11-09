import { jsonResponse, withApi } from '@/server/api/handler';
import {
  API_KEY_DEFAULT_TTL_DAYS,
  API_KEY_MAX_TTL_DAYS,
  API_KEY_MIN_TTL_DAYS,
  MAX_ACTIVE_API_KEYS_PER_ORGANIZATION,
} from '@/server/domain/api-keys';
import { readJsonBody } from '@/server/http/request-meta';
import { createUserApiKey, listUserApiKeys } from '@/server/services/api-keys';
import { apiKeyCreateSchema } from '@/server/validation/api-keys';

export const dynamic = 'force-dynamic';

/**
 * Personal API keys of the signed-in user. The list never includes the
 * credential itself: only a short prefix, the lifetime and usage timestamps.
 */
export const GET = withApi(
  { rateLimit: { limit: 60, windowSeconds: 60, scope: 'user' } },
  async ({ meta, user }) => {
    // A key principal only sees the keys of its own organization.
    const apiKeys = await listUserApiKeys(user.id, user.apiKey?.organizationId);

    return jsonResponse(
      {
        apiKeys,
        policy: {
          minDays: API_KEY_MIN_TTL_DAYS,
          maxDays: API_KEY_MAX_TTL_DAYS,
          defaultDays: API_KEY_DEFAULT_TTL_DAYS,
          maxActivePerOrganization: MAX_ACTIVE_API_KEYS_PER_ORGANIZATION,
        },
      },
      meta,
    );
  },
);

/**
 * Issues one key for one organization. The plaintext value appears in this
 * response only, so the client must show it before navigating away.
 */
export const POST = withApi(
  { rateLimit: { limit: 10, windowSeconds: 600, scope: 'user' } },
  async ({ request, meta, user }) => {
    const input = apiKeyCreateSchema.parse(await readJsonBody(request, 4 * 1024));
    const result = await createUserApiKey(user, input, meta);
    return jsonResponse(result, meta, 201);
  },
);
