import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { purgeRetentionPolicy } from '@/server/services/retention';
import { purgeRetentionSchema } from '@/server/validation/retention';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/**
 * Irreversible: deletes the categories that are past their window and records
 * the exact counts in the audit chain. The route asks for the `retention.manage`
 * capability and the service additionally requires the OWNER role, because
 * changing a policy and acting on it are different levels of trust.
 */
export const POST = withTenantApi<Params>(
  'retention.manage',
  { rateLimit: { limit: 5, windowSeconds: 300 } },
  async ({ request, meta, ctx }) => {
    purgeRetentionSchema.parse(await readJsonBody(request));
    const result = await purgeRetentionPolicy(ctx);
    return jsonResponse({ purge: result }, meta);
  },
);
