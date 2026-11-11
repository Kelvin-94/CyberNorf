import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { transitionIdentity } from '@/server/services/identities';
import { identityLifecycleSchema } from '@/server/validation/identities';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; identityId: string };

/**
 * One endpoint for approve, suspend, reactivate and deprovision. The service
 * applies the transition table; approval is additionally restricted to owners.
 */
export const POST = withTenantApi<Params>(
  'identity.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = identityLifecycleSchema.parse(await readJsonBody(request));
    const identity = await transitionIdentity(ctx, params.identityId, input);
    return jsonResponse({ identity }, meta);
  },
);
