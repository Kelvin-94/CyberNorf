import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { approveEnforcement } from '@/server/services/enforcement';
import { approveEnforcementSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; actionId: string };

/**
 * Approval is refused for the operator who raised the request: the service
 * compares requester and approver and rejects a match with `self_approval`.
 */
export const POST = withTenantApi<Params>(
  'enforcement.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = approveEnforcementSchema.parse(await readJsonBody(request));
    const action = await approveEnforcement(ctx, params.actionId, input.note ?? undefined);
    return jsonResponse({ action }, meta);
  },
);
