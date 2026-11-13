import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { rejectEnforcement } from '@/server/services/enforcement';
import { rejectEnforcementSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; actionId: string };

export const POST = withTenantApi<Params>(
  'enforcement.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = rejectEnforcementSchema.parse(await readJsonBody(request));
    const action = await rejectEnforcement(ctx, params.actionId, input.reason);
    return jsonResponse({ action }, meta);
  },
);
