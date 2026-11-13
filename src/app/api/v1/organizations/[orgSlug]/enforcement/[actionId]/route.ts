import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { getEnforcementAction } from '@/server/services/enforcement';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; actionId: string };

export const GET = withTenantApi<Params>('enforcement.read', {}, async ({ meta, ctx, params }) => {
  const action = await getEnforcementAction(ctx.organization.id, params.actionId);
  return jsonResponse({ action }, meta);
});
