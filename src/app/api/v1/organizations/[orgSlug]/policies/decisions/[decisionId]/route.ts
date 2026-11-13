import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { getPolicyDecision } from '@/server/services/policy';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; decisionId: string };

export const GET = withTenantApi<Params>('policy.read', {}, async ({ meta, ctx, params }) => {
  const decision = await getPolicyDecision(ctx.organization.id, params.decisionId);
  return jsonResponse({ decision }, meta);
});
