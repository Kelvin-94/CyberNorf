import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { listPolicyDecisions } from '@/server/services/policy';
import { parseQuery } from '@/server/validation/common';
import { policyDecisionListQuerySchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>('policy.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, policyDecisionListQuerySchema);
  const result = await listPolicyDecisions(ctx.organization.id, query);
  return jsonResponse(result, meta);
});
