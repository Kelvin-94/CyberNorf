import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { createPolicyRule, getPolicyOverview, listPolicyRules } from '@/server/services/policy';
import { parseQuery } from '@/server/validation/common';
import { createPolicyRuleSchema, policyRuleListQuerySchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>('policy.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, policyRuleListQuerySchema);
  const [page, overview] = await Promise.all([
    listPolicyRules(ctx.organization.id, query),
    getPolicyOverview(ctx.organization.id),
  ]);
  return jsonResponse({ ...page, overview }, meta);
});

export const POST = withTenantApi<Params>('policy.manage', {}, async ({ request, meta, ctx }) => {
  const input = createPolicyRuleSchema.parse(await readJsonBody(request));
  const rule = await createPolicyRule(ctx, input);
  return jsonResponse({ rule }, meta, 201);
});
