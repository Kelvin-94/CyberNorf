import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { deletePolicyRule, getPolicyRule, updatePolicyRule } from '@/server/services/policy';
import { updatePolicyRuleSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; ruleId: string };

export const GET = withTenantApi<Params>('policy.read', {}, async ({ meta, ctx, params }) => {
  const rule = await getPolicyRule(ctx.organization.id, params.ruleId);
  return jsonResponse({ rule }, meta);
});

export const PATCH = withTenantApi<Params>(
  'policy.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = updatePolicyRuleSchema.parse(await readJsonBody(request));
    const rule = await updatePolicyRule(ctx, params.ruleId, input);
    return jsonResponse({ rule }, meta);
  },
);

export const DELETE = withTenantApi<Params>('policy.manage', {}, async ({ meta, ctx, params }) => {
  await deletePolicyRule(ctx, params.ruleId);
  return jsonResponse({ deleted: true }, meta);
});
