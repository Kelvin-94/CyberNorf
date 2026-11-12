import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { getEngagement, updateEngagement } from '@/server/services/engagements';
import { withoutUndefined } from '@/server/validation/common';
import { updateEngagementSchema } from '@/server/validation/engagements';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; engagementId: string };

export const GET = withTenantApi<Params>('engagement.read', {}, async ({ meta, ctx, params }) => {
  const engagement = await getEngagement(ctx.organization.id, params.engagementId);
  return jsonResponse({ engagement }, meta);
});

export const PATCH = withTenantApi<Params>(
  'engagement.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = updateEngagementSchema.parse(await readJsonBody(request));
    const engagement = await updateEngagement(ctx, params.engagementId, withoutUndefined(input));
    return jsonResponse({ engagement }, meta);
  },
);
