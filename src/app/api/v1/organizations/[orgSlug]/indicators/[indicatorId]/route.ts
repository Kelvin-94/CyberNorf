import { emptyResponse, jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { deleteIndicator, getIndicatorDetail, updateIndicator } from '@/server/services/indicators';
import { withoutUndefined } from '@/server/validation/common';
import { updateIndicatorSchema } from '@/server/validation/indicators';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; indicatorId: string };

export const GET = withTenantApi<Params>('indicator.read', {}, async ({ meta, ctx, params }) => {
  const result = await getIndicatorDetail(ctx, params.indicatorId);
  return jsonResponse(result, meta);
});

export const PATCH = withTenantApi<Params>(
  'indicator.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = updateIndicatorSchema.parse(await readJsonBody(request));
    const indicator = await updateIndicator(ctx, params.indicatorId, withoutUndefined(input));
    return jsonResponse({ indicator }, meta);
  },
);

export const DELETE = withTenantApi<Params>(
  'indicator.delete',
  {},
  async ({ meta, ctx, params }) => {
    await deleteIndicator(ctx, params.indicatorId);
    return emptyResponse(meta);
  },
);
