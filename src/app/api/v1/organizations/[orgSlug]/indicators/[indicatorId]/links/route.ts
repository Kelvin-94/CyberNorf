import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { linkIndicator } from '@/server/services/indicators';
import { withoutUndefined } from '@/server/validation/common';
import { linkIndicatorSchema } from '@/server/validation/indicators';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; indicatorId: string };

export const POST = withTenantApi<Params>(
  'indicator.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = linkIndicatorSchema.parse(await readJsonBody(request));
    const link = await linkIndicator(ctx, params.indicatorId, withoutUndefined(input));
    return jsonResponse({ link }, meta, 201);
  },
);
