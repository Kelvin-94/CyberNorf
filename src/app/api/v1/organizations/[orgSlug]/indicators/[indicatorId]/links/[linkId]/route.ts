import { emptyResponse, withTenantApi } from '@/server/api/handler';
import { unlinkIndicator } from '@/server/services/indicators';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; indicatorId: string; linkId: string };

export const DELETE = withTenantApi<Params>(
  'indicator.manage',
  {},
  async ({ meta, ctx, params }) => {
    await unlinkIndicator(ctx, params.indicatorId, params.linkId);
    return emptyResponse(meta);
  },
);
