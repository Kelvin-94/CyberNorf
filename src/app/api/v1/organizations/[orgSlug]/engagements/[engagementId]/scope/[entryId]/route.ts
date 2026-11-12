import { emptyResponse, withTenantApi } from '@/server/api/handler';
import { removeScopeEntry } from '@/server/services/engagements';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; engagementId: string; entryId: string };

export const DELETE = withTenantApi<Params>(
  'engagement.manage',
  {},
  async ({ meta, ctx, params }) => {
    await removeScopeEntry(ctx, params.engagementId, params.entryId);
    return emptyResponse(meta);
  },
);
