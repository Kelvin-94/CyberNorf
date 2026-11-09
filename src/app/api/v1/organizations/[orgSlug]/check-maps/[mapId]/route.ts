import { emptyResponse, withTenantApi } from '@/server/api/handler';
import { deleteCheckMap } from '@/server/services/check-maps';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; mapId: string };

/**
 * Removing a mapping stops future automatic evidence. Evidence already filed is
 * audit history and stays put; an analyst removes it from the control itself.
 */
export const DELETE = withTenantApi<Params>('agent.manage', {}, async ({ meta, ctx, params }) => {
  await deleteCheckMap(ctx, params.mapId);
  return emptyResponse(meta);
});
