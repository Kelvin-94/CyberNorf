import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { getUpdateOverview, listDeviceUpdates } from '@/server/services/updates';
import { parseQuery } from '@/server/validation/common';
import { updateListQuerySchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>('update.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, updateListQuerySchema);
  const [page, overview] = await Promise.all([
    listDeviceUpdates(ctx.organization.id, query),
    getUpdateOverview(ctx.organization.id),
  ]);
  return jsonResponse({ ...page, overview }, meta);
});
